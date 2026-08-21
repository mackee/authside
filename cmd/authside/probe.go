// The reachability probe.
//
// authside never cross-checks `issuer` against `listen` or `advertise`,
// and must not (config/validate.go carries the full argument, and
// authside_splithorizon_test.go the regression test). The price of that
// is that a genuine typo is accepted in silence: a config saying
//
//	advertise:
//	  internal: http://authsdie:5556/oidc
//
// starts, looks healthy, serves a discovery document, and only breaks
// when the application tries to exchange a code -- at which point the
// error surfaces in the application's logs, not authside's, pointing at
// nothing in particular.
//
// This probe is the opt-in rescue for that one case: with --probe,
// authside makes a single GET, from itself, to each configured
// advertise.internal, and logs what happened. It is a diagnostic, never
// a gate: it cannot fail startup and cannot change the exit code,
// because "unreachable from authside" is a legitimate state (see
// config/validate.go reason 2 -- the application may reach that base
// over a route authside has no access to).
//
// What it deliberately does NOT do, because authside cannot know it:
//
//   - probe advertise.browser. That base only has to work from the
//     browser; authside's own reachability says nothing about it.
//   - probe anything when advertise is unset. The advertised base is
//     then derived per-request, so at startup there is no URL to try.
//   - infer anything from the HTTP status. Any status at all means the
//     name resolved and something answered, which is the whole question
//     being asked; a 404 is expected under `discovery: off` and under
//     `discovery: per_issuer`, and legitimate behind a path-rewriting
//     ingress. The status is logged for a human to read, not judged.
//   - stand in for the application's view. The measurement is
//     "authside's network namespace can reach this", not "the app can".
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/mackee/authside/config"
)

// wellKnownPath is the discovery document's path below a target's base.
// Kept as a local const rather than an import of internal/oidcop (where
// the same string lives, see internal/oidcop/discovery_periss.go): the
// probe needs one well-known URL to GET, not the discovery machinery.
const wellKnownPath = "/.well-known/openid-configuration"

// probeTimeout bounds each individual GET. Short on purpose -- the probe
// runs alongside a server that is already accepting connections, and a
// diagnostic that takes visibly long to print is one people stop
// enabling. A hostname that does not resolve fails far inside this.
const probeTimeout = 3 * time.Second

// probeClient is the HTTP client the probe uses.
//
// InsecureSkipVerify is deliberate and is not a weakening of anything:
// the probe asks "does this name resolve and answer", sends no
// credentials, and trusts nothing in the response (it does not even read
// the body). Verifying the certificate would make it answer a different
// and less useful question -- a dev ingress with a local-CA or
// self-signed certificate is the normal case here, and rejecting it
// would turn a reachable base into a spurious warning.
//
// This is not a concession to the runtime image: distroless/static does
// ship a CA bundle, so verifying would be possible here -- it is just the
// wrong question to ask (see Dockerfile).
//
// Proxy is nil for the same reason: HTTP_PROXY in authside's environment
// describes authside's egress, not the path the application would take,
// so honouring it would answer a third unrelated question.
func probeClient() *http.Client {
	return &http.Client{
		Timeout: probeTimeout,
		Transport: &http.Transport{
			Proxy: nil,
			TLSClientConfig: &tls.Config{
				// #nosec G402 -- reachability, not authentication; see above.
				InsecureSkipVerify: true,
			},
		},
	}
}

// probeTargets GETs each target's advertise.internal discovery URL and
// logs the outcome. It returns nothing: every result is advisory.
//
// ctx is the server's context, so a probe still in flight is abandoned
// when the process is shutting down.
func probeTargets(ctx context.Context, logger *slog.Logger, targets []config.Target, client *http.Client) {
	probed := 0
	for _, t := range targets {
		base := strings.TrimRight(t.Advertise.Internal, "/")
		if base == "" {
			// Not a warning: this is the common, correct
			// configuration. Said out loud all the same, so that a
			// silent probe is never mistaken for a passing one.
			logger.Info("probe skipped: no advertise.internal is set, so the advertised base is derived from each request and is not known at startup",
				slog.String("target", t.Name),
			)
			continue
		}
		probed++
		probeOne(ctx, logger, client, t.Name, base)
	}
	if probed == 0 {
		logger.Info("probe checked nothing: no target sets advertise.internal (the probe only checks that one field)")
	}
}

// probeOne performs the single GET for one target.
func probeOne(ctx context.Context, logger *slog.Logger, client *http.Client, name, base string) {
	url := base + wellKnownPath

	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		// A base that is not a usable URL at all. Still only a warning:
		// the probe is not a validator, and this field is intentionally
		// unvalidated elsewhere.
		logger.Warn("probe could not be run: advertise.internal is not a usable URL",
			slog.String("target", name),
			slog.String("advertise_internal", base),
			slog.String("error", err.Error()),
		)
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		logger.Warn("probe: advertise.internal is NOT reachable from authside itself -- if the application reaches it by another route this is fine, otherwise check the hostname for a typo",
			slog.String("target", name),
			slog.String("url", url),
			slog.String("error", err.Error()),
		)
		return
	}
	defer resp.Body.Close()

	// Any status answers the question: something at that name replied.
	// The code is reported without judgement -- see this file's header
	// for why a 404 here is not necessarily wrong.
	logger.Info("probe: advertise.internal answered from authside itself (the status is reported, not judged)",
		slog.String("target", name),
		slog.String("url", url),
		slog.String("status", fmt.Sprintf("%d %s", resp.StatusCode, http.StatusText(resp.StatusCode))),
	)
}
