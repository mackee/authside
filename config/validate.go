package config

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------
// On NOT checking issuer against listen
//
// This package deliberately does not, and must not, cross-check `issuer`
// against `listen` (or against `advertise`). Do not add one. Three
// reasons, straight from the README:
//
//  1. issuer is an identifier, not the address the process listens on.
//     "https://login.microsoftonline.com/${claims.tid}/v2.0" served over
//     plain HTTP on 127.0.0.1:5556 is a legitimate, intended
//     configuration (see "Per-tenant issuers" and "Why not an existing
//     mock?").
//  2. Real split-horizon dev setups exist where the browser reaches
//     authside through a TLS-terminating ingress while the app reaches it
//     over the container network or loopback, and the app's outbound path
//     to the ingress hostname does not work at all (a host firewall
//     dropping it, for instance). A consistency check would reject that
//     correct configuration outright.
//  3. The README states this in so many words: "authside never rejects a
//     configuration because issuer disagrees with listen." A reachability
//     probe is an opt-in flag, not a load-time validation rule, and is
//     out of this package's scope.
//
// See TestIssuerListenMismatchAccepted in validate_test.go for the
// regression test.
// ---------------------------------------------------------------------

// validEndpoints is the set of endpoint names an `errors` entry may name
// (README "OIDC target" > Endpoints, plus "discovery" for the discovery
// document itself).
var validEndpoints = map[string]bool{
	"authorize":   true,
	"token":       true,
	"userinfo":    true,
	"jwks":        true,
	"revocation":  true,
	"end_session": true,
	"discovery":   true,
}

func validEndpointNames() []string {
	return []string{"authorize", "token", "userinfo", "jwks", "revocation", "end_session", "discovery"}
}

// validOAuthErrorCodes is RFC 6749's registered error codes (§4.1.2.1,
// §4.2.2.1, §5.2) — the set an `errors` value may name when it is not a
// bare HTTP status.
var validOAuthErrorCodes = map[string]bool{
	"invalid_request":           true,
	"invalid_client":            true,
	"invalid_grant":             true,
	"unauthorized_client":       true,
	"unsupported_grant_type":    true,
	"invalid_scope":             true,
	"access_denied":             true,
	"unsupported_response_type": true,
	"server_error":              true,
	"temporarily_unavailable":   true,
}

var validTampers = map[TamperTarget]bool{
	TamperAtHash:    true,
	TamperIss:       true,
	TamperAud:       true,
	TamperNonce:     true,
	TamperExp:       true,
	TamperSignature: true,
}

// Validate checks cfg for problems that would make it unusable and
// aggregates all of them (via errors.Join) rather than stopping at the
// first, so a config for a test tool tells the user everything wrong in
// one run. It also (re)computes non-fatal findings into cfg.Warnings
// (e.g. a login: auto target with no default_user) — see the idempotence
// note below.
//
// Validate assumes ApplyDefaults has already run: the enum fields
// (login, discovery, access_token, refresh_token, type, mount) are
// checked against their known values, and defaulting is what turns an
// empty field into one of those values. Calling Validate on a config
// that has not been defaulted will flag every still-empty enum field as
// invalid — LoadBytes always defaults before validating, so this only
// matters for a caller assembling a Config by hand.
//
// Validate is idempotent: it computes the complete warning set for the
// config it was handed and replaces cfg.Warnings with that set (rather
// than appending to whatever was there before), so calling Validate any
// number of times on the same Config — e.g. once from config.LoadBytes
// and again from authside.New, which deliberately re-runs
// ApplyDefaults+Validate on an already-loaded config (see authside.go) —
// leaves exactly one copy of each warning, never a multiplying pile.
func Validate(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("config: nil config")
	}
	cfg.Warnings = nil

	var errs []error

	if len(cfg.Targets) == 0 {
		errs = append(errs, fmt.Errorf("targets: at least one target is required"))
	}

	names := make(map[string]int, len(cfg.Targets))
	var mounts []mountRef

	for i := range cfg.Targets {
		t := &cfg.Targets[i]
		label := targetLabel(i, t.Name)

		if t.Name == "" {
			errs = append(errs, fmt.Errorf("%s: name is required", label))
		} else if first, dup := names[t.Name]; dup {
			errs = append(errs, fmt.Errorf("%s: duplicate target name %q (also used by targets[%d])", label, t.Name, first))
		} else {
			names[t.Name] = i
		}

		if t.Type != "oidc" {
			errs = append(errs, fmt.Errorf("%s: type: unknown type %q, must be one of: oidc", label, t.Type))
		}

		if t.Mount == "" {
			errs = append(errs, fmt.Errorf("%s: mount must not be empty (leave it unset to default to \"/%s\")", label, t.Name))
		} else if !strings.HasPrefix(t.Mount, "/") {
			errs = append(errs, fmt.Errorf("%s: mount %q must start with \"/\"", label, t.Mount))
		} else {
			mounts = append(mounts, mountRef{name: t.Name, mount: t.Mount})
		}

		errs = append(errs, validateIssuer(label, t.Issuer)...)

		if !validEnum(t.Login, LoginAuto, LoginPicker, LoginForm) {
			errs = append(errs, enumError(label, "login", string(t.Login), "auto", "picker", "form"))
		}
		if !validEnum(t.Discovery, DiscoverShared, DiscoverPerIssuer, DiscoverOff) {
			errs = append(errs, enumError(label, "discovery", string(t.Discovery), "shared", "per_issuer", "off"))
		}
		if !validEnum(t.AccessToken, AccessTokenJWT, AccessTokenOpaque) {
			errs = append(errs, enumError(label, "access_token", string(t.AccessToken), "jwt", "opaque"))
		}
		if !validEnum(t.RefreshToken, RefreshRotate, RefreshStatic) {
			errs = append(errs, enumError(label, "refresh_token", string(t.RefreshToken), "rotate", "static"))
		}

		// One key or none. Both set is a mistake with no sensible
		// precedence -- silently preferring one would hide whichever the
		// author meant.
		if t.KeyPEM != "" && t.KeyFile != "" {
			errs = append(errs, fmt.Errorf("%s: key_pem and key_file are mutually exclusive; set one or neither", label))
		}

		for _, tm := range t.Tamper {
			if !validTampers[tm] {
				errs = append(errs, fmt.Errorf("%s: tamper: unknown value %q, must be one of: at_hash, iss, aud, nonce, exp, signature", label, tm))
			}
		}

		for endpoint, spec := range t.Errors {
			if !validEndpoints[endpoint] {
				errs = append(errs, fmt.Errorf("%s: errors: unknown endpoint %q, must be one of: %s", label, endpoint, strings.Join(validEndpointNames(), ", ")))
				continue
			}
			if !validErrorSpec(spec) {
				errs = append(errs, fmt.Errorf("%s: errors[%s]: %q is neither a known OAuth error code nor a 3-digit HTTP status", label, endpoint, spec))
			}
		}

		if len(t.Clients) == 0 {
			errs = append(errs, fmt.Errorf("%s: clients: at least one client is required", label))
		}
		clientIDs := make(map[string]bool, len(t.Clients))
		for ci := range t.Clients {
			c := &t.Clients[ci]
			clabel := fmt.Sprintf("%s.clients[%d]", label, ci)
			switch {
			case c.ClientID == "":
				errs = append(errs, fmt.Errorf("%s: client_id is required", clabel))
			case clientIDs[c.ClientID]:
				errs = append(errs, fmt.Errorf("%s: duplicate client_id %q within target %q", clabel, c.ClientID, t.Name))
			default:
				clientIDs[c.ClientID] = true
			}

			if len(c.RedirectURIs) == 0 {
				errs = append(errs, fmt.Errorf("%s: redirect_uris: at least one is required", clabel))
			}
			for ri, ru := range c.RedirectURIs {
				if !isAbsoluteURL(ru) {
					errs = append(errs, fmt.Errorf("%s: redirect_uris[%d] %q must be an absolute URL", clabel, ri, ru))
				}
			}
		}

		subs := make(map[string]bool, len(t.Users))
		for ui := range t.Users {
			u := &t.Users[ui]
			ulabel := fmt.Sprintf("%s.users[%d]", label, ui)
			switch {
			case u.Sub == "":
				errs = append(errs, fmt.Errorf("%s: sub is required", ulabel))
			case subs[u.Sub]:
				errs = append(errs, fmt.Errorf("%s: duplicate sub %q within target %q", ulabel, u.Sub, t.Name))
			default:
				subs[u.Sub] = true
			}
		}
		if len(t.Users) == 0 && !t.AcceptAnyUsername {
			errs = append(errs, fmt.Errorf("%s: users must not be empty unless accept_any_username is true — with no configured users and accept_any_username false, nobody could ever log in on this target", label))
		}

		if t.DefaultUser != "" && !subs[t.DefaultUser] {
			errs = append(errs, fmt.Errorf("%s: default_user %q does not match any configured user's sub", label, t.DefaultUser))
		}

		// login: auto has no implicit fallback subject (README "Login
		// modes"): it needs either default_user on the target, or the
		// authside_sub cookie set at runtime before the flow starts.
		// The cookie is a legitimate, runtime-only source that this
		// package cannot see, so a missing default_user here is NOT an
		// error — but it is worth flagging, since a target configured
		// this way will 4xx at /authorize for anyone who forgot to set
		// the cookie. Hence: warning, not error.
		if t.Login == LoginAuto && t.DefaultUser == "" {
			cfg.Warnings = append(cfg.Warnings, fmt.Sprintf(
				"target %q: login: auto has no default_user; /authorize will only work if the caller sets the authside_sub cookie itself (README: auto has no implicit fallback subject)",
				t.Name))
		}
	}

	errs = append(errs, checkMountCollisions(mounts)...)

	return errors.Join(errs...)
}

func targetLabel(i int, name string) string {
	if name == "" {
		return fmt.Sprintf("targets[%d]", i)
	}
	return fmt.Sprintf("targets[%d] (name %q)", i, name)
}

func validEnum[T ~string](v T, valid ...T) bool {
	for _, o := range valid {
		if v == o {
			return true
		}
	}
	return false
}

func enumError(label, field, value string, valid ...string) error {
	return fmt.Errorf("%s: %s: unknown value %q, must be one of: %s", label, field, value, strings.Join(valid, ", "))
}

// validateIssuer requires issuer to be present and to parse as an
// absolute URL (scheme and host both present) — with template
// placeholders such as ${claims.tid} still in it. url.Parse tolerates
// "${...}" in a path (it percent-encodes the braces internally but does
// not error), which is exactly the Entra per-tenant case; see
// TestIssuerAcceptsTemplatePlaceholder. Whatever url.Parse does to the
// value is only used for this check — the original string is kept
// verbatim in Target.Issuer and is never rewritten.
func validateIssuer(label, issuer string) []error {
	if issuer == "" {
		return []error{fmt.Errorf("%s: issuer is required", label)}
	}
	u, err := url.Parse(issuer)
	if err != nil {
		return []error{fmt.Errorf("%s: issuer %q: %w", label, issuer, err)}
	}
	if u.Scheme == "" || u.Host == "" {
		return []error{fmt.Errorf("%s: issuer %q must be an absolute URL (scheme and host required)", label, issuer)}
	}
	return nil
}

func isAbsoluteURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme != "" && u.Host != ""
}

func validErrorSpec(spec ErrorSpec) bool {
	s := string(spec)
	if spec.IsHTTPStatus() {
		if len(s) != 3 {
			return false
		}
		n, err := strconv.Atoi(s)
		return err == nil && n >= 100 && n <= 599
	}
	return validOAuthErrorCodes[s]
}

// normalizeMount trims a trailing slash so "/oidc/" and "/oidc" compare
// equal, except for the root mount itself.
func normalizeMount(m string) string {
	if m == "/" {
		return m
	}
	return strings.TrimSuffix(m, "/")
}

// mountsCollide reports whether two normalized mounts would receive
// overlapping requests: either they are the same mount, or one is a
// segment-prefix of the other (e.g. "/oidc" and "/oidc/sub" — a request
// under /oidc/sub/* is ambiguous between the two targets). "/oidc" and
// "/oidc2" do NOT collide: "oidc2" is not a path segment inside "/oidc".
func mountsCollide(a, b string) bool {
	an, bn := normalizeMount(a), normalizeMount(b)
	if an == bn {
		return true
	}
	// The root mount ("/") is a segment-prefix of literally every other
	// mount, but the generic "an+\"/\" prefix of bn+\"/\"" probe below
	// doesn't catch it: normalizeMount keeps "/" as "/", so the probe
	// becomes HasPrefix(bn+"/", "//"), which is false for any bn that
	// doesn't itself start with an extra slash. Handle it explicitly.
	if an == "/" || bn == "/" {
		return true
	}
	return strings.HasPrefix(bn+"/", an+"/") || strings.HasPrefix(an+"/", bn+"/")
}

// mountRef pairs a target name with its (already validated, "/"-prefixed)
// mount, for the cross-target collision check.
type mountRef struct {
	name  string
	mount string
}

func checkMountCollisions(mounts []mountRef) []error {
	var errs []error
	for i := 0; i < len(mounts); i++ {
		for j := i + 1; j < len(mounts); j++ {
			if mountsCollide(mounts[i].mount, mounts[j].mount) {
				errs = append(errs, fmt.Errorf(
					"targets: mount %q (target %q) collides with mount %q (target %q)",
					mounts[i].mount, mounts[i].name, mounts[j].mount, mounts[j].name))
			}
		}
	}
	return errs
}

// On NOT checking discovery: per_issuer route collisions here
//
// README "Discovery under a templated issuer" requires that per_issuer's
// routes be enumerated up front and a collision be a startup error. That
// check exists -- in internal/oidcop (enumeratePerIssuerRoutes), not here
// -- and this comment records why, because the obvious reading is that it
// belongs in this file next to checkMountCollisions.
//
// Two reasons. First, rendering a target's issuer template against every
// configured user needs internal/tmpl, and this package deliberately
// imports nothing from this module: it is a leaf, so that a caller can
// parse and inspect a config without pulling in any of the serving
// machinery. Reaching for tmpl here would trade that away for one check.
//
// Second, the part that genuinely needs a whole-config view -- a
// per-issuer route overlapping some *other* target's mount subtree -- is
// already unreachable. A per-issuer route always lives under its own
// target's mount, and checkMountCollisions above rejects any two mounts
// where one is a segment-prefix of the other, so a second target mounted
// anywhere inside the first is refused before per_issuer is even
// considered. Nothing is left for this file to check that oidcop cannot
// check per target, and construction-time failure there is the same
// startup error: authside.New returns it, and the process never serves.
