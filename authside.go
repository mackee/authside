// Package authside is a mock identity provider for local development and
// test environments. See the repo README for the full design.
//
// # Invariant: the core does not know its listen address
//
// New returns a plain http.Handler and never a listen address, a
// *http.Server, or anything that binds a socket. That is deliberate: the
// issuer string configured on a target is independent from the address the
// process happens to be reached at, and giving this package no way to
// observe the listen address makes that separation structural rather than
// a convention someone can accidentally break. The address to bind to,
// whether to bind beyond loopback (--allow-external) and TLS termination
// are all concerns of cmd/authside (or of whatever embeds this package),
// never of New.
//
// This is also what makes the mockoidc failure mode this project exists to
// avoid ("Issuer() = Addr() + IssuerBase", see README "Why not an existing
// mock?") structurally unreproducible here: there is no Addr() for an
// issuer to be derived from.
package authside

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/mackee/authside/config"
	"github.com/mackee/authside/internal/clock"
	"github.com/mackee/authside/internal/oidcop"
	"github.com/mackee/authside/internal/reqlog"
	"github.com/mackee/tanukirpc"
)

// Config is the parsed form of authside.yaml / AUTHSIDE_CONFIG_INLINE.
// Re-exported so callers of this package need only one import.
type Config = config.Config

// authsideMarkerHeader is set on every response New's handler serves,
// including a 404 for a path matching no target's mount (README "Loud
// about being fake").
const authsideMarkerHeader = "X-Authside"

// New returns the http.Handler serving every configured target, one
// per-target runtime mounted under its own config.Target.Mount — see the
// package doc comment for why New has no access to a listen address.
//
// New itself runs cfg through config.ApplyDefaults and config.Validate
// before building anything, exactly as config.LoadBytes does. This is a
// deliberate design decision: a *Config assembled by hand in a test — the
// common case for a Go caller, as opposed to one decoded from YAML via
// config.Load — would otherwise reach here with
// mount/login/discovery/access_token still blank and get rejected by
// internal/oidcop's construction-time checks for values that are actually
// just "not yet defaulted", not genuinely unsupported. Running the same
// normalize-then-validate pipeline here as config.Load uses makes New(cfg)
// behave identically regardless of how cfg was produced. ApplyDefaults
// only fills already-empty fields, and config.Validate is idempotent — it
// replaces cfg.Warnings with the complete warning set for cfg rather than
// appending to it — so calling them again on an already-loaded (and
// hence already-defaulted and already-validated) Config is a harmless
// no-op: the resulting Warnings is identical to what config.Load already
// produced, not a duplicate of it.
//
// # Who logs the warnings
//
// Every non-fatal problem in cfg.Warnings (from config.Validate, e.g. a
// login: auto target with no default_user) is logged right here, via a
// *slog.Logger this
// package resolves itself rather than one the caller is required to
// thread through by hand. Absent WithLogger, that resolution is
// slog.Default(), read at call time, matching New's behaviour before it
// took any Option at all. This package, not cmd/authside, owns emitting
// them, for two reasons: (1) New is also called directly by library
// callers (Go tests via httptest) who never go through cmd/authside at
// all — if New stayed silent, a library user with a config that warns
// would get no warning whatsoever; (2) cmd/authside calls
// slog.SetDefault(logger) before ever touching config, so slog.Default()
// here *is* cmd/authside's own logger when WithLogger is not given — the
// operator sees these lines through the exact same handler either way.
// cmd/authside therefore does not also log cfg.Warnings after
// config.Resolve; doing so would just be this same slice, logged twice
// through the same logger under a different message string. WithLogger
// exists for a caller — a Go test being the main one — that wants these
// warnings routed somewhere assertable instead of wherever the
// process-wide default happens to point; it does not change any of the
// above for a caller that does not use it.
func New(cfg *Config, opts ...Option) (http.Handler, error) {
	if cfg == nil {
		cfg = &Config{}
	}

	config.ApplyDefaults(cfg)
	if err := config.Validate(cfg); err != nil {
		return nil, fmt.Errorf("authside: invalid config: %w", err)
	}

	var o options
	for _, opt := range opts {
		opt(&o)
	}
	if o.clock == nil {
		o.clock = clock.System{}
	}
	if o.logger == nil {
		o.logger = slog.Default()
	}
	if o.requestLog == nil {
		o.requestLog = os.Stdout
	}
	logger := o.logger

	for _, w := range cfg.Warnings {
		logger.Warn("authside: config warning", slog.String("warning", w))
	}

	root := tanukirpc.NewRouter(struct{}{})
	root.Use(markerMiddleware)

	// One recorder for the whole process, shared across every target
	// (README "Request log"): the log is a single JSON-lines stream
	// distinguished by each record's own "target" field, not one stream
	// per target. oidcop.New is per-target, so the same *reqlog.Recorder
	// is threaded into each call rather than one being built per target.
	//
	// recorder is built from the same o.clock every target below also
	// receives via oidcop.WithClock, deliberately: if a test moved
	// o.clock forward but the request log kept stamping records with the
	// wall clock instead, a record's "time" field would drift from the
	// iat/exp of a token minted around the same call, breaking any test
	// that tries to correlate the two.
	recorder := reqlog.New(o.requestLog, o.clock)

	for i := range cfg.Targets {
		t := &cfg.Targets[i]
		handler, err := oidcop.New(t, logger, recorder, oidcop.WithClock(o.clock))
		if err != nil {
			return nil, fmt.Errorf("authside: building target %q: %w", t.Name, err)
		}
		root.Mount(t.Mount, handler)
	}

	return root, nil
}

// markerMiddleware stamps every response — including a 404 for a path
// under no target's mount — with authsideMarkerHeader.
func markerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(authsideMarkerHeader, "fake-idp")
		next.ServeHTTP(w, r)
	})
}
