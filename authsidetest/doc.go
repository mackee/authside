// Package authsidetest is an httptest-based Go library helper for driving
// authside in-process from tests: spinning up a target, choosing who logs
// in, and minting tokens without a browser. See README "As a Go library"
// for the design this package implements.
//
// NewOIDC starts a real httptest.Server backed by authside.New and hands
// back an *OIDC through which a test drives a normal OIDC discovery /
// authorization-code / token flow — with coreos/go-oidc, x/oauth2, or a
// plain http.Client — against a genuinely live issuer, and controls both
// "who logs in" (ClientAs) and "what time it is" (Now/Advance/SetTime)
// without mutating the served config at runtime (the same "configuration
// is the whole API" discipline the sidecar itself follows — see the repo
// README's "Design goals").
//
// # The redirect-URI ordering constraint
//
// NewOIDC needs its target's client redirect URIs before it can build the
// config and start the server, so WithRedirectURIs / WithClient must be
// given to NewOIDC itself, up front. That is awkward for the common case
// of testing a real application whose own callback endpoint also runs on
// a random httptest port: that port is not known until the application's
// own httptest.Server has started. There is no way around this ordering
// — a test whose application-under-test serves its callback on a random
// port must therefore start that application FIRST, then pass
// app.URL+"/callback" (or whatever the callback path is) to NewOIDC via
// WithRedirectURIs, not the other way around:
//
//	app := startMyApp(t) // starts first, so its URL is known
//	as := authsidetest.NewOIDC(t,
//		authsidetest.WithRedirectURIs(app.URL+"/callback"),
//	)
//	// now point app's own OIDC client config at as.Issuer(), as.ClientID(), ...
//
// Building authside's own server first and only then discovering the
// application's callback address does not work: authside would have to be
// reconfigured (and thus rebuilt/restarted) after the fact, which this
// package deliberately never does.
//
// # Quieting the "request completed" lines
//
// Each request served here also produces one `INFO request completed` line
// on the default slog logger. That line comes from tanukirpc's handler,
// which calls the log/slog package function directly rather than going
// through any logger this package or authside is given, so no option here
// suppresses it. Silence it from the test binary that consumes this
// package, which is the process that owns the default logger:
//
//	func TestMain(m *testing.M) {
//		slog.SetDefault(slog.New(slog.DiscardHandler))
//		os.Exit(m.Run())
//	}
//
// That is process-wide, so it also drops whatever else the test binary
// logs through the default logger. To keep your own lines, set a handler
// that drops only these -- Enabled/Handle filtering on the message -- and
// note that authside's own config warnings are separate and already
// routed wherever authside.WithLogger points.
package authsidetest
