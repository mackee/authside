package oidcop

import (
	"net/http"

	"github.com/mackee/authside/config"
	"github.com/mackee/authside/internal/httpx"
	"github.com/mackee/authside/internal/reqlog"
	"github.com/mackee/tanukirpc"
)

// authsideMarkerHeader is set on every response this package serves
// (README "Loud about being fake"), so a token or response from authside
// is recognisable if it ever reaches somewhere it should not have.
const authsideMarkerHeader = "X-Authside"

// newRouter builds the http.Handler for one Target, with every route
// registered relative to the target's own root -- the caller (authside.go)
// mounts this under the target's configured mount.
//
// recorder is wrapped around the whole target router via reqlog.Middleware
// (README "Request log"), so it captures method/path/status for every
// route below, this target's own 404s included. Middleware reads
// req.URL.Path as the http.Handler it wraps receives it; go-chi's Mount
// (which is what authside.go uses to mount this handler under the
// target's configured mount) shifts its own internal chi.RouteContext
// route path but never rewrites req.URL.Path itself, so what Middleware
// sees here is already the full externally-visible path (e.g.
// "/oidc/authorize", not "/authorize") with no extra work needed --
// verified against the real tanukirpc/chi Mount, not assumed.
//
// tanukirpc.WithAccessLogger[*Target](nil) disables tanukirpc's own
// built-in "accesslog" line (accesslog.go's accessLogger, on by default in
// tanukirpc.NewRouter): passing the nil AccessLogger short-circuits
// Router.accessLoggerLog, which checks `r.accessLogger == nil` before
// calling it. That is the only tanukirpc-logged line this disables --
// handler.go's unconditional `slog.InfoContext(ctx, "request completed")`
// bypasses r.logger entirely (it calls the log/slog package function
// directly against slog.Default()) and has no option to suppress it.
// That residual line goes to slog.Default(), never to this package's own
// JSON request log, so the two do not conflict.
func newRouter(t *Target, recorder *reqlog.Recorder) http.Handler {
	r := httpx.NewRouter[*Target](t, tanukirpc.WithAccessLogger[*Target](nil))
	r.Use(markerMiddleware)

	// discovery: off is implemented by simply never registering this
	// route: an unmatched path falls through to the router's own 404,
	// which is exactly what README's "off" behaviour asks for.
	//
	// per_issuer registers one document per rendered issuer instead, at
	// the tenant sub-path each issuer's own URL implies, and no document
	// at the target root -- there is no single issuer the root could
	// name. A tenant that is not configured therefore 404s exactly like
	// any other unmatched path, marker header and request log line
	// included. The routes are enumerated at construction, so this loop
	// cannot fail: see discovery_periss.go.
	switch t.discovery {
	case config.DiscoverShared:
		r.Get(wellKnownPath, discoveryHandler(t))
	case config.DiscoverPerIssuer:
		for _, pi := range t.perIssuer {
			r.Get(pi.route, perIssuerDiscoveryHandler(t, pi.issuer))
		}
	}

	r.Get("/jwks", jwksHandler(t))
	r.Get("/authorize", authorizeHandler(t))

	// POST /authorize is only registered for the login mode that actually
	// uses it: picker's click, or form's submission. login: auto has no
	// POST /authorize at all -- it never renders a page to submit, and an
	// unmatched POST here falls through to the router's own 404/405.
	switch t.login {
	case config.LoginPicker:
		r.Post("/authorize", pickerSubmitHandler(t))
	case config.LoginForm:
		r.Post("/authorize", formSubmitHandler(t))
	}

	r.Post("/token", tokenHandler(t))
	r.Get("/userinfo", userinfoHandler(t))
	r.Post("/revocation", revocationHandler(t))
	r.Get("/end_session", endSessionHandler(t))

	return reqlog.Middleware(recorder, t.name)(r)
}

// markerMiddleware stamps every response -- including a 404 for an
// unmatched path -- with authsideMarkerHeader.
func markerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(authsideMarkerHeader, "fake-idp")
		next.ServeHTTP(w, r)
	})
}
