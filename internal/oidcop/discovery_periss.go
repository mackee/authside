package oidcop

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/mackee/authside/config"
	"github.com/mackee/authside/internal/tmpl"
	"github.com/mackee/tanukirpc"
)

// perIssuerRoute pairs one rendered issuer with the route, relative to the
// target's own root, whose discovery document names it.
type perIssuerRoute struct {
	// issuer is the rendered issuer verbatim -- the exact string the
	// document's "issuer" field carries, and the exact string a client
	// doing vanilla discovery compares against the URL it fetched.
	issuer string
	// route is the path this document is served at, relative to the
	// target's root, e.g. "/tenant-a/.well-known/openid-configuration".
	route string
}

// wellKnownPath is the discovery document's path, relative to whatever
// base precedes it.
const wellKnownPath = "/.well-known/openid-configuration"

// enumeratePerIssuerRoutes computes the full set of discovery routes for
// discovery: per_issuer -- one document per distinct rendered issuer
// (README "Discovery under a templated issuer").
//
// The enumeration is over every (user, client) pair rather than over users
// alone, because a user's claims are resolved per client
// (preparedUser.resolveClaims takes the client_id), so the same user can
// render a different issuer for a different client. The result is
// deduplicated: two pairs rendering the same issuer are one document, not
// a collision.
//
// A rendered issuer becomes a route by taking its URL path and stripping
// the target's mount, which is what makes vanilla discovery work: a client
// pointed at "http://authside:5556/entra/tenant-a" fetches
// "/entra/tenant-a/.well-known/openid-configuration", and authside serves
// a document there whose issuer field is that same string. That only works
// if the issuer's path actually sits under the mount -- an issuer naming
// some other path could never be served at its own URL -- so a rendered
// issuer that does not is a construction-time error rather than a route
// silently registered somewhere a client will never look.
//
// What this cannot check is the issuer's *host*: authside has no idea what
// address it is reached at (deliberately -- see README "Issuer, mount and
// advertise" and discovery.go's baseURL), so whether the host routes here
// is the operator's responsibility. The mount-prefix rule is the half that
// is checkable, and it is checked.
//
// Two distinct issuers that map to the same route are a hard error: one
// path cannot serve two different issuer fields, and picking either would
// silently break the client that asked for the other.
func enumeratePerIssuerRoutes(t *config.Target, issuerTmpl *tmpl.Template, users map[string]preparedUser, userOrder []string) ([]perIssuerRoute, error) {
	// byRoute is what detects collisions; order comes from the
	// deterministic iteration below, so two runs of the same config
	// register the same routes in the same order.
	byRoute := make(map[string]string, len(userOrder))
	var routes []perIssuerRoute

	for _, sub := range userOrder {
		user := users[sub]
		for _, client := range t.Clients {
			claims, err := user.resolveClaims(client.ClientID)
			if err != nil {
				return nil, fmt.Errorf("oidcop: target %q: user %q: %w", t.Name, sub, err)
			}
			issuer, err := issuerTmpl.Resolve(tmpl.Login{
				Subject:  sub,
				ClientID: client.ClientID,
				Claims:   claims,
			})
			if err != nil {
				return nil, fmt.Errorf("oidcop: target %q: user %q: issuer: %w", t.Name, sub, err)
			}

			route, err := perIssuerRouteFor(t, issuer, sub)
			if err != nil {
				return nil, err
			}

			if existing, dup := byRoute[route]; dup {
				if existing == issuer {
					continue // same issuer from another (user, client) pair: one document
				}
				return nil, fmt.Errorf(
					"oidcop: target %q: discovery: per_issuer: issuers %q and %q both resolve to the discovery route %q; one path cannot serve two issuers",
					t.Name, existing, issuer, route,
				)
			}
			byRoute[route] = issuer
			routes = append(routes, perIssuerRoute{issuer: issuer, route: route})
		}
	}

	if len(routes) == 0 {
		return nil, fmt.Errorf(
			"oidcop: target %q: discovery: per_issuer needs at least one user and one client to enumerate issuers from, and this target has %d users and %d clients",
			t.Name, len(userOrder), len(t.Clients),
		)
	}
	return routes, nil
}

// perIssuerRouteFor derives the route serving issuer's discovery document
// from issuer's own URL path and the target's mount. subject is only used
// to say which user produced an unusable issuer.
func perIssuerRouteFor(t *config.Target, issuer, subject string) (string, error) {
	u, err := url.Parse(issuer)
	if err != nil {
		return "", fmt.Errorf(
			"oidcop: target %q: user %q: discovery: per_issuer: issuer %q is not a valid URL: %w",
			t.Name, subject, issuer, err,
		)
	}

	suffix, ok := pathBelowMount(t.Mount, u.Path)
	if !ok {
		return "", fmt.Errorf(
			"oidcop: target %q: user %q: discovery: per_issuer: issuer %q has path %q, which is not under this target's mount %q -- its discovery document could never be served at its own URL, so use discovery: shared (or off) instead",
			t.Name, subject, issuer, u.Path, t.Mount,
		)
	}

	// The suffix becomes a literal chi route pattern, and chi reads "{",
	// "}" and "*" as pattern syntax. A "*" panics registration outright,
	// but "{" is worse: "/t{1}/..." registers as a *parameter* route that
	// matches every other tenant too, so one tenant's document would
	// answer for all of them. Neither character is legal raw in a URL
	// path (RFC 3986), so refusing them here costs nothing real.
	if i := strings.IndexAny(suffix, "{}*"); i >= 0 {
		return "", fmt.Errorf(
			"oidcop: target %q: user %q: discovery: per_issuer: issuer %q renders the path segment %q, which contains %q -- that character is not usable in a route (and is not legal raw in a URL path); pick a claim value without it",
			t.Name, subject, issuer, suffix, suffix[i:i+1],
		)
	}

	return suffix + wellKnownPath, nil
}

// pathBelowMount returns the part of issuerPath that lies below mount, and
// whether issuerPath is under mount at all. The result is "" when the
// issuer's path IS the mount (the document then sits at the target's own
// root, exactly where discovery: shared would have put it).
//
// Comparison ignores a trailing slash on either side, matching
// config.normalizeMount's rule, so "/oidc/" and "/oidc" behave the same.
func pathBelowMount(mount, issuerPath string) (string, bool) {
	m := strings.TrimSuffix(mount, "/")
	p := strings.TrimSuffix(issuerPath, "/")

	if p == m {
		return "", true
	}
	// A root mount ("/", normalized to "") contains every absolute path.
	if m == "" {
		if strings.HasPrefix(p, "/") {
			return p, true
		}
		return "", false
	}
	if rest, ok := strings.CutPrefix(p, m+"/"); ok {
		return "/" + rest, true
	}
	return "", false
}

// perIssuerDiscoveryHandler serves the discovery document for one rendered
// issuer. It differs from discoveryHandler in exactly one field -- issuer
// is this route's rendered value rather than the placeholderized template
// -- which is the whole point: a client fetching this URL can compare the
// two and find them equal, so vanilla oidc.NewProvider works against a
// per-tenant issuer with no InsecureIssuerURLContext.
//
// Every endpoint URL is still resolved by the ordinary advertise /
// request-derived rule against the target's mount, NOT against this
// route's tenant sub-path: /authorize, /token and the rest are mounted at
// the target root and are shared by every tenant. Which tenant a login
// belongs to is decided by who logs in, not by which discovery document
// the client happened to read.
func perIssuerDiscoveryHandler(t *Target, issuer string) tanukirpc.Handler[*Target] {
	return tanukirpc.NewHandler(func(ctx tanukirpc.Context[*Target], _ struct{}) (*discoveryResponse, error) {
		if err := t.configuredError("discovery"); err != nil {
			return nil, err
		}
		return t.discoveryDocument(ctx.Request(), issuer), nil
	})
}

// sortedPerIssuerRoutes returns routes ordered by route, for tests and
// logs that want a stable listing independent of config order.
func sortedPerIssuerRoutes(routes []perIssuerRoute) []perIssuerRoute {
	out := make([]perIssuerRoute, len(routes))
	copy(out, routes)
	sort.Slice(out, func(i, j int) bool { return out[i].route < out[j].route })
	return out
}
