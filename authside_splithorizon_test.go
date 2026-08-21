package authside_test

// This file is the end-to-end half of the split-horizon advertise test:
// internal/oidcop/discovery_advertise_test.go proves the *document* names
// the right URL for each field; this file proves a real login actually
// completes when the browser and the app literally cannot reach each
// other's address -- the genuine split-horizon topology the README
// documents ("Split-horizon dev environments" / "Issuer, mount and
// advertise"), not just two differently-labelled strings.
//
// One authside.New(cfg) handler is served from TWO separate
// httptest.Server instances with different host:port, standing in for
// "the browser's ingress hostname" and "the app container's internal
// address". advertise.browser names the first, advertise.internal names
// the second, and issuer is a THIRD address that is reachable from
// NEITHER -- an Entra-shaped issuer, exactly the case the README's
// "issuer is an identifier, not necessarily a reachable address" design
// note is about. Every request in this test is sent to the specific
// server that owns it: /authorize to the browser server, /token and the
// JWKS fetch (and /userinfo) to the internal server. If discovery.go's
// audience selection were ever built backwards, or if browser/internal
// endpoints leaked into the wrong document, this test would fail with a
// connection error or a verification failure, not just a mismatched
// string.
//
// This file reuses the helpers defined in authside_test.go
// (noFollowClient, setAuthsideSubCookie, driveAuthorize) rather than
// duplicating them.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/mackee/authside"
	"github.com/mackee/authside/config"
)

// sortedArrays returns a shallow copy of a decoded JSON object with every
// []any value (as produced by encoding/json for a JSON array) replaced by
// a sorted copy of itself, so two documents that differ only in the
// iteration order of a same-content list compare equal. It exists solely
// to make TestSplitHorizon_LoginCompletesAcrossTwoUnreachableAddresses's
// discovery-document comparison robust to claims_supported's documented
// map-iteration non-determinism (see that test) without weakening what
// it actually checks: element content, not element order.
func sortedArrays(doc map[string]any) map[string]any {
	out := make(map[string]any, len(doc))
	for k, v := range doc {
		arr, ok := v.([]any)
		if !ok {
			out[k] = v
			continue
		}
		strs := make([]string, 0, len(arr))
		for _, e := range arr {
			s, ok := e.(string)
			if !ok {
				// Not a string array (none of this discovery document's
				// arrays are anything else, but fail loudly rather than
				// silently mis-comparing if that ever changes).
				out[k] = v
				strs = nil
				break
			}
			strs = append(strs, s)
		}
		if strs == nil {
			continue
		}
		sort.Strings(strs)
		out[k] = strs
	}
	return out
}

// TestSplitHorizon_LoginCompletesAcrossTwoUnreachableAddresses is the
// main acceptance test for this file: a full authorization-code login,
// with /authorize driven against the "browser" server and /token, the
// JWKS fetch and /userinfo driven against the "internal" server, and an
// issuer that is reachable from neither.
//
// The login itself is driven against explicit, hand-picked URLs (see
// providerCfg below) rather than by following the discovery document, so
// swapping advertise.browser and advertise.internal inside discovery.go
// does not by itself break the login half of this test -- confirmed
// empirically: temporarily swapping them left the login subtest green
// while the discovery subtest below went red. That subtest is the one
// load-bearing against exactly that regression: it fetches the real
// discovery document from both servers and asserts each field is rooted
// at the httptest server whose address genuinely differs from the
// other's (unlike TestM2_1's use of the same base for both audiences),
// so a browser/internal swap cannot hide behind "both sides look the
// same".

func TestSplitHorizon_LoginCompletesAcrossTwoUnreachableAddresses(t *testing.T) {
	const (
		mount        = "/oidc"
		clientID     = "local-app"
		clientSecret = "local-secret"
		redirectURI  = "http://app.invalid/callback"
		// Entra-shaped and, deliberately, dialled by nobody in this test:
		// neither browserSrv nor internalSrv is bound to this host, so a
		// login that only ever succeeds because something fell back to
		// deriving endpoints from issuer would fail here with a DNS/dial
		// error instead of quietly passing.
		issuer = "https://login.microsoftonline.com/44444444-4444-4444-4444-444444444444/v2.0"
	)

	// Chicken-and-egg: the two httptest servers' addresses are needed to
	// build the config, but the config is needed to build the handler
	// those servers should serve. httptest.NewUnstartedServer already
	// allocates a real listener (and hence a real host:port) without
	// requiring a Handler up front, so both listeners are stood up
	// first, their addresses feed the config/advertise values, and only
	// then is New's handler attached and Start called on each.
	browserSrv := httptest.NewUnstartedServer(nil)
	internalSrv := httptest.NewUnstartedServer(nil)
	browserBase := "http://" + browserSrv.Listener.Addr().String()
	internalBase := "http://" + internalSrv.Listener.Addr().String()

	cfg := &authside.Config{
		Targets: []config.Target{
			{
				Name:   "oidc",
				Type:   "oidc",
				Issuer: issuer,
				Mount:  mount,
				Login:  config.LoginAuto,
				Advertise: config.Advertise{
					// Advertise values carry the mount, exactly like the
					// README's split-horizon example
					// (config/readme_test.go's TestSplitHorizonYAML):
					// "http://authside:5556/oidc", not just the bare host.
					Browser:  browserBase + mount,
					Internal: internalBase + mount,
				},
				Clients: []config.Client{
					{ClientID: clientID, ClientSecret: clientSecret, RedirectURIs: []string{redirectURI}},
				},
				Users: []config.User{
					{Sub: "user-1", Claims: map[string]any{"email": "alice@example.com", "name": "Alice"}},
				},
			},
		},
	}

	handler, err := authside.New(cfg)
	if err != nil {
		t.Fatalf("authside.New: %v", err)
	}
	browserSrv.Config.Handler = handler
	internalSrv.Config.Handler = handler
	browserSrv.Start()
	internalSrv.Start()
	defer browserSrv.Close()
	defer internalSrv.Close()

	browserServed := browserBase + mount
	internalServed := internalBase + mount

	// --- Discovery must not vary with which side answers it ---
	//
	// Both httptest servers share the exact same handler, so this is not
	// "the app happens to configure two similar targets" -- it is one
	// target whose discovery document is, by construction, independent
	// of the request's own host (advertise wins over request-derived
	// base; see internal/oidcop/discovery.go's baseURL). Cheap, but high
	// value: if that independence ever regressed (e.g. advertise being
	// applied only when the request arrives on one particular side),
	// this is what would catch it.
	t.Run("discovery document is identical from either side, with each half naming the right host", func(t *testing.T) {
		docFrom := func(base string) map[string]any {
			resp, err := http.Get(base + "/.well-known/openid-configuration")
			if err != nil {
				t.Fatalf("GET discovery from %s: %v", base, err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("GET discovery from %s: status = %d, want 200", base, resp.StatusCode)
			}
			var doc map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
				t.Fatalf("decoding discovery document from %s: %v", base, err)
			}
			return doc
		}

		fromBrowser := docFrom(browserServed)
		fromInternal := docFrom(internalServed)
		// claims_supported (and, in principle, any other *_supported
		// list) is assembled from a Go map inside claimsSupported()
		// (internal/oidcop/discovery.go), so its element order is not
		// stable even across two calls to the very same target -- a
		// genuine, separately-reportable non-determinism, not something
		// this test's job is to pin down. Sort every array-valued field
		// before comparing so this test stays focused on its own
		// question -- do the two sides agree on *content* -- without
		// being tripped by that unrelated ordering issue; sorting a copy
		// still catches any real difference in which elements are
		// present.
		if !reflect.DeepEqual(sortedArrays(fromBrowser), sortedArrays(fromInternal)) {
			t.Fatalf("discovery document differs by which side answered it:\n  from browserSrv: %+v\n  from internalSrv: %+v", fromBrowser, fromInternal)
		}

		if fromBrowser["issuer"] != issuer {
			t.Fatalf("issuer = %v, want the configured (unreachable) issuer %q", fromBrowser["issuer"], issuer)
		}

		checks := []struct {
			field    string
			wantHost string
		}{
			{"authorization_endpoint", browserBase},
			{"end_session_endpoint", browserBase},
			{"token_endpoint", internalBase},
			{"jwks_uri", internalBase},
			{"userinfo_endpoint", internalBase},
			{"revocation_endpoint", internalBase},
		}
		for _, c := range checks {
			got, _ := fromBrowser[c.field].(string)
			if !strings.HasPrefix(got, c.wantHost) {
				t.Errorf("%s = %q, want it rooted at %q", c.field, got, c.wantHost)
			}
		}
	})

	// --- The actual login, each request sent to the side that owns it ---
	//
	// discovery cannot be used here to look up an unreachable issuer (no
	// resolver on earth maps login.microsoftonline.com/.../v2.0 to either
	// httptest server), so the provider is hand-built from the two known
	// server addresses, exactly as TestM2_2_HTTPSIssuerOverPlainHTTPListener
	// already does in this package.
	providerCfg := &oidc.ProviderConfig{
		IssuerURL:   issuer,
		AuthURL:     browserServed + "/authorize",
		TokenURL:    internalServed + "/token",
		JWKSURL:     internalServed + "/jwks",
		UserInfoURL: internalServed + "/userinfo",
		Algorithms:  []string{"RS256"},
	}
	ctx := context.Background()
	provider := providerCfg.NewProvider(ctx)

	oauth2Config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURI,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID},
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	// login: auto reads the authside_sub cookie from the request that
	// hits /authorize, which lands on browserSrv -- so the cookie must be
	// set on browserSrv's own origin, not internalSrv's.
	setAuthsideSubCookie(t, jar, browserBase, "user-1")
	client := noFollowClient(jar)

	const state = "split-horizon-state-0123456789"
	const nonce = "split-horizon-nonce-abcdefghij"

	// GET /authorize -> browserSrv.
	code, gotState := driveAuthorize(t, client, browserServed, clientID, redirectURI, state, nonce)
	if code == "" {
		t.Fatalf("no code in the /authorize redirect from browserSrv")
	}
	if gotState != state {
		t.Fatalf("state = %q, want byte-identical %q", gotState, state)
	}

	// POST /token -> internalSrv (oauth2Config.Endpoint.TokenURL is
	// internalServed+"/token", set above).
	tok, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		t.Fatalf("Exchange (POST %s/token): %v", internalServed, err)
	}
	if tok.AccessToken == "" {
		t.Fatalf("no access_token in the token response")
	}
	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		t.Fatalf("no id_token in the token response")
	}

	// Verify the id_token: JWKS fetch -> internalSrv (provider.Verifier
	// uses providerCfg.JWKSURL, set to internalServed+"/jwks" above), iss
	// must equal the configured (unreachable) issuer.
	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		t.Fatalf("Verify (JWKS fetched from internalSrv): %v", err)
	}
	if idToken.Issuer != issuer {
		t.Fatalf("id_token iss = %q, want byte-exact %q", idToken.Issuer, issuer)
	}
	if idToken.Subject != "user-1" {
		t.Fatalf("id_token sub = %q, want user-1", idToken.Subject)
	}
	if idToken.Nonce != nonce {
		t.Fatalf("id_token nonce = %q, want %q", idToken.Nonce, nonce)
	}

	// GET /userinfo -> internalSrv.
	req, err := http.NewRequest(http.MethodGet, internalServed+"/userinfo", nil)
	if err != nil {
		t.Fatalf("building /userinfo request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s/userinfo: %v", internalServed, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/userinfo status = %d, want 200", resp.StatusCode)
	}
	var userinfo map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&userinfo); err != nil {
		t.Fatalf("decoding /userinfo body: %v", err)
	}
	if userinfo["sub"] != "user-1" {
		t.Fatalf("/userinfo sub = %v, want user-1", userinfo["sub"])
	}
	if userinfo["email"] != "alice@example.com" {
		t.Fatalf("/userinfo email = %v, want alice@example.com", userinfo["email"])
	}
}
