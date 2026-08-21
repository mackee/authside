package authside_test

// This file is the acceptance suite for README "Why not an existing
// mock?": three tests, each one the direct negation of a structural
// limitation of oauth2-proxy/mockoidc. If all three pass, that is
// authside's stated reason to exist.
//
//  1. TestM2_1_IssuerWithTrailingPathSegment  -- mockoidc's Issuer() is
//     Addr()+IssuerBase, and IssuerBase = "/oidc" is a const: an issuer
//     ending in "/v2.0" is unreachable there.
//  2. TestM2_2_HTTPSIssuerOverPlainHTTPListener -- mockoidc's scheme
//     follows its own listener's TLS state: a provider behind a
//     TLS-terminating ingress cannot be imitated there.
//  3. TestM2_3_TemplatedPerTenantIssuer -- mockoidc's iss comes from one
//     config field for the whole process: it cannot vary per login,
//     which is exactly what a per-tenant provider (Entra) requires.
//
// This file reuses the helpers defined in authside_test.go
// (noFollowClient, setAuthsideSubCookie, driveAuthorize) rather than
// duplicating them -- see that file's doc comment for what each does.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/mackee/authside"
	"github.com/mackee/authside/config"
)

// TestM2_1_IssuerWithTrailingPathSegment is README "Why not an existing
// mock?" point 1: an issuer ending in a path segment other than "/oidc"
// ("/v2.0", Entra-shaped) must be fully usable -- served, discoverable,
// and verifiable -- something mockoidc's "Issuer() = Addr() + const
// IssuerBase" cannot represent at all.
func TestM2_1_IssuerWithTrailingPathSegment(t *testing.T) {
	const (
		issuer       = "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0"
		mount        = "/entra"
		clientID     = "local-app"
		clientSecret = "local-secret"
		redirectURI  = "http://app.invalid/callback"
	)

	// httptest.NewUnstartedServer, exactly as in authside_test.go: the
	// config's advertise URLs need the server's address before the handler
	// exists.
	srv := httptest.NewUnstartedServer(nil)
	baseURL := "http://" + srv.Listener.Addr().String()
	servedBase := baseURL + mount

	// issuer's host (login.microsoftonline.com) is never the host this
	// target is actually served on, so this target needs advertise (README
	// "Split-horizon dev environments") to make discovery's endpoints
	// point somewhere reachable -- both audiences point at the same test
	// server here, since this test has no browser/app split of its own.
	// See the final report for what happens if advertise is left unset:
	// that is a genuine, separately-confirmed finding, not something this
	// test papers over by omission.
	cfg := &authside.Config{
		Targets: []config.Target{
			{
				Name:   "entra",
				Type:   "oidc",
				Issuer: issuer,
				Mount:  mount,
				Login:  config.LoginAuto,
				Advertise: config.Advertise{
					Internal: servedBase,
					Browser:  servedBase,
				},
				Clients: []config.Client{
					{ClientID: clientID, ClientSecret: clientSecret, RedirectURIs: []string{redirectURI}},
				},
				Users: []config.User{
					{Sub: "user-1", Claims: map[string]any{"email": "alice@example.com"}},
				},
			},
		},
	}
	handler, err := authside.New(cfg)
	if err != nil {
		t.Fatalf("authside.New: %v", err)
	}
	srv.Config.Handler = handler
	srv.Start()
	defer srv.Close()

	t.Run("discovery document is fetchable and its issuer is byte-exact", func(t *testing.T) {
		resp, err := http.Get(servedBase + "/.well-known/openid-configuration")
		if err != nil {
			t.Fatalf("GET %s/.well-known/openid-configuration: %v", servedBase, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("discovery status = %d, want 200", resp.StatusCode)
		}
		var doc map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
			t.Fatalf("decoding discovery document: %v", err)
		}
		if doc["issuer"] != issuer {
			t.Fatalf("discovery issuer = %q, want byte-exact %q (trailing /v2.0 intact)", doc["issuer"], issuer)
		}

		// The discovery document's own endpoints must be reachable ON
		// THIS TEST SERVER, not on the (unreachable, and never dialled by
		// this test) login.microsoftonline.com host.
		jwksURI, _ := doc["jwks_uri"].(string)
		if !strings.HasPrefix(jwksURI, servedBase) {
			t.Fatalf("jwks_uri = %q, want it to start with the served base %q -- it must not point at the issuer's (unreachable) host", jwksURI, servedBase)
		}
		jresp, err := http.Get(jwksURI)
		if err != nil {
			t.Fatalf("GET jwks_uri %s: %v", jwksURI, err)
		}
		defer jresp.Body.Close()
		if jresp.StatusCode != http.StatusOK {
			t.Fatalf("GET jwks_uri %s: status = %d, want 200", jwksURI, jresp.StatusCode)
		}
	})

	t.Run("full login and token exchange yields a byte-exact iss, and it verifies", func(t *testing.T) {
		// Tier-3 client style (README "Client compatibility"): the
		// issuer's host is not the test server, so the expected iss is
		// supplied out of band via oidc.InsecureIssuerURLContext, and
		// discovery/token/jwks are fetched from the served mount URL
		// rather than from the issuer string.
		ctx := oidc.InsecureIssuerURLContext(context.Background(), issuer)
		provider, err := oidc.NewProvider(ctx, servedBase)
		if err != nil {
			t.Fatalf("oidc.NewProvider: %v", err)
		}
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
		setAuthsideSubCookie(t, jar, baseURL, "user-1")
		client := noFollowClient(jar)

		const state = "m2-1-state-0123456789"
		const nonce = "m2-1-nonce-abcdefghij"
		code, gotState := driveAuthorize(t, client, servedBase, clientID, redirectURI, state, nonce)
		if code == "" {
			t.Fatalf("no code in the /authorize redirect")
		}
		if gotState != state {
			t.Fatalf("state = %q, want byte-identical %q", gotState, state)
		}

		tok, err := oauth2Config.Exchange(ctx, code)
		if err != nil {
			t.Fatalf("Exchange: %v", err)
		}
		rawIDToken, ok := tok.Extra("id_token").(string)
		if !ok || rawIDToken == "" {
			t.Fatalf("no id_token in the token response")
		}

		verifier := provider.Verifier(&oidc.Config{ClientID: clientID})
		idToken, err := verifier.Verify(ctx, rawIDToken)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if idToken.Issuer != issuer {
			t.Fatalf("id_token iss = %q, want byte-exact %q", idToken.Issuer, issuer)
		}
	})
}

// TestM2_2_HTTPSIssuerOverPlainHTTPListener_AuthsideNeverRejectsIssuerListenMismatch
// is README "Why not an existing mock?" point 2: an https:// issuer
// served by a plain-HTTP listener (the TLS-terminating-ingress shape)
// must be accepted, served, and verifiable end to end. mockoidc's Addr()
// only returns "https" when its own listener has TLS, so it cannot
// represent this configuration at all.
func TestM2_2_HTTPSIssuerOverPlainHTTPListener_AuthsideNeverRejectsIssuerListenMismatch(t *testing.T) {
	const (
		issuer       = "https://auth.local.test/oidc"
		mount        = "/oidc"
		clientID     = "local-app"
		clientSecret = "local-secret"
		redirectURI  = "http://app.invalid/callback"
	)

	cfg := &authside.Config{
		Targets: []config.Target{
			{
				Name:   "oidc",
				Type:   "oidc",
				Issuer: issuer,
				Mount:  mount,
				Login:  config.LoginAuto,
				Clients: []config.Client{
					{ClientID: clientID, ClientSecret: clientSecret, RedirectURIs: []string{redirectURI}},
				},
				Users: []config.User{
					{Sub: "user-1", Claims: map[string]any{"email": "alice@example.com"}},
				},
			},
		},
	}

	// The load-bearing assertion this test exists for (README: "authside
	// never rejects a configuration because issuer disagrees with
	// listen"): an https:// issuer over a plain HTTP listener must start
	// without error at all.
	handler, err := authside.New(cfg)
	if err != nil {
		t.Fatalf(`authside.New rejected an https:// issuer served over a plain HTTP listener; README states "authside never rejects a configuration because issuer disagrees with listen" -- this must start clean. Got: %v`, err)
	}

	srv := httptest.NewServer(handler)
	defer srv.Close()
	if strings.HasPrefix(srv.URL, "https://") {
		t.Fatalf("test server unexpectedly has TLS (srv.URL = %q); this test requires a genuinely plain-HTTP listener to be meaningful", srv.URL)
	}
	servedBase := srv.URL + mount

	// The client hand-builds oidc.ProviderConfig: the issuer
	// (https://auth.local.test) is never dialled by this test at all --
	// only its literal string matters for the iss comparison. Discovery
	// is skipped entirely (ProviderConfig.NewProvider does a straight
	// field copy, no fetch, no issuer comparison), and the endpoint URLs
	// point at the plain-HTTP test server.
	providerCfg := &oidc.ProviderConfig{
		IssuerURL:   issuer,
		AuthURL:     servedBase + "/authorize",
		TokenURL:    servedBase + "/token",
		JWKSURL:     servedBase + "/jwks",
		UserInfoURL: servedBase + "/userinfo",
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
	setAuthsideSubCookie(t, jar, srv.URL, "user-1")
	client := noFollowClient(jar)

	const state = "m2-2-state-0123456789"
	const nonce = "m2-2-nonce-abcdefghij"
	code, gotState := driveAuthorize(t, client, servedBase, clientID, redirectURI, state, nonce)
	if code == "" {
		t.Fatalf("no code in the /authorize redirect")
	}
	if gotState != state {
		t.Fatalf("state = %q, want byte-identical %q", gotState, state)
	}

	tok, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		t.Fatalf("no id_token in the token response")
	}

	// Verification succeeds with a verifier expecting the https:// issuer
	// -- proving authside did not reject, rewrite, or downgrade the
	// scheme anywhere on the way to minting this token.
	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		t.Fatalf("Verify: %v (an https:// issuer must verify cleanly even though the wire transport was plain HTTP)", err)
	}
	if idToken.Issuer != issuer {
		t.Fatalf("id_token iss = %q, want byte-exact %q", idToken.Issuer, issuer)
	}

	// Belt-and-braces: authside's own discovery document (served over the
	// same plain-HTTP listener) must still carry the https:// issuer
	// verbatim -- confirming the scheme was never downgraded on authside's
	// side either, not just on the client's hand-built side.
	discResp, err := http.Get(servedBase + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("GET discovery: %v", err)
	}
	defer discResp.Body.Close()
	var doc map[string]any
	if err := json.NewDecoder(discResp.Body).Decode(&doc); err != nil {
		t.Fatalf("decoding discovery document: %v", err)
	}
	if doc["issuer"] != issuer {
		t.Fatalf("discovery issuer = %q, want byte-exact %q (must not be downgraded to http://)", doc["issuer"], issuer)
	}
}

// TestM2_3_TemplatedPerTenantIssuer is README "Why not an existing
// mock?" point 3, and the most important of the three: a single
// target whose issuer is templated over a login's claims
// (Entra's ${claims.tid}) so that different logins get different iss --
// a property mockoidc's "one issuer per process" cannot provide at all.
func TestM2_3_TemplatedPerTenantIssuer(t *testing.T) {
	const (
		mount         = "/entra"
		clientID      = "local-app"
		clientSecret  = "local-secret"
		redirectURI   = "http://app.invalid/callback"
		issuerTmplStr = "https://login.microsoftonline.com/${claims.tid}/v2.0"
		tid1          = "11111111-1111-1111-1111-111111111111"
		tid2          = "22222222-2222-2222-2222-222222222222"
	)
	issuerFor := func(tid string) string {
		return "https://login.microsoftonline.com/" + tid + "/v2.0"
	}

	cfg := &authside.Config{
		Targets: []config.Target{
			{
				Name:      "entra",
				Type:      "oidc",
				Issuer:    issuerTmplStr,
				Mount:     mount,
				Login:     config.LoginAuto,
				Discovery: config.DiscoverShared, // the default; explicit here since this test's whole point is discovery's shape
				Clients: []config.Client{
					{ClientID: clientID, ClientSecret: clientSecret, RedirectURIs: []string{redirectURI}},
				},
				Users: []config.User{
					{Sub: "user-1", Claims: map[string]any{"tid": tid1, "email": "alice@example.com"}},
					{Sub: "user-2", Claims: map[string]any{"tid": tid2, "email": "bob@example.net"}},
				},
			},
		},
	}
	handler, err := authside.New(cfg)
	if err != nil {
		t.Fatalf("authside.New: %v", err)
	}
	srv := httptest.NewServer(handler)
	defer srv.Close()
	servedBase := srv.URL + mount

	var jwksURI string

	t.Run("shared discovery document leaves the tid placeholder unresolved", func(t *testing.T) {
		resp, err := http.Get(servedBase + "/.well-known/openid-configuration")
		if err != nil {
			t.Fatalf("GET discovery: %v", err)
		}
		defer resp.Body.Close()
		var doc map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
			t.Fatalf("decoding discovery document: %v", err)
		}

		const wantPlaceholderIssuer = "https://login.microsoftonline.com/{tid}/v2.0"
		if doc["issuer"] != wantPlaceholderIssuer {
			t.Fatalf("discovery issuer = %q, want the unresolved placeholder %q (real Entra metadata does the same -- see README \"Discovery under a templated issuer\")", doc["issuer"], wantPlaceholderIssuer)
		}

		jwksURI, _ = doc["jwks_uri"].(string)
		if jwksURI == "" {
			t.Fatalf("discovery document has no jwks_uri")
		}
		jresp, err := http.Get(jwksURI)
		if err != nil {
			t.Fatalf("GET jwks_uri %s: %v", jwksURI, err)
		}
		defer jresp.Body.Close()
		if jresp.StatusCode != http.StatusOK {
			t.Fatalf("GET jwks_uri %s: status = %d, want 200 -- one key set shared across tenants", jwksURI, jresp.StatusCode)
		}
	})

	login := func(t *testing.T, sub, tid string) (*oidc.Provider, *oauth2.Token) {
		t.Helper()
		expectedIssuer := issuerFor(tid)
		// Tier-3 client style, and exactly what a real multi-tenant client
		// must do against the real provider (README "Per-tenant issuers"):
		// the expected iss is supplied out of band, since the shared
		// document's own issuer field is a placeholder the client cannot
		// resolve on its own.
		ctx := oidc.InsecureIssuerURLContext(context.Background(), expectedIssuer)
		provider, err := oidc.NewProvider(ctx, servedBase)
		if err != nil {
			t.Fatalf("oidc.NewProvider(sub=%s): %v", sub, err)
		}
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
		setAuthsideSubCookie(t, jar, srv.URL, sub)
		client := noFollowClient(jar)
		code, _ := driveAuthorize(t, client, servedBase, clientID, redirectURI, "st-"+sub, "no-"+sub)
		if code == "" {
			t.Fatalf("no code in the /authorize redirect for sub=%s", sub)
		}
		tok, err := oauth2Config.Exchange(ctx, code)
		if err != nil {
			t.Fatalf("Exchange(sub=%s): %v", sub, err)
		}
		return provider, tok
	}

	var providerA, providerB *oidc.Provider
	var rawA, rawB string

	t.Run("different logins produce different iss", func(t *testing.T) {
		var tokA, tokB *oauth2.Token
		providerA, tokA = login(t, "user-1", tid1)
		providerB, tokB = login(t, "user-2", tid2)

		var ok bool
		rawA, ok = tokA.Extra("id_token").(string)
		if !ok || rawA == "" {
			t.Fatalf("no id_token for tenant A")
		}
		rawB, ok = tokB.Extra("id_token").(string)
		if !ok || rawB == "" {
			t.Fatalf("no id_token for tenant B")
		}

		idA, err := providerA.Verifier(&oidc.Config{ClientID: clientID}).Verify(context.Background(), rawA)
		if err != nil {
			t.Fatalf("verify tenant-A token under tenant-A's own issuer: %v", err)
		}
		if idA.Issuer != issuerFor(tid1) {
			t.Fatalf("tenant-A id_token iss = %q, want %q", idA.Issuer, issuerFor(tid1))
		}

		idB, err := providerB.Verifier(&oidc.Config{ClientID: clientID}).Verify(context.Background(), rawB)
		if err != nil {
			t.Fatalf("verify tenant-B token under tenant-B's own issuer: %v", err)
		}
		if idB.Issuer != issuerFor(tid2) {
			t.Fatalf("tenant-B id_token iss = %q, want %q", idB.Issuer, issuerFor(tid2))
		}

		if idA.Issuer == idB.Issuer {
			t.Fatalf("tenant-A and tenant-B produced the SAME iss (%q); a per-tenant issuer must differ per login", idA.Issuer)
		}
	})

	t.Run("tenant isolation: a token minted for tenant A fails verification under tenant B's issuer, on iss specifically", func(t *testing.T) {
		if rawA == "" || rawB == "" || providerA == nil || providerB == nil {
			t.Fatalf("prerequisite subtest did not produce tokens/providers")
		}
		verifierA := providerA.Verifier(&oidc.Config{ClientID: clientID})
		verifierB := providerB.Verifier(&oidc.Config{ClientID: clientID})

		_, err := verifierB.Verify(context.Background(), rawA)
		if err == nil {
			t.Fatalf("tenant-A's token verified under tenant-B's issuer; want an issuer-mismatch failure -- tenant isolation is broken")
		}
		// Same target, one shared key set (asserted above): the
		// signature is valid under both providers, so a failure here can
		// only be the iss check (go-oidc verify.go: signature is checked
		// before iss, so this message appearing is proof the failure is
		// not a signature or expiry problem in disguise).
		if !strings.Contains(err.Error(), "issued by a different provider") {
			t.Fatalf("verifying tenant-A's token under tenant-B's issuer failed for the WRONG reason (want an iss mismatch, e.g. \"issued by a different provider\"): %v", err)
		}

		_, err = verifierA.Verify(context.Background(), rawB)
		if err == nil {
			t.Fatalf("tenant-B's token verified under tenant-A's issuer; want an issuer-mismatch failure -- tenant isolation is broken")
		}
		if !strings.Contains(err.Error(), "issued by a different provider") {
			t.Fatalf("verifying tenant-B's token under tenant-A's issuer failed for the WRONG reason (want an iss mismatch, e.g. \"issued by a different provider\"): %v", err)
		}
	})
}
