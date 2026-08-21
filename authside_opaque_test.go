package authside_test

// This file is the exit test for access_token: opaque, driven end to end
// through the same libraries a real application uses (x/oauth2 and
// coreos/go-oidc), against httptest.NewServer(authside.New(cfg)).
//
// The point worth proving at this level, and the reason this is not just
// a unit test in internal/oidcop, is at_hash: OIDC Core computes it over
// the octets of whatever the access_token value is, with no requirement
// that the value be a JWT. authside therefore does not special-case the
// opaque format there -- and go-oidc's own IDToken.VerifyAccessToken,
// which is the strictest consumer of that claim this project knows
// about, has to agree.

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

func TestM9_OpaqueAccessTokenEndToEnd(t *testing.T) {
	const (
		mount        = "/oidc-opaque"
		clientID     = "local-app"
		clientSecret = "local-secret"
		redirectURI  = "http://app.invalid/callback"
	)

	srv := httptest.NewUnstartedServer(nil)
	baseURL := "http://" + srv.Listener.Addr().String()

	cfg := oneTarget("oidc-opaque", baseURL, mount, clientID, clientSecret, redirectURI, nil)
	cfg.Targets[0].AccessToken = config.AccessTokenOpaque

	handler, err := authside.New(cfg)
	if err != nil {
		t.Fatalf("authside.New: %v", err)
	}
	srv.Config.Handler = handler
	srv.Start()
	defer srv.Close()

	issuer := baseURL + mount
	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, issuer)
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

	const state, nonce = "state-opaque-0123456789", "nonce-opaque-abcdefghij"
	code, gotState := driveAuthorize(t, noFollowClient(jar), issuer, clientID, redirectURI, state, nonce)
	if code == "" || gotState != state {
		t.Fatalf("authorize returned code=%q state=%q, want a code and state %q", code, gotState, state)
	}

	tok, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	// The access token is an opaque handle: not a JWT, so a client that
	// tries to decode it instead of presenting it fails here rather than
	// in production.
	if strings.Contains(tok.AccessToken, ".") {
		t.Fatalf("access_token = %q, want an opaque handle with no JWT structure", tok.AccessToken)
	}

	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		t.Fatalf("no id_token in the token response")
	}
	idToken, err := provider.Verifier(&oidc.Config{ClientID: clientID}).Verify(ctx, rawIDToken)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// The claim this whole file exists for: at_hash over an opaque
	// access token, checked by the strictest consumer available.
	if err := idToken.VerifyAccessToken(tok.AccessToken); err != nil {
		t.Fatalf("VerifyAccessToken against an opaque access token: %v", err)
	}

	// And the token still works as a credential: /userinfo resolves it
	// by lookup, which is what makes a claims-free token usable at all.
	req, err := http.NewRequest(http.MethodGet, issuer+"/userinfo", nil)
	if err != nil {
		t.Fatalf("building /userinfo request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /userinfo: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/userinfo status = %d, want 200", resp.StatusCode)
	}
	var userinfo map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&userinfo); err != nil {
		t.Fatalf("decoding /userinfo body: %v", err)
	}
	if userinfo["sub"] != "user-1" || userinfo["email"] != "alice@example.com" {
		t.Fatalf("/userinfo = %v, want sub=user-1 email=alice@example.com", userinfo)
	}
}
