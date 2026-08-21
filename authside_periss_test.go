package authside_test

// This file is the exit test for discovery: per_issuer, the escape hatch
// that turns a per-tenant issuer from README "Client compatibility" tier 3
// into tier 1.
//
// The whole feature is one equality. A client pointed at a tenant's issuer
// URL fetches {issuer}/.well-known/openid-configuration and compares the
// document's issuer field against the URL it used; go-oidc's NewProvider
// fails outright when they differ, which is why tier 3 normally needs
// oidc.InsecureIssuerURLContext to suppress that comparison. Nothing here
// uses it. Two tenants complete vanilla discovery and a full login in one
// process, each getting its own iss.

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/mackee/authside"
	"github.com/mackee/authside/config"
)

// perTenantConfig is one target whose issuer templates on each user's tid
// claim, mounted so that every rendered issuer's path sits under the
// mount -- the condition per_issuer requires.
func perTenantConfig(baseURL, mount, clientID, clientSecret, redirectURI string) *authside.Config {
	return &authside.Config{
		Targets: []config.Target{
			{
				Name:      "entra",
				Type:      "oidc",
				Issuer:    baseURL + mount + "/${claims.tid}",
				Mount:     mount,
				Login:     config.LoginAuto,
				Discovery: config.DiscoverPerIssuer,
				Clients: []config.Client{
					{ClientID: clientID, ClientSecret: clientSecret, RedirectURIs: []string{redirectURI}},
				},
				Users: []config.User{
					{Sub: "user-a", Claims: map[string]any{"tid": "tenant-a", "email": "alice@tenant-a.example"}},
					{Sub: "user-b", Claims: map[string]any{"tid": "tenant-b", "email": "bob@tenant-b.example"}},
				},
			},
		},
	}
}

func TestM6_PerIssuerDiscoveryMakesVanillaLoginWorkPerTenant(t *testing.T) {
	const (
		mount        = "/entra"
		clientID     = "local-app"
		clientSecret = "local-secret"
		redirectURI  = "http://app.invalid/callback"
	)

	srv := httptest.NewUnstartedServer(nil)
	baseURL := "http://" + srv.Listener.Addr().String()

	handler, err := authside.New(perTenantConfig(baseURL, mount, clientID, clientSecret, redirectURI))
	if err != nil {
		t.Fatalf("authside.New: %v", err)
	}
	srv.Config.Handler = handler
	srv.Start()
	defer srv.Close()

	ctx := context.Background()

	for _, tc := range []struct{ sub, tenant, email string }{
		{"user-a", "tenant-a", "alice@tenant-a.example"},
		{"user-b", "tenant-b", "bob@tenant-b.example"},
	} {
		t.Run(tc.tenant, func(t *testing.T) {
			tenantIssuer := baseURL + mount + "/" + tc.tenant

			// Vanilla discovery against the tenant's own issuer URL. No
			// InsecureIssuerURLContext: NewProvider itself checks that
			// the document's issuer field equals tenantIssuer, so this
			// call succeeding IS the assertion.
			provider, err := oidc.NewProvider(ctx, tenantIssuer)
			if err != nil {
				t.Fatalf("oidc.NewProvider(%q): %v", tenantIssuer, err)
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
			setAuthsideSubCookie(t, jar, baseURL, tc.sub)

			// The endpoints come from the shared target root, not from
			// the tenant path -- so /authorize is driven against the
			// mount, exactly as the discovery document advertised.
			const state, nonce = "state-per-issuer-01", "nonce-per-issuer-01"
			code, gotState := driveAuthorize(t, noFollowClient(jar), baseURL+mount, clientID, redirectURI, state, nonce)
			if code == "" || gotState != state {
				t.Fatalf("authorize returned code=%q state=%q", code, gotState)
			}

			tok, err := oauth2Config.Exchange(ctx, code)
			if err != nil {
				t.Fatalf("Exchange: %v", err)
			}
			rawIDToken, ok := tok.Extra("id_token").(string)
			if !ok || rawIDToken == "" {
				t.Fatalf("no id_token in the token response")
			}

			// And the token's iss matches the tenant the client
			// discovered: provider.Verifier checks iss against the
			// issuer NewProvider was given.
			idToken, err := provider.Verifier(&oidc.Config{ClientID: clientID}).Verify(ctx, rawIDToken)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if idToken.Issuer != tenantIssuer {
				t.Fatalf("iss = %q, want %q", idToken.Issuer, tenantIssuer)
			}
			if idToken.Subject != tc.sub {
				t.Fatalf("sub = %q, want %q", idToken.Subject, tc.sub)
			}
			var claims struct {
				Email string `json:"email"`
			}
			if err := idToken.Claims(&claims); err != nil {
				t.Fatalf("Claims: %v", err)
			}
			if claims.Email != tc.email {
				t.Fatalf("email = %q, want %q", claims.Email, tc.email)
			}
		})
	}
}

// TestM6_UnconfiguredTenantHasNoDiscoveryDocument: per_issuer serves the
// enumerated tenants and nothing else, so a client pointed at a tenant
// nobody configured fails at discovery rather than getting a document that
// names an issuer no token will ever carry.
func TestM6_UnconfiguredTenantHasNoDiscoveryDocument(t *testing.T) {
	const (
		mount        = "/entra"
		clientID     = "local-app"
		clientSecret = "local-secret"
		redirectURI  = "http://app.invalid/callback"
	)

	srv := httptest.NewUnstartedServer(nil)
	baseURL := "http://" + srv.Listener.Addr().String()

	handler, err := authside.New(perTenantConfig(baseURL, mount, clientID, clientSecret, redirectURI))
	if err != nil {
		t.Fatalf("authside.New: %v", err)
	}
	srv.Config.Handler = handler
	srv.Start()
	defer srv.Close()

	resp, err := http.Get(baseURL + mount + "/tenant-nobody-configured/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	if resp.Header.Get("X-Authside") == "" {
		t.Fatal("the 404 is missing the X-Authside marker header")
	}

	if _, err := oidc.NewProvider(context.Background(), baseURL+mount+"/tenant-nobody-configured"); err == nil {
		t.Fatal("oidc.NewProvider succeeded for an unconfigured tenant, want an error")
	}
}
