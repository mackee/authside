package authside_test

// This file is the minimal single-target exit test: a real end-to-end
// login flow, driven entirely through golang.org/x/oauth2 and
// coreos/go-oidc/v3 -- the same libraries a real application uses --
// against httptest.NewServer(authside.New(cfg)), with no shortcuts into
// authside's internals.
//
// The test server's URL is only known once httptest.NewUnstartedServer
// has allocated its listener, and authside.New needs the issuer *before*
// building the handler that becomes that server's Handler -- so this test
// builds the config from the not-yet-started server's address, builds
// the handler, attaches it, and only then starts serving. The config's
// issuer is the test server's URL + mount, so tier-1 simple mode holds.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/mackee/authside"
	"github.com/mackee/authside/config"
)

// noFollowClient is an *http.Client that never follows a redirect, so a
// test can inspect authside's 302 to redirect_uri directly instead of
// having http.Client try to actually dial the (non-existent) client
// callback server.
func noFollowClient(jar *cookiejar.Jar) *http.Client {
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// setAuthsideSubCookie sets the authside_sub cookie on authside's own
// origin (baseURL), the way a Playwright context.addCookies call or a Go
// test's cookie jar is expected to (README "Login modes").
func setAuthsideSubCookie(t *testing.T, jar *cookiejar.Jar, baseURL, sub string) {
	t.Helper()
	u, err := url.Parse(baseURL)
	if err != nil {
		t.Fatalf("parsing base URL: %v", err)
	}
	jar.SetCookies(u, []*http.Cookie{{Name: "authside_sub", Value: sub, Path: "/"}})
}

// driveAuthorize hits GET {issuer}/authorize (via the http.Client's cookie
// jar, which is how login: auto picks a subject) and returns the code and
// state that come back on the redirect to redirectURI.
func driveAuthorize(t *testing.T, client *http.Client, issuer, clientID, redirectURI, state, nonce string) (code, gotState string) {
	t.Helper()

	u, err := url.Parse(issuer + "/authorize")
	if err != nil {
		t.Fatalf("parsing authorize URL: %v", err)
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", "openid")
	q.Set("state", state)
	q.Set("nonce", nonce)
	u.RawQuery = q.Encode()

	resp, err := client.Get(u.String())
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("GET /authorize status = %d, want 302", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parsing Location: %v", err)
	}
	if errCode := loc.Query().Get("error"); errCode != "" {
		t.Fatalf("authorize redirected with error=%s (%s)", errCode, loc.Query().Get("error_description"))
	}
	return loc.Query().Get("code"), loc.Query().Get("state")
}

// oneTarget builds a single-target authside config whose issuer is
// baseURL+mount ("simple mode": the issuer is also the served URL, so
// vanilla oidc.NewProvider works with no extra wiring). idTokenTTL is
// nil to leave it at authside.New's default (1h, applied via
// config.ApplyDefaults), or a pointer to an explicit override (e.g. a
// negative TTL, to mint an already-expired token on purpose).
func oneTarget(name, baseURL, mount, clientID, clientSecret, redirectURI string, idTokenTTL *config.Duration) *authside.Config {
	return &authside.Config{
		Targets: []config.Target{
			{
				Name:       name,
				Type:       "oidc",
				Issuer:     baseURL + mount,
				Mount:      mount,
				Login:      config.LoginAuto,
				IDTokenTTL: idTokenTTL,
				Clients: []config.Client{
					{ClientID: clientID, ClientSecret: clientSecret, RedirectURIs: []string{redirectURI}},
				},
				Users: []config.User{
					{Sub: "user-1", Claims: map[string]any{
						"email": "alice@example.com",
						"name":  "Alice",
					}},
				},
			},
		},
	}
}

func TestM1_EndToEndLoginFlow(t *testing.T) {
	const (
		mount        = "/oidc"
		clientID     = "local-app"
		clientSecret = "local-secret"
		redirectURI  = "http://app.invalid/callback"
	)

	srv := httptest.NewUnstartedServer(nil)
	baseURL := "http://" + srv.Listener.Addr().String()

	cfg := oneTarget("oidc", baseURL, mount, clientID, clientSecret, redirectURI, nil)
	handler, err := authside.New(cfg)
	if err != nil {
		t.Fatalf("authside.New: %v", err)
	}
	srv.Config.Handler = handler
	srv.Start()
	defer srv.Close()

	issuer := baseURL + mount
	ctx := context.Background()

	// Step 1: vanilla discovery. A byte mismatch between the discovery
	// document's "issuer" and issuer itself is fatal here.
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
	client := noFollowClient(jar)

	// Step 2: drive /authorize, capture code and state.
	const state = "the-exact-state-value-0123456789"
	const nonce = "the-exact-nonce-value-abcdefghij"
	code, gotState := driveAuthorize(t, client, issuer, clientID, redirectURI, state, nonce)
	if code == "" {
		t.Fatalf("no code in the /authorize redirect")
	}
	if gotState != state {
		t.Fatalf("state = %q, want byte-identical %q", gotState, state)
	}

	// Step 3: Exchange -- exercises client_secret_basic-then-post retry
	// behaviour inside x/oauth2 itself.
	tok, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if tok.AccessToken == "" {
		t.Fatalf("no access_token in the token response")
	}

	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		t.Fatalf("no id_token in the token response")
	}

	// Step 4: verify the ID token and its claims.
	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if idToken.Subject != "user-1" {
		t.Fatalf("sub = %q, want user-1", idToken.Subject)
	}
	if idToken.Nonce != nonce {
		t.Fatalf("nonce = %q, want %q", idToken.Nonce, nonce)
	}
	var claims struct {
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := idToken.Claims(&claims); err != nil {
		t.Fatalf("Claims: %v", err)
	}
	if claims.Email != "alice@example.com" || claims.Name != "Alice" {
		t.Fatalf("claims = %+v, want email=alice@example.com name=Alice", claims)
	}

	// Step 5: at_hash, via go-oidc's own VerifyAccessToken.
	if err := idToken.VerifyAccessToken(tok.AccessToken); err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}

	// Step 6: /userinfo with the access token.
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
	if userinfo["sub"] != "user-1" {
		t.Fatalf("/userinfo sub = %v, want user-1", userinfo["sub"])
	}
	if userinfo["email"] != "alice@example.com" {
		t.Fatalf("/userinfo email = %v, want alice@example.com", userinfo["email"])
	}

	if resp.Header.Get("X-Authside") == "" {
		t.Fatalf("/userinfo response missing the X-Authside marker header")
	}
}

// TestM1_NegativeIDTokenTTLProducesAnAlreadyExpiredToken is the
// "Scenarios are configuration" check: id_token_ttl: -5m must mint a
// token that go-oidc's Verify rejects as expired, with no special-cased
// "clock manipulation" mechanism involved -- the token is simply born
// expired.
func TestM1_NegativeIDTokenTTLProducesAnAlreadyExpiredToken(t *testing.T) {
	const (
		mount        = "/oidc-expired"
		clientID     = "local-app"
		clientSecret = "local-secret"
		redirectURI  = "http://app.invalid/callback"
	)

	srv := httptest.NewUnstartedServer(nil)
	baseURL := "http://" + srv.Listener.Addr().String()

	negTTL := config.Duration(-5 * time.Minute)
	cfg := oneTarget("oidc-expired", baseURL, mount, clientID, clientSecret, redirectURI, &negTTL)
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
	client := noFollowClient(jar)

	code, _ := driveAuthorize(t, client, issuer, clientID, redirectURI, "st", "no")
	tok, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	rawIDToken, _ := tok.Extra("id_token").(string)

	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})
	_, err = verifier.Verify(ctx, rawIDToken)
	if err == nil {
		t.Fatalf("Verify succeeded for a token minted with id_token_ttl: -5m, want an expiry error")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("Verify error = %v, want it to mention expiry", err)
	}
}

// TestM1_TwoTargetsDifferentIssuersOneProcess is the structural half of
// README "Why not an existing mock?" point 3: "one issuer per process" is
// exactly the limitation this project exists to not have.
// One authside.New(cfg) handler serves two targets at different mounts
// with different issuers; each verifies correctly under its own issuer,
// and a token from one target must NOT verify under the other's issuer.
func TestM1_TwoTargetsDifferentIssuersOneProcess(t *testing.T) {
	const redirectURI = "http://app.invalid/callback"

	srv := httptest.NewUnstartedServer(nil)
	baseURL := "http://" + srv.Listener.Addr().String()

	cfg := &authside.Config{
		Targets: []config.Target{
			{
				Name: "tenant-a", Type: "oidc",
				Issuer: baseURL + "/tenant-a", Mount: "/tenant-a", Login: config.LoginAuto,
				Clients: []config.Client{{ClientID: "app", ClientSecret: "secret", RedirectURIs: []string{redirectURI}}},
				Users:   []config.User{{Sub: "user-1"}},
			},
			{
				Name: "tenant-b", Type: "oidc",
				Issuer: baseURL + "/tenant-b", Mount: "/tenant-b", Login: config.LoginAuto,
				Clients: []config.Client{{ClientID: "app", ClientSecret: "secret", RedirectURIs: []string{redirectURI}}},
				Users:   []config.User{{Sub: "user-1"}},
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

	ctx := context.Background()

	login := func(mount string) (*oidc.Provider, *oauth2.Token) {
		issuer := baseURL + mount
		provider, err := oidc.NewProvider(ctx, issuer)
		if err != nil {
			t.Fatalf("oidc.NewProvider(%s): %v", issuer, err)
		}
		oauth2Config := &oauth2.Config{
			ClientID: "app", ClientSecret: "secret", RedirectURL: redirectURI,
			Endpoint: provider.Endpoint(), Scopes: []string{oidc.ScopeOpenID},
		}
		jar, _ := cookiejar.New(nil)
		setAuthsideSubCookie(t, jar, baseURL, "user-1")
		client := noFollowClient(jar)
		code, _ := driveAuthorize(t, client, issuer, "app", redirectURI, "st", "no")
		tok, err := oauth2Config.Exchange(ctx, code)
		if err != nil {
			t.Fatalf("Exchange(%s): %v", issuer, err)
		}
		return provider, tok
	}

	providerA, tokA := login("/tenant-a")
	providerB, tokB := login("/tenant-b")

	rawA, _ := tokA.Extra("id_token").(string)
	rawB, _ := tokB.Extra("id_token").(string)

	if _, err := providerA.Verifier(&oidc.Config{ClientID: "app"}).Verify(ctx, rawA); err != nil {
		t.Fatalf("tenant-a token failed to verify under tenant-a's own issuer: %v", err)
	}
	if _, err := providerB.Verifier(&oidc.Config{ClientID: "app"}).Verify(ctx, rawB); err != nil {
		t.Fatalf("tenant-b token failed to verify under tenant-b's own issuer: %v", err)
	}

	// Tenant isolation: tenant-a's token must NOT verify under tenant-b's
	// issuer, and vice versa.
	if _, err := providerB.Verifier(&oidc.Config{ClientID: "app"}).Verify(ctx, rawA); err == nil {
		t.Fatalf("tenant-a's token verified under tenant-b's issuer, want an iss mismatch error")
	}
	if _, err := providerA.Verifier(&oidc.Config{ClientID: "app"}).Verify(ctx, rawB); err == nil {
		t.Fatalf("tenant-b's token verified under tenant-a's issuer, want an iss mismatch error")
	}
}
