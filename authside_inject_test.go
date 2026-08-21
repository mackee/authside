package authside_test

// This file is the exit test for accept_injected_claims: the authside_claims
// cookie, which lets one login carry its own complete identity -- sub and
// every claim -- instead of naming a user the config listed ahead of time.
//
// The case it exists for is a parallel E2E suite that generates identities
// per run (a unique email, a claim derived from it), which by construction
// cannot be enumerated in a users: block. Nothing here configures a single
// user; the target's users: is empty throughout.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/mackee/authside"
	"github.com/mackee/authside/config"
)

const (
	injMount        = "/oidc"
	injClientID     = "local-app"
	injClientSecret = "local-secret"
	injRedirectURI  = "http://app.invalid/callback"
)

// injectedConfig is a target with NO configured users at all: every
// identity it can ever mint arrives in the request.
func injectedConfig(baseURL, issuer string, users []config.User) *authside.Config {
	if issuer == "" {
		issuer = baseURL + injMount
	}
	return &authside.Config{
		Targets: []config.Target{
			{
				Name:                 "oidc",
				Type:                 "oidc",
				Issuer:               issuer,
				Mount:                injMount,
				Login:                config.LoginAuto,
				AcceptInjectedClaims: true,
				Clients: []config.Client{
					{ClientID: injClientID, ClientSecret: injClientSecret, RedirectURIs: []string{injRedirectURI}},
				},
				Users: users,
			},
		},
	}
}

func startInjected(t *testing.T, cfg func(baseURL string) *authside.Config) (baseURL string) {
	t.Helper()
	srv := httptest.NewUnstartedServer(nil)
	baseURL = "http://" + srv.Listener.Addr().String()

	handler, err := authside.New(cfg(baseURL))
	if err != nil {
		t.Fatalf("authside.New: %v", err)
	}
	srv.Config.Handler = handler
	srv.Start()
	t.Cleanup(srv.Close)
	return baseURL
}

// setAuthsideClaimsCookie sets authside_claims the way a Playwright
// context.addCookies call would: on authside's own origin, base64url of a
// flat JSON object whose "sub" names the subject.
func setAuthsideClaimsCookie(t *testing.T, jar *cookiejar.Jar, baseURL string, payload map[string]any) {
	t.Helper()
	u, err := url.Parse(baseURL)
	if err != nil {
		t.Fatalf("parsing base URL: %v", err)
	}
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshalling payload: %v", err)
	}
	jar.SetCookies(u, []*http.Cookie{{
		Name:  "authside_claims",
		Value: base64.RawURLEncoding.EncodeToString(b),
		Path:  "/",
	}})
}

func newJar(t *testing.T) *cookiejar.Jar {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	return jar
}

// TestInject_IdentityFromTheRequestSurvivesTheWholeFlow is the headline
// case: a subject that appears nowhere in the config logs in, and the
// claims that came with it reach the ID token, /userinfo, and -- the part
// that is easy to get wrong -- the tokens minted by a later refresh.
func TestInject_IdentityFromTheRequestSurvivesTheWholeFlow(t *testing.T) {
	baseURL := startInjected(t, func(baseURL string) *authside.Config {
		return injectedConfig(baseURL, "", nil)
	})
	issuer := baseURL + injMount
	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		t.Fatalf("oidc.NewProvider: %v", err)
	}
	oauth2Config := &oauth2.Config{
		ClientID:     injClientID,
		ClientSecret: injClientSecret,
		RedirectURL:  injRedirectURI,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID},
	}

	// The identity a parallel suite would generate: unique per run,
	// with a claim derived from it.
	const (
		wantSub   = "e2e-run-4711-sub"
		wantEmail = "e2e-run-4711@example.com"
		wantHD    = "example.com"
	)

	jar := newJar(t)
	setAuthsideClaimsCookie(t, jar, baseURL, map[string]any{
		"sub": wantSub, "email": wantEmail, "hd": wantHD, "email_verified": true,
	})

	code, gotState := driveAuthorize(t, noFollowClient(jar), issuer, injClientID, injRedirectURI, "state-inject-01", "nonce-inject-01")
	if code == "" || gotState != "state-inject-01" {
		t.Fatalf("authorize returned code=%q state=%q", code, gotState)
	}

	tok, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: injClientID})
	assertInjectedIDToken := func(t *testing.T, what string, tok *oauth2.Token) {
		t.Helper()
		raw, ok := tok.Extra("id_token").(string)
		if !ok || raw == "" {
			t.Fatalf("%s: no id_token in the token response", what)
		}
		idToken, err := verifier.Verify(ctx, raw)
		if err != nil {
			t.Fatalf("%s: Verify: %v", what, err)
		}
		if idToken.Subject != wantSub {
			t.Fatalf("%s: sub = %q, want %q", what, idToken.Subject, wantSub)
		}
		var claims struct {
			Email         string `json:"email"`
			HD            string `json:"hd"`
			EmailVerified bool   `json:"email_verified"`
		}
		if err := idToken.Claims(&claims); err != nil {
			t.Fatalf("%s: Claims: %v", what, err)
		}
		if claims.Email != wantEmail || claims.HD != wantHD || !claims.EmailVerified {
			t.Fatalf("%s: claims = %+v, want email=%q hd=%q email_verified=true", what, claims, wantEmail, wantHD)
		}
	}

	assertInjectedIDToken(t, "code exchange", tok)

	// /userinfo answers from the session the exchange stored, so it is a
	// second, independent read of the same injected claims.
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
	if userinfo["sub"] != wantSub || userinfo["email"] != wantEmail || userinfo["hd"] != wantHD {
		t.Fatalf("/userinfo = %v, want the injected identity back", userinfo)
	}

	// The regression this test exists to pin: a refresh re-mints from
	// stored state, and the injected identity exists nowhere in the
	// config to re-derive from. Deriving it from the subject instead
	// would hand back a token with no claims at all -- silently, with a
	// 200.
	if tok.RefreshToken == "" {
		t.Fatalf("no refresh token issued")
	}
	refreshed, err := oauth2Config.TokenSource(ctx, &oauth2.Token{RefreshToken: tok.RefreshToken}).Token()
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	assertInjectedIDToken(t, "after refresh", refreshed)
}

// TestInject_ResolvesATemplatedIssuer: an injected claim feeds the issuer
// template, so one target imitates a per-tenant provider for a tenant
// nobody configured. discovery stays shared (the document keeps the
// unresolved "{tid}" form), which is what a real Entra-shaped provider
// does -- the client is expected to know its own expected iss.
func TestInject_ResolvesATemplatedIssuer(t *testing.T) {
	baseURL := startInjected(t, func(b string) *authside.Config {
		return injectedConfig(b, b+injMount+"/${claims.tid}/v2.0", nil)
	})
	issuerBase := baseURL + injMount
	ctx := context.Background()

	const tenant = "tenant-generated-at-run-time"
	wantIssuer := issuerBase + "/" + tenant + "/v2.0"

	jar := newJar(t)
	setAuthsideClaimsCookie(t, jar, baseURL, map[string]any{"sub": "u-1", "tid": tenant})

	code, _ := driveAuthorize(t, noFollowClient(jar), issuerBase, injClientID, injRedirectURI, "state-inject-tid", "nonce-inject-tid")
	if code == "" {
		t.Fatalf("authorize returned no code")
	}

	oauth2Config := &oauth2.Config{
		ClientID:     injClientID,
		ClientSecret: injClientSecret,
		RedirectURL:  injRedirectURI,
		Endpoint:     oauth2.Endpoint{AuthURL: issuerBase + "/authorize", TokenURL: issuerBase + "/token"},
	}
	tok, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	raw, _ := tok.Extra("id_token").(string)

	// The expected iss is passed out of band, exactly as a client of a
	// per-tenant provider does (README "Per-tenant issuers").
	keySet := oidc.NewRemoteKeySet(ctx, issuerBase+"/jwks")
	idToken, err := oidc.NewVerifier(wantIssuer, keySet, &oidc.Config{ClientID: injClientID}).Verify(ctx, raw)
	if err != nil {
		t.Fatalf("Verify against %q: %v", wantIssuer, err)
	}
	if idToken.Issuer != wantIssuer {
		t.Fatalf("iss = %q, want %q", idToken.Issuer, wantIssuer)
	}
}

// TestInject_WinsOverAuthsideSub: the payload names a subject as well as
// its claims, so honouring authside_sub first would mint one login's
// claims against another login's sub.
func TestInject_WinsOverAuthsideSub(t *testing.T) {
	baseURL := startInjected(t, func(baseURL string) *authside.Config {
		return injectedConfig(baseURL, "", []config.User{
			{Sub: "configured-user", Claims: map[string]any{"email": "configured@example.com"}},
		})
	})
	issuer := baseURL + injMount

	jar := newJar(t)
	setAuthsideSubCookie(t, jar, baseURL, "configured-user")
	setAuthsideClaimsCookie(t, jar, baseURL, map[string]any{"sub": "injected-user", "email": "injected@example.com"})

	claims := loginAndReadIDTokenClaims(t, issuer, jar)
	if claims["sub"] != "injected-user" || claims["email"] != "injected@example.com" {
		t.Fatalf("claims = %v, want the injected identity to win over authside_sub", claims)
	}
}

// TestInject_ReplacesAConfiguredUserWholesale: an injected sub that
// happens to name a configured user is still not looked up -- the payload
// is the identity, not a patch on one. A merge would make what a test
// gets depend on config it never mentioned.
func TestInject_ReplacesAConfiguredUserWholesale(t *testing.T) {
	baseURL := startInjected(t, func(baseURL string) *authside.Config {
		return injectedConfig(baseURL, "", []config.User{
			{Sub: "user-1", Claims: map[string]any{"email": "configured@example.com", "role": "admin"}},
		})
	})
	issuer := baseURL + injMount

	jar := newJar(t)
	setAuthsideClaimsCookie(t, jar, baseURL, map[string]any{"sub": "user-1", "email": "injected@example.com"})

	claims := loginAndReadIDTokenClaims(t, issuer, jar)
	if claims["email"] != "injected@example.com" {
		t.Fatalf("email = %v, want the injected value", claims["email"])
	}
	if _, ok := claims["role"]; ok {
		t.Fatalf("configured claim %q leaked into an injected login: %v", "role", claims)
	}
}

// TestInject_RefreshDoesNotFallBackToTheConfiguredUser is the silent half
// of the refresh regression. When the injected sub happens to name a
// configured user, re-deriving the claims at refresh time does not fail --
// it succeeds, with the wrong claims, behind a 200. Only comparing the
// refreshed token against the injected values catches it.
func TestInject_RefreshDoesNotFallBackToTheConfiguredUser(t *testing.T) {
	baseURL := startInjected(t, func(baseURL string) *authside.Config {
		return injectedConfig(baseURL, "", []config.User{
			{Sub: "user-1", Claims: map[string]any{"email": "configured@example.com"}},
		})
	})
	issuer := baseURL + injMount
	ctx := context.Background()

	jar := newJar(t)
	setAuthsideClaimsCookie(t, jar, baseURL, map[string]any{"sub": "user-1", "email": "injected@example.com"})

	code, _ := driveAuthorize(t, noFollowClient(jar), issuer, injClientID, injRedirectURI, "state-refresh-fallback", "nonce-refresh-fallback")
	if code == "" {
		t.Fatalf("authorize returned no code")
	}
	oauth2Config := &oauth2.Config{
		ClientID:     injClientID,
		ClientSecret: injClientSecret,
		RedirectURL:  injRedirectURI,
		Endpoint:     oauth2.Endpoint{AuthURL: issuer + "/authorize", TokenURL: issuer + "/token"},
	}
	tok, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if tok.RefreshToken == "" {
		t.Fatalf("no refresh token issued")
	}

	refreshed, err := oauth2Config.TokenSource(ctx, &oauth2.Token{RefreshToken: tok.RefreshToken}).Token()
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	raw, ok := refreshed.Extra("id_token").(string)
	if !ok || raw == "" {
		t.Fatalf("no id_token in the refresh response")
	}
	keySet := oidc.NewRemoteKeySet(ctx, issuer+"/jwks")
	idToken, err := oidc.NewVerifier(issuer, keySet, &oidc.Config{ClientID: injClientID}).Verify(ctx, raw)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	var claims struct {
		Email string `json:"email"`
	}
	if err := idToken.Claims(&claims); err != nil {
		t.Fatalf("Claims: %v", err)
	}
	if claims.Email != "injected@example.com" {
		t.Fatalf("refreshed email = %q, want the injected value; the refresh fell back to the configured user", claims.Email)
	}
}

// TestInject_IgnoredWithoutOptIn: every target in one process shares one
// origin, so a cookie set for target A rides along to target B. B ignores
// it rather than failing, which is what keeps enabling the feature
// somewhere from breaking logins everywhere else.
func TestInject_IgnoredWithoutOptIn(t *testing.T) {
	baseURL := startInjected(t, func(baseURL string) *authside.Config {
		cfg := injectedConfig(baseURL, "", []config.User{
			{Sub: "user-1", Claims: map[string]any{"email": "configured@example.com"}},
		})
		cfg.Targets[0].AcceptInjectedClaims = false
		cfg.Targets[0].DefaultUser = "user-1"
		return cfg
	})
	issuer := baseURL + injMount

	jar := newJar(t)
	setAuthsideClaimsCookie(t, jar, baseURL, map[string]any{"sub": "injected-user", "email": "injected@example.com"})

	claims := loginAndReadIDTokenClaims(t, issuer, jar)
	if claims["sub"] != "user-1" || claims["email"] != "configured@example.com" {
		t.Fatalf("claims = %v, want the cookie ignored and default_user used", claims)
	}
}

// TestInject_MalformedPayloadIsLoud: a payload the caller meant to be
// used and authside cannot read must not fall through to default_user --
// that logs the test in as the wrong identity and fails somewhere far
// from the cause.
func TestInject_MalformedPayloadIsLoud(t *testing.T) {
	baseURL := startInjected(t, func(baseURL string) *authside.Config {
		cfg := injectedConfig(baseURL, "", []config.User{{Sub: "user-1"}})
		cfg.Targets[0].DefaultUser = "user-1"
		return cfg
	})
	issuer := baseURL + injMount

	for _, tc := range []struct{ name, value string }{
		{"not base64", "!!!!"},
		{"no sub", base64.RawURLEncoding.EncodeToString([]byte(`{"email":"a@b.example"}`))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			jar := newJar(t)
			u, _ := url.Parse(baseURL)
			jar.SetCookies(u, []*http.Cookie{{Name: "authside_claims", Value: tc.value, Path: "/"}})

			loc := authorizeLocation(t, noFollowClient(jar), issuer, "state-malformed")
			q := loc.Query()
			if q.Get("error") != "invalid_request" {
				t.Fatalf("error = %q, want invalid_request (location %q)", q.Get("error"), loc)
			}
			if q.Get("code") != "" {
				t.Fatalf("a code was issued for a malformed payload: %q", loc)
			}
			if !strings.Contains(q.Get("error_description"), "authside_claims") {
				t.Fatalf("error_description = %q, want it to name the cookie", q.Get("error_description"))
			}
		})
	}
}

// TestInject_EndSessionClearsTheCookie: logout has to clear
// authside_claims for the same reason it clears authside_sub -- otherwise
// the next login in the same browser context silently reuses the previous
// identity.
func TestInject_EndSessionClearsTheCookie(t *testing.T) {
	baseURL := startInjected(t, func(baseURL string) *authside.Config {
		return injectedConfig(baseURL, "", nil)
	})
	issuer := baseURL + injMount

	jar := newJar(t)
	setAuthsideClaimsCookie(t, jar, baseURL, map[string]any{"sub": "u-1"})

	resp, err := noFollowClient(jar).Get(issuer + "/end_session")
	if err != nil {
		t.Fatalf("GET /end_session: %v", err)
	}
	defer resp.Body.Close()

	u, _ := url.Parse(baseURL)
	for _, c := range jar.Cookies(u) {
		if c.Name == "authside_claims" && c.Value != "" {
			t.Fatalf("authside_claims survived /end_session with value %q", c.Value)
		}
	}
}

// TestInject_RevocationEndsAnInjectedSession: revocation keys on token
// strings, not on subjects, so it has no reason to care where an identity
// came from -- but refreshFamily now carries that identity, so this pins
// that the family-wide kill still reaches an injected login's tokens.
func TestInject_RevocationEndsAnInjectedSession(t *testing.T) {
	baseURL := startInjected(t, func(baseURL string) *authside.Config {
		return injectedConfig(baseURL, "", nil)
	})
	issuer := baseURL + injMount
	ctx := context.Background()

	jar := newJar(t)
	setAuthsideClaimsCookie(t, jar, baseURL, map[string]any{"sub": "u-revoke", "email": "u-revoke@example.com"})

	code, _ := driveAuthorize(t, noFollowClient(jar), issuer, injClientID, injRedirectURI, "state-revoke", "nonce-revoke")
	if code == "" {
		t.Fatalf("authorize returned no code")
	}
	oauth2Config := &oauth2.Config{
		ClientID:     injClientID,
		ClientSecret: injClientSecret,
		RedirectURL:  injRedirectURI,
		Endpoint:     oauth2.Endpoint{AuthURL: issuer + "/authorize", TokenURL: issuer + "/token"},
	}
	tok, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	userinfoStatus := func() int {
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
		return resp.StatusCode
	}
	if got := userinfoStatus(); got != http.StatusOK {
		t.Fatalf("/userinfo before revocation = %d, want 200", got)
	}

	// Revoking the refresh token kills the whole family, access token
	// included -- the "end a session from outside the application" lever.
	resp, err := http.PostForm(issuer+"/revocation", url.Values{
		"token":         {tok.RefreshToken},
		"client_id":     {injClientID},
		"client_secret": {injClientSecret},
	})
	if err != nil {
		t.Fatalf("POST /revocation: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /revocation status = %d, want 200", resp.StatusCode)
	}

	if got := userinfoStatus(); got != http.StatusUnauthorized {
		t.Fatalf("/userinfo after revocation = %d, want 401", got)
	}
}

// --- helpers -------------------------------------------------------

// authorizeLocation drives GET /authorize and returns the Location it
// redirects to, whether that carries a code or an error.
func authorizeLocation(t *testing.T, client *http.Client, issuer, state string) *url.URL {
	t.Helper()
	u, err := url.Parse(issuer + "/authorize")
	if err != nil {
		t.Fatalf("parsing authorize URL: %v", err)
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", injClientID)
	q.Set("redirect_uri", injRedirectURI)
	q.Set("scope", "openid")
	q.Set("state", state)
	u.RawQuery = q.Encode()

	resp, err := client.Get(u.String())
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("/authorize status = %d, want 302", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parsing Location: %v", err)
	}
	return loc
}

// loginAndReadIDTokenClaims completes one login with whatever cookies jar
// carries and returns the ID token's claims as a plain map.
func loginAndReadIDTokenClaims(t *testing.T, issuer string, jar *cookiejar.Jar) map[string]any {
	t.Helper()
	ctx := context.Background()

	code, _ := driveAuthorize(t, noFollowClient(jar), issuer, injClientID, injRedirectURI, "state-claims-read", "nonce-claims-read")
	if code == "" {
		t.Fatalf("authorize returned no code")
	}
	oauth2Config := &oauth2.Config{
		ClientID:     injClientID,
		ClientSecret: injClientSecret,
		RedirectURL:  injRedirectURI,
		Endpoint:     oauth2.Endpoint{AuthURL: issuer + "/authorize", TokenURL: issuer + "/token"},
	}
	tok, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok || raw == "" {
		t.Fatalf("no id_token in the token response")
	}

	keySet := oidc.NewRemoteKeySet(ctx, issuer+"/jwks")
	idToken, err := oidc.NewVerifier(issuer, keySet, &oidc.Config{ClientID: injClientID}).Verify(ctx, raw)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		t.Fatalf("Claims: %v", err)
	}
	if claims == nil {
		t.Fatalf("no claims in %s", raw)
	}
	return claims
}
