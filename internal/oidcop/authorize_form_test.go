package oidcop

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/mackee/authside/config"
)

// readJSON decodes resp's JSON body into v.
func readJSON(resp *http.Response, v any) error {
	return json.NewDecoder(resp.Body).Decode(v)
}

// decodeUnverifiedJWTPayload extracts a JWT's payload (second segment) as
// a plain map, without verifying its signature -- fine for a test that
// only wants to read claims out of a token this same package just minted
// and is not itself testing signature verification.
func decodeUnverifiedJWTPayload(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, io.ErrUnexpectedEOF
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(payload, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// formTarget returns a config.Target for login: form with one configured
// user. acceptAny controls accept_any_username (README "Login modes").
func formTarget(acceptAny bool) *config.Target {
	tgt := testTarget()
	tgt.Login = config.LoginForm
	tgt.Mount = ""
	tgt.AcceptAnyUsername = acceptAny
	tgt.Users = []config.User{
		{Sub: "user-1", Claims: map[string]any{"email": "alice@example.com", "name": "Alice"}},
	}
	return tgt
}

// postAuthorizeForm submits form to srv's POST /authorize without
// following redirects, so the test can tell a 302 (login succeeded) apart
// from a 200 (re-rendered page, login failed) directly.
func postAuthorizeForm(t *testing.T, srv *httptest.Server, form url.Values) *http.Response {
	t.Helper()
	resp, err := noRedirectHTTPClient().PostForm(srv.URL+"/authorize", form)
	if err != nil {
		t.Fatalf("POST /authorize: %v", err)
	}
	return resp
}

func baseFormValues(clientID, redirectURI, state string) url.Values {
	return url.Values{
		"response_type": {"code"},
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"state":         {state},
		"nonce":         {"n-" + state},
	}
}

func TestForm_SuccessForConfiguredUser(t *testing.T) {
	srv := newTestServer(t, formTarget(false))

	form := baseFormValues("client-1", "https://app.example/cb", "st1")
	form.Set("username", "user-1")
	form.Set("password", "whatever")

	resp := postAuthorizeForm(t, srv, form)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 302 (body: %s)", resp.StatusCode, body)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parsing Location: %v", err)
	}
	if loc.Query().Get("code") == "" {
		t.Fatalf("no code in the redirect")
	}
	if got := loc.Query().Get("state"); got != "st1" {
		t.Fatalf("state = %q, want st1", got)
	}
}

func TestForm_AnyPasswordIsAccepted(t *testing.T) {
	srv := newTestServer(t, formTarget(false))

	for _, pw := range []string{"correct-horse-battery-staple", "", "wrong on purpose", "🔑"} {
		form := baseFormValues("client-1", "https://app.example/cb", "st-"+pw)
		form.Set("username", "user-1")
		form.Set("password", pw)

		resp := postAuthorizeForm(t, srv, form)
		if resp.StatusCode != http.StatusFound {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("password %q: status = %d, want 302 -- any password must be accepted for a configured user (body: %s)", pw, resp.StatusCode, body)
		}
		resp.Body.Close()
	}
}

func TestForm_AcceptAnyUsernameTrue_MintsTokenForInventedSub(t *testing.T) {
	srv := newTestServer(t, formTarget(true))

	form := baseFormValues("client-1", "https://app.example/cb", "st2")
	form.Set("username", "brand-new-invented-user")
	form.Set("password", "irrelevant")

	resp := postAuthorizeForm(t, srv, form)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 302 (body: %s)", resp.StatusCode, body)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parsing Location: %v", err)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in the redirect")
	}

	// Exchange the code and check the minted sub is exactly the invented
	// username, with no claims (README "Login modes": "become the sub,
	// so tests can invent users without editing the config").
	tokResp, err := http.PostForm(srv.URL+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://app.example/cb"},
		"client_id":     {"client-1"},
		"client_secret": {"secret-1"},
	})
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer tokResp.Body.Close()
	if tokResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(tokResp.Body)
		t.Fatalf("/token status = %d, want 200 (body: %s)", tokResp.StatusCode, body)
	}
	var body struct {
		IDToken string `json:"id_token"`
	}
	if err := readJSON(tokResp, &body); err != nil {
		t.Fatalf("decoding token response: %v", err)
	}
	claims, err := decodeUnverifiedJWTPayload(body.IDToken)
	if err != nil {
		t.Fatalf("decoding id_token payload: %v", err)
	}
	if claims["sub"] != "brand-new-invented-user" {
		t.Fatalf("sub = %v, want brand-new-invented-user", claims["sub"])
	}
	if _, hasEmail := claims["email"]; hasEmail {
		t.Fatalf("claims = %+v, want no email claim for an invented, unconfigured user", claims)
	}
}

func TestForm_UnknownUsernameWithAcceptAnyFalse_RerendersWithError(t *testing.T) {
	srv := newTestServer(t, formTarget(false))

	form := baseFormValues("client-1", "https://app.example/cb", "st3")
	form.Set("username", "no-such-user")
	form.Set("password", "whatever")

	resp := postAuthorizeForm(t, srv, form)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200 (re-rendered form), body: %s", resp.StatusCode, body)
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		t.Fatalf("Location = %q, want no redirect -- no code should have been issued for an unknown username", loc)
	}
	body, _ := io.ReadAll(resp.Body)
	html := string(body)
	if !strings.Contains(html, "no-such-user") {
		t.Fatalf("error page does not mention the unknown username %q: %s", "no-such-user", html)
	}
	if !strings.Contains(strings.ToLower(html), "unknown") && !strings.Contains(strings.ToLower(html), "error") {
		t.Fatalf("error page has no visible error text: %s", html)
	}

	// Authorization parameters must be preserved for a retry.
	hidden := extractHiddenInputs(html)
	if hidden["state"] != "st3" {
		t.Fatalf("hidden state = %q after a failed attempt, want st3 (preserved)", hidden["state"])
	}
	if hidden["client_id"] != "client-1" {
		t.Fatalf("hidden client_id = %q after a failed attempt, want client-1 (preserved)", hidden["client_id"])
	}
	if hidden["redirect_uri"] != "https://app.example/cb" {
		t.Fatalf("hidden redirect_uri = %q after a failed attempt, want https://app.example/cb (preserved)", hidden["redirect_uri"])
	}
}

func TestForm_EmptyUsername_RerendersWithError(t *testing.T) {
	srv := newTestServer(t, formTarget(false))

	form := baseFormValues("client-1", "https://app.example/cb", "st4")
	form.Set("username", "")
	form.Set("password", "whatever")

	resp := postAuthorizeForm(t, srv, form)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200 (re-rendered form), body: %s", resp.StatusCode, body)
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		t.Fatalf("Location = %q, want no redirect -- no code should have been issued for an empty username", loc)
	}
	body, _ := io.ReadAll(resp.Body)
	html := string(body)
	if !strings.Contains(strings.ToLower(html), "username is required") && !strings.Contains(strings.ToLower(html), "error") {
		t.Fatalf("error page has no visible error text: %s", html)
	}

	hidden := extractHiddenInputs(html)
	if hidden["state"] != "st4" {
		t.Fatalf("hidden state = %q after a failed attempt, want st4 (preserved)", hidden["state"])
	}
	if hidden["nonce"] != "n-st4" {
		t.Fatalf("hidden nonce = %q after a failed attempt, want n-st4 (preserved)", hidden["nonce"])
	}
}

func TestForm_GET_RendersFormNotRedirect(t *testing.T) {
	srv := newTestServer(t, formTarget(false))

	resp, err := noRedirectHTTPClient().Get(srv.URL + "/authorize?response_type=code&client_id=client-1&redirect_uri=https://app.example/cb&state=st")
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200 (body: %s)", resp.StatusCode, body)
	}
	body, _ := io.ReadAll(resp.Body)
	html := string(body)
	if !strings.Contains(html, `name="username"`) || !strings.Contains(html, `name="password"`) {
		t.Fatalf("form page missing username/password fields: %s", html)
	}
	if !strings.Contains(html, "authside") {
		t.Fatalf("form page missing the fake-IdP banner: %s", html)
	}
}

// TestForm_QuickStartShapedConfig_EndToEndLoginFlow drives login: form
// with a real oidc.NewProvider + oauth2.Config, the same way
// TestPicker_QuickStartConfig_FullFlow does for picker, confirming form
// mode also produces a verifiable ID token end to end.
func TestForm_QuickStartShapedConfig_EndToEndLoginFlow(t *testing.T) {
	const (
		clientID     = "local-app"
		clientSecret = "local-secret"
		redirectURI  = "http://localhost:8080/auth/callback"
	)

	srv := httptest.NewUnstartedServer(nil)
	baseURL := "http://" + srv.Listener.Addr().String()

	oneHour := config.Duration(time.Hour)
	tgt := &config.Target{
		Name:           "oidc",
		Type:           "oidc",
		Issuer:         baseURL,
		Login:          config.LoginForm,
		Discovery:      config.DiscoverShared,
		IDTokenTTL:     &oneHour,
		AccessTokenTTL: &oneHour,
		Clients: []config.Client{
			{ClientID: clientID, ClientSecret: clientSecret, RedirectURIs: []string{redirectURI}},
		},
		Users: []config.User{
			{Sub: "user-1", Claims: map[string]any{"email": "alice@example.com", "name": "Alice"}},
		},
	}

	handler, err := New(tgt, nil, nil)
	if err != nil {
		t.Fatalf("New() = %v", err)
	}
	srv.Config.Handler = handler
	srv.Start()
	defer srv.Close()

	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, baseURL)
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

	const (
		state = "form-state-0123456789"
		nonce = "form-nonce-abcdefghij"
	)
	authCodeURL := oauth2Config.AuthCodeURL(state, oidc.Nonce(nonce))

	getResp, err := http.Get(authCodeURL)
	if err != nil {
		t.Fatalf("GET %s: %v", authCodeURL, err)
	}
	body, _ := io.ReadAll(getResp.Body)
	getResp.Body.Close()
	hidden := extractHiddenInputs(string(body))
	if hidden["nonce"] != nonce {
		t.Fatalf("hidden nonce = %q, want %q", hidden["nonce"], nonce)
	}

	form := url.Values{
		"response_type": {hidden["response_type"]},
		"client_id":     {hidden["client_id"]},
		"redirect_uri":  {hidden["redirect_uri"]},
		"scope":         {hidden["scope"]},
		"state":         {hidden["state"]},
		"nonce":         {hidden["nonce"]},
		"username":      {"user-1"},
		"password":      {"does-not-matter"},
	}
	postResp := postAuthorizeForm(t, srv, form)
	defer postResp.Body.Close()
	if postResp.StatusCode != http.StatusFound {
		b, _ := io.ReadAll(postResp.Body)
		t.Fatalf("status = %d, want 302 (body: %s)", postResp.StatusCode, b)
	}
	loc, err := url.Parse(postResp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parsing Location: %v", err)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in the redirect")
	}
	if got := loc.Query().Get("state"); got != state {
		t.Fatalf("state = %q, want %q", got, state)
	}

	tok, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		t.Fatalf("no id_token in the token response")
	}
	idToken, err := provider.Verifier(&oidc.Config{ClientID: clientID}).Verify(ctx, rawIDToken)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if idToken.Subject != "user-1" {
		t.Fatalf("sub = %q, want user-1", idToken.Subject)
	}
	if idToken.Nonce != nonce {
		t.Fatalf("nonce = %q, want %q", idToken.Nonce, nonce)
	}
}
