package oidcop

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/mackee/authside/config"
)

// pickerTarget returns a config.Target for login: picker with two
// configured users -- one carrying email+name, one carrying only email --
// mirroring README's Quick start users, so tests here double as evidence
// that shape actually serves (task Part 4/definition of done). Mount is
// left empty so the httptest.Server this is served from (root-mounted,
// with no authside.go-level mount composition in play here -- that
// belongs to the root package this task does not own) matches the
// request-derived discovery base exactly: see discovery.go's baseURL.
func pickerTarget() *config.Target {
	tgt := testTarget()
	tgt.Login = config.LoginPicker
	tgt.Mount = ""
	tgt.Users = []config.User{
		{Sub: "user-1", Claims: map[string]any{
			"email": "alice@example.com",
			"name":  "Alice",
		}},
		{Sub: "user-2", Claims: map[string]any{
			"email": "bob@example.net",
		}},
	}
	return tgt
}

var hiddenInputRE = regexp.MustCompile(`name="([a-z_]+)" value="([^"]*)"`)

// extractHiddenInputs parses every `name="..." value="..."` hidden input
// out of an HTML page rendered by this package's picker/form templates.
// No HTML parser is available in this module's dependency set, and the
// templates' hidden-input markup is simple and fixed enough that a plain
// regexp is an honest, low-risk way to read it back in a test.
func extractHiddenInputs(html string) map[string]string {
	out := map[string]string{}
	for _, m := range hiddenInputRE.FindAllStringSubmatch(html, -1) {
		out[m[1]] = m[2]
	}
	return out
}

func TestPicker_RendersHTMLWithBrowserAcceptHeader(t *testing.T) {
	srv := newTestServer(t, pickerTarget())

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/authorize?response_type=code&client_id=client-1&redirect_uri=https://app.example/cb&state=st", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	// A real browser's Accept header: exact-matches neither "*/*" nor
	// "application/json" -- the tanukirpc pitfall this package's dispatch
	// codec exists to route around (see internal/httpx/codec.go).
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) == 0 {
		t.Fatalf("body is empty (the tanukirpc Accept-header pitfall: a 200 with no body)")
	}
	if !strings.Contains(string(body), "authside") {
		t.Fatalf("body does not mention authside; want the fake-IdP banner. body: %s", body)
	}
}

func TestPicker_RendersHTMLWithNoAcceptHeader(t *testing.T) {
	srv := newTestServer(t, pickerTarget())

	// http.NewRequest/http.DefaultClient set no Accept header at all --
	// the broader case of the same tanukirpc pitfall (an absent header,
	// not just a mismatched one).
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/authorize?response_type=code&client_id=client-1&redirect_uri=https://app.example/cb&state=st", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	if got := req.Header.Get("Accept"); got != "" {
		t.Fatalf("test setup: request already has an Accept header %q", got)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) == 0 {
		t.Fatalf("body is empty with no Accept header (the tanukirpc pitfall this package's codec must route around)")
	}
}

func TestPicker_ListsEveryConfiguredUser(t *testing.T) {
	srv := newTestServer(t, pickerTarget())

	resp, err := http.Get(srv.URL + "/authorize?response_type=code&client_id=client-1&redirect_uri=https://app.example/cb&state=st")
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	html := string(body)

	for _, want := range []string{"user-1", "user-2", "alice@example.com", "Alice", "bob@example.net"} {
		if !strings.Contains(html, want) {
			t.Errorf("picker page missing %q; body: %s", want, html)
		}
	}
}

func TestPicker_EscapesUserClaims(t *testing.T) {
	tgt := pickerTarget()
	tgt.Users = []config.User{
		{Sub: "xss-user", Claims: map[string]any{
			"name": `<script>alert(1)</script>`,
		}},
	}
	srv := newTestServer(t, tgt)

	resp, err := http.Get(srv.URL + "/authorize?response_type=code&client_id=client-1&redirect_uri=https://app.example/cb&state=st")
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	html := string(body)

	if strings.Contains(html, "<script>alert(1)</script>") {
		t.Fatalf("XSS: literal <script> tag present unescaped in picker page: %s", html)
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Fatalf("expected the claim to be HTML-escaped (&lt;script&gt;...); body: %s", html)
	}
}

func TestPicker_ClickCompletesFlowWithCodeAndUntouchedState(t *testing.T) {
	srv := newTestServer(t, pickerTarget())
	const (
		clientID    = "client-1"
		redirectURI = "https://app.example/cb"
		state       = "some-random-state-value-0123456789"
	)

	getURL := srv.URL + "/authorize?response_type=code&client_id=" + clientID +
		"&redirect_uri=" + url.QueryEscape(redirectURI) + "&state=" + state
	resp, err := http.Get(getURL)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	hidden := extractHiddenInputs(string(body))

	if hidden["state"] != state {
		t.Fatalf("hidden state = %q, want %q", hidden["state"], state)
	}
	if !strings.Contains(string(body), `name="sub" value="user-1"`) {
		t.Fatalf("no clickable button for user-1 found in picker page: %s", body)
	}

	form := url.Values{
		"response_type": {hidden["response_type"]},
		"client_id":     {hidden["client_id"]},
		"redirect_uri":  {hidden["redirect_uri"]},
		"scope":         {hidden["scope"]},
		"state":         {hidden["state"]},
		"nonce":         {hidden["nonce"]},
		"sub":           {"user-1"},
	}
	postResp, err := noRedirectHTTPClient().PostForm(srv.URL+"/authorize", form)
	if err != nil {
		t.Fatalf("POST /authorize (click): %v", err)
	}
	defer postResp.Body.Close()

	if postResp.StatusCode != http.StatusFound {
		b, _ := io.ReadAll(postResp.Body)
		t.Fatalf("status = %d, want 302 (body: %s)", postResp.StatusCode, b)
	}
	loc, err := url.Parse(postResp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parsing Location: %v", err)
	}
	if loc.Query().Get("code") == "" {
		t.Fatalf("no code in the redirect")
	}
	if got := loc.Query().Get("state"); got != state {
		t.Fatalf("state = %q, want byte-identical %q", got, state)
	}
}

// TestPicker_QuickStartConfig_FullFlow is this package's version of the
// README quick-start end-to-end check (task Part 4/Tests): a real
// oidc.NewProvider + oauth2.Config drives GET /authorize (login: picker),
// reads the rendered hidden fields back out of the page -- proving every
// authorization parameter, nonce and code_challenge included, survived
// the round trip untouched -- clicks user-1 via POST /authorize, follows
// the 302, exchanges the code (with the matching PKCE verifier) and
// verifies the resulting ID token, including that nonce came back
// unchanged. The verbatim README quick-start config additionally starting
// and serving via `authside` itself is checked separately, by actually
// running the binary (task Part 4) -- this test uses the same target
// shape through oidcop.New directly, which is what this package owns.
func TestPicker_QuickStartConfig_FullFlow(t *testing.T) {
	const (
		clientID     = "local-app"
		clientSecret = "local-secret"
		redirectURI  = "http://localhost:8080/auth/callback"
	)

	srv := httptest.NewUnstartedServer(nil)
	baseURL := "http://" + srv.Listener.Addr().String()

	// oidcop.New does not fill in TTL defaults itself -- that is
	// config.ApplyDefaults's job, upstream of this package, which a
	// hand-built config.Target here bypasses -- so an explicit,
	// comfortably-in-the-future TTL is required or the tokens this test
	// mints would expire (TTL 0) before Verify ever runs.
	oneHour := config.Duration(time.Hour)

	tgt := &config.Target{
		Name:           "oidc",
		Type:           "oidc",
		Issuer:         baseURL, // simple mode: issuer IS the served URL
		Mount:          "",
		Login:          config.LoginPicker,
		Discovery:      config.DiscoverShared,
		IDTokenTTL:     &oneHour,
		AccessTokenTTL: &oneHour,
		Clients: []config.Client{
			{ClientID: clientID, ClientSecret: clientSecret, RedirectURIs: []string{redirectURI}},
		},
		Users: []config.User{
			{Sub: "user-1", Claims: map[string]any{
				"email":          "alice@example.com",
				"email_verified": true,
				"name":           "Alice",
				"hd":             "example.com",
			}},
			{Sub: "user-2", Claims: map[string]any{
				"email": "bob@example.net",
				"name":  "Bob",
			}},
		},
	}

	handler, err := New(tgt, nil, nil)
	if err != nil {
		t.Fatalf("New() = %v, want nil (README quick-start's login: picker must build)", err)
	}
	srv.Config.Handler = handler
	srv.Start()
	defer srv.Close()

	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, baseURL)
	if err != nil {
		t.Fatalf("oidc.NewProvider: %v", err)
	}

	verifier := oauth2.GenerateVerifier()
	oauth2Config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURI,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID},
	}

	const (
		state = "the-exact-state-value-0123456789"
		nonce = "the-exact-nonce-value-abcdefghij"
	)
	authCodeURL := oauth2Config.AuthCodeURL(state,
		oidc.Nonce(nonce),
		oauth2.S256ChallengeOption(verifier),
	)

	resp, err := http.Get(authCodeURL)
	if err != nil {
		t.Fatalf("GET %s: %v", authCodeURL, err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /authorize status = %d, want 200 (picker page). body: %s", resp.StatusCode, body)
	}

	hidden := extractHiddenInputs(string(body))
	// The whole point of this test: nonce and code_challenge must survive
	// the round trip through the rendered page's hidden fields
	// byte-identical, not just "some value".
	if hidden["nonce"] != nonce {
		t.Fatalf("hidden nonce = %q, want %q -- nonce did not survive the picker page", hidden["nonce"], nonce)
	}
	if hidden["state"] != state {
		t.Fatalf("hidden state = %q, want %q", hidden["state"], state)
	}
	if hidden["code_challenge"] == "" {
		t.Fatalf("hidden code_challenge is empty -- code_challenge did not survive the picker page")
	}
	if hidden["code_challenge_method"] != "S256" {
		t.Fatalf("hidden code_challenge_method = %q, want S256", hidden["code_challenge_method"])
	}

	form := url.Values{
		"response_type":         {hidden["response_type"]},
		"client_id":             {hidden["client_id"]},
		"redirect_uri":          {hidden["redirect_uri"]},
		"scope":                 {hidden["scope"]},
		"state":                 {hidden["state"]},
		"nonce":                 {hidden["nonce"]},
		"code_challenge":        {hidden["code_challenge"]},
		"code_challenge_method": {hidden["code_challenge_method"]},
		"sub":                   {"user-1"},
	}
	clickResp, err := noRedirectHTTPClient().PostForm(baseURL+"/authorize", form)
	if err != nil {
		t.Fatalf("POST /authorize (click user-1): %v", err)
	}
	defer clickResp.Body.Close()
	if clickResp.StatusCode != http.StatusFound {
		b, _ := io.ReadAll(clickResp.Body)
		t.Fatalf("status = %d, want 302 (body: %s)", clickResp.StatusCode, b)
	}
	loc, err := url.Parse(clickResp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parsing Location: %v", err)
	}
	if got := loc.Query().Get("state"); got != state {
		t.Fatalf("state = %q, want byte-identical %q", got, state)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in the /authorize redirect")
	}

	tok, err := oauth2Config.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		t.Fatalf("no id_token in the token response")
	}

	idTokenVerifier := provider.Verifier(&oidc.Config{ClientID: clientID})
	idToken, err := idTokenVerifier.Verify(ctx, rawIDToken)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if idToken.Subject != "user-1" {
		t.Fatalf("sub = %q, want user-1", idToken.Subject)
	}
	if idToken.Nonce != nonce {
		t.Fatalf("id_token nonce = %q, want %q -- nonce did not survive the click", idToken.Nonce, nonce)
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
}

// TestPicker_UnknownSubOnPost_RedirectsAccessDenied covers the defensive
// path in pickerSubmitHandler: a POST naming a sub the picker never
// listed (a tampered body, since the rendered page only ever contains
// buttons for configured users) fails closed with a redirect back to the
// client carrying access_denied, exactly like login: auto's equivalent
// failure -- never a 500, never a silently-issued token.
func TestPicker_UnknownSubOnPost_RedirectsAccessDenied(t *testing.T) {
	srv := newTestServer(t, pickerTarget())

	form := url.Values{
		"response_type": {"code"},
		"client_id":     {"client-1"},
		"redirect_uri":  {"https://app.example/cb"},
		"state":         {"st"},
		"sub":           {"no-such-user"},
	}
	resp, err := noRedirectHTTPClient().PostForm(srv.URL+"/authorize", form)
	if err != nil {
		t.Fatalf("POST /authorize: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 302 (body: %s)", resp.StatusCode, b)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parsing Location: %v", err)
	}
	if got := loc.Query().Get("error"); got != "access_denied" {
		t.Fatalf("error = %q, want access_denied", got)
	}
}

// TestPicker_LoginModeHasNoGETRedirect is a small sanity check that
// login: picker really does render a page rather than redirecting like
// auto does -- the two modes must not be confusable at the wire level.
func TestPicker_LoginModeHasNoGETRedirect(t *testing.T) {
	srv := newTestServer(t, pickerTarget())

	resp, err := noRedirectHTTPClient().Get(srv.URL + "/authorize?response_type=code&client_id=client-1&redirect_uri=https://app.example/cb&state=st")
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusFound {
		t.Fatalf("login: picker redirected on GET /authorize (Location: %s); want a rendered page", resp.Header.Get("Location"))
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200 (body: %s)", resp.StatusCode, b)
	}
}
