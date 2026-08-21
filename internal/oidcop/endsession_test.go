package oidcop

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/mackee/authside/config"
)

func noFollowClientForEndSession(t *testing.T) (*http.Client, *cookiejar.Jar) {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, jar
}

// TestEndSession_ClearsAuthsideSubCookie is Part 5's core requirement:
// GET /end_session must clear authside_sub on authside's own origin, so
// a subsequent login: auto/picker login does not silently reuse the old
// subject.
func TestEndSession_ClearsAuthsideSubCookie(t *testing.T) {
	tgt := testTarget()
	srv := newTestServer(t, tgt)

	client, jar := noFollowClientForEndSession(t)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parsing server URL: %v", err)
	}
	jar.SetCookies(u, []*http.Cookie{{Name: authsideSubCookie, Value: "user-1", Path: "/"}})

	// Confirm the cookie really is set before logout, so the assertion
	// below is meaningful.
	if got := jar.Cookies(u); len(got) != 1 || got[0].Value != "user-1" {
		t.Fatalf("precondition failed: authside_sub not set in the jar before logout: %+v", got)
	}

	resp, err := client.Get(srv.URL + "/end_session")
	if err != nil {
		t.Fatalf("GET /end_session: %v", err)
	}
	defer resp.Body.Close()

	setCookie := resp.Header.Get("Set-Cookie")
	if !strings.Contains(setCookie, authsideSubCookie+"=") || !strings.Contains(setCookie, "Max-Age=0") {
		t.Fatalf("Set-Cookie = %q, want it to clear %s (Max-Age=0)", setCookie, authsideSubCookie)
	}

	// The jar itself must have dropped it (http.Client applies Set-Cookie
	// responses to the jar automatically).
	if got := jar.Cookies(u); len(got) != 0 {
		t.Fatalf("jar still has cookies after logout: %+v, want none", got)
	}
}

// TestEndSession_ValidPostLogoutRedirect_WithClientID confirms the
// post_logout_redirect_uri rule: a URI registered in the identified
// client's redirect_uris is redirected to, with state passed through
// byte-identical.
func TestEndSession_ValidPostLogoutRedirect_WithClientID(t *testing.T) {
	tgt := testTarget() // client-1's redirect_uris includes https://app.example/cb
	srv := newTestServer(t, tgt)

	client, _ := noFollowClientForEndSession(t)
	u, err := url.Parse(srv.URL + "/end_session")
	if err != nil {
		t.Fatalf("parsing URL: %v", err)
	}
	q := u.Query()
	q.Set("client_id", "client-1")
	q.Set("post_logout_redirect_uri", "https://app.example/cb")
	q.Set("state", "the-exact-state-0123456789")
	u.RawQuery = q.Encode()

	resp, err := client.Get(u.String())
	if err != nil {
		t.Fatalf("GET /end_session: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 302 (body: %s)", resp.StatusCode, body)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parsing Location: %v", err)
	}
	if got := loc.Scheme + "://" + loc.Host + loc.Path; got != "https://app.example/cb" {
		t.Fatalf("redirect target = %q, want https://app.example/cb", got)
	}
	if got := loc.Query().Get("state"); got != "the-exact-state-0123456789" {
		t.Fatalf("state = %q, want byte-identical passthrough", got)
	}
}

// TestEndSession_UnregisteredRedirect_RendersSignedOutPage is the open-
// redirect guard: a post_logout_redirect_uri NOT in the identified
// client's redirect_uris must never be redirected to.
func TestEndSession_UnregisteredRedirect_RendersSignedOutPage(t *testing.T) {
	tgt := testTarget()
	srv := newTestServer(t, tgt)

	client, _ := noFollowClientForEndSession(t)
	u, err := url.Parse(srv.URL + "/end_session")
	if err != nil {
		t.Fatalf("parsing URL: %v", err)
	}
	q := u.Query()
	q.Set("client_id", "client-1")
	q.Set("post_logout_redirect_uri", "https://evil.example/steal")
	u.RawQuery = q.Encode()

	resp, err := client.Get(u.String())
	if err != nil {
		t.Fatalf("GET /end_session: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (the signed-out page, not a redirect to an unregistered URI)", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html", got)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	if !strings.Contains(string(body), "authside") || !strings.Contains(string(body), "FAKE") {
		t.Fatalf("signed-out page is not unmistakably authside-branded/fake: %s", body)
	}
}

// TestEndSession_NoParams_RendersSignedOutPage confirms the safe default
// with nothing supplied at all.
func TestEndSession_NoParams_RendersSignedOutPage(t *testing.T) {
	tgt := testTarget()
	srv := newTestServer(t, tgt)

	resp, err := http.Get(srv.URL + "/end_session")
	if err != nil {
		t.Fatalf("GET /end_session: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

// TestEndSession_ClientIdentifiedFromIDTokenHint_ValidRedirect confirms
// that when client_id is absent, the client is identified from
// id_token_hint's (unverified) aud claim instead, per RP-Initiated
// Logout's expectation that id_token_hint alone is enough to find the RP.
func TestEndSession_ClientIdentifiedFromIDTokenHint_ValidRedirect(t *testing.T) {
	tgt := testTarget()
	tgt.DefaultUser = "user-1"
	srv := newTestServer(t, tgt)

	code := codeFromAuthorize(t, srv, refreshTestClientID, refreshTestRedirectURI)
	tok := exchangeCodeRaw(t, srv.URL+"/token", code)
	if tok.IDToken == "" {
		t.Fatalf("exchange returned no id_token to use as id_token_hint")
	}

	client, _ := noFollowClientForEndSession(t)
	u, err := url.Parse(srv.URL + "/end_session")
	if err != nil {
		t.Fatalf("parsing URL: %v", err)
	}
	q := u.Query()
	q.Set("id_token_hint", tok.IDToken)
	q.Set("post_logout_redirect_uri", refreshTestRedirectURI)
	u.RawQuery = q.Encode()

	resp, err := client.Get(u.String())
	if err != nil {
		t.Fatalf("GET /end_session: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 302 (client_id inferred from id_token_hint) (body: %s)", resp.StatusCode, body)
	}
}

// TestEndSession_ConfiguredError is README "Negative testing" > errors:
// {end_session: ...}.
func TestEndSession_ConfiguredError(t *testing.T) {
	tgt := testTarget()
	tgt.Errors = map[string]config.ErrorSpec{"end_session": "server_error"}
	srv := newTestServer(t, tgt)

	resp, err := http.Get(srv.URL + "/end_session")
	if err != nil {
		t.Fatalf("GET /end_session: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (errors: {end_session: server_error})", resp.StatusCode)
	}
}
