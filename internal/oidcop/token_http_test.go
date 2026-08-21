package oidcop

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// codeFromAuthorize drives GET /authorize on srv (login: auto via
// default_user, already configured on the target passed to
// newTestServer) and returns the code from the 302 redirect to
// redirectURI.
func codeFromAuthorize(t *testing.T, srv *httptest.Server, clientID, redirectURI string) string {
	t.Helper()

	u, err := url.Parse(srv.URL + "/authorize")
	if err != nil {
		t.Fatalf("parsing authorize URL: %v", err)
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("state", "st")
	u.RawQuery = q.Encode()

	resp, err := noRedirectHTTPClient().Get(u.String())
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET /authorize status = %d, want 302 (body: %s)", resp.StatusCode, body)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parsing Location: %v", err)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in the /authorize redirect (Location: %s)", loc)
	}
	return code
}

func noRedirectHTTPClient() *http.Client {
	return &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

// TestToken_FailedBasicAuthDoesNotConsumeCode_ThenClientSecretPostSucceeds
// is the endpoint-level twin of TestCodeStore_NotConsumedOnFailedCheck,
// exercising the real HTTP path end to end: authenticateClient
// (token.go) runs *before* the code store is ever touched, so a POST
// /token with a wrong client_secret_basic must fail with 401 (and the
// RFC 6749 WWW-Authenticate challenge) and leave the code exchangeable; a
// second POST with the *correct* credentials sent as client_secret_post
// (no Authorization header, client_id/client_secret in the form body --
// the "must accept both" invariant) must then succeed against the very
// same code, exactly as x/oauth2's own basic-then-post retry behaviour
// requires.
func TestToken_FailedBasicAuthDoesNotConsumeCode_ThenClientSecretPostSucceeds(t *testing.T) {
	const (
		clientID     = "client-1"
		clientSecret = "secret-1"
		redirectURI  = "https://app.example/cb"
	)

	tgt := testTarget()
	tgt.DefaultUser = "user-1"
	srv := newTestServer(t, tgt)

	code := codeFromAuthorize(t, srv, clientID, redirectURI)

	// Attempt 1: client_secret_basic with the WRONG secret. Must fail
	// with 401 and a WWW-Authenticate challenge, and must NOT consume
	// the code.
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectURI},
	}
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(clientID+":wrong-secret")))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /token (wrong basic secret): %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (body: %s)", resp.StatusCode, body)
	}
	if resp.Header.Get("WWW-Authenticate") == "" {
		t.Fatalf("WWW-Authenticate header missing on a rejected client_secret_basic attempt")
	}

	// Attempt 2: client_secret_post with the CORRECT credentials, no
	// Authorization header, reusing the SAME code. Must succeed.
	form2 := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	req2, err := http.NewRequest(http.MethodPost, srv.URL+"/token", strings.NewReader(form2.Encode()))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("POST /token (client_secret_post retry): %v", err)
	}
	defer resp2.Body.Close()
	body2, _ := io.ReadAll(resp2.Body)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", resp2.StatusCode, body2)
	}
	if got := resp2.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want \"no-store\"", got)
	}
	if got := resp2.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}

	var tokResp struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	if err := json.Unmarshal(body2, &tokResp); err != nil {
		t.Fatalf("decoding token response: %v (body: %s)", err, body2)
	}
	if tokResp.AccessToken == "" || tokResp.IDToken == "" {
		t.Fatalf("token response missing access_token/id_token: %s", body2)
	}

	// The code is now spent: a third attempt, even with fully correct
	// credentials, must fail with invalid_grant.
	req3, err := http.NewRequest(http.MethodPost, srv.URL+"/token", strings.NewReader(form2.Encode()))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp3, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatalf("POST /token (replay): %v", err)
	}
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusBadRequest {
		body3, _ := io.ReadAll(resp3.Body)
		t.Fatalf("replay status = %d, want 400 invalid_grant (body: %s)", resp3.StatusCode, body3)
	}
}
