package oidcop

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/mackee/authside/config"
)

// TestConfiguredError_Token is README "Negative testing" > errors: {token:
// invalid_grant}: POST /token on a target so configured must always fail
// with the RFC 6749 JSON error body, the code's default status, and
// application/json -- regardless of whether the request itself would
// otherwise have been valid.
func TestConfiguredError_Token(t *testing.T) {
	tgt := testTarget()
	tgt.DefaultUser = "user-1"
	tgt.Errors = map[string]config.ErrorSpec{"token": "invalid_grant"}
	srv := newTestServer(t, tgt)

	// A well-formed, otherwise-valid /token request -- no code has even
	// been minted, which is the point: this target fails here no matter
	// what the client sends.
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"whatever"},
		"redirect_uri":  {"https://app.example/cb"},
		"client_id":     {"client-1"},
		"client_secret": {"secret-1"},
	}
	resp, err := http.PostForm(srv.URL+"/token", form)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
	body, _ := io.ReadAll(resp.Body)
	var out struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decoding body: %v (body: %s)", err, body)
	}
	if out.Error != "invalid_grant" {
		t.Fatalf("error = %q, want invalid_grant (body: %s)", out.Error, body)
	}
}

// TestConfiguredError_UserinfoBareStatus is errors: {userinfo: 503}: a
// bare HTTP status with no RFC 6749 JSON shape.
func TestConfiguredError_UserinfoBareStatus(t *testing.T) {
	tgt := testTarget()
	tgt.Errors = map[string]config.ErrorSpec{"userinfo": "503"}
	srv := newTestServer(t, tgt)

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/userinfo", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer whatever")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /userinfo: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
}

// TestConfiguredError_JWKSAndDiscovery checks the two remaining
// straightforward endpoints.
func TestConfiguredError_JWKSAndDiscovery(t *testing.T) {
	t.Run("jwks", func(t *testing.T) {
		tgt := testTarget()
		tgt.Errors = map[string]config.ErrorSpec{"jwks": "server_error"}
		srv := newTestServer(t, tgt)

		resp, err := http.Get(srv.URL + "/jwks")
		if err != nil {
			t.Fatalf("GET /jwks: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", resp.StatusCode)
		}
	})

	t.Run("discovery", func(t *testing.T) {
		tgt := testTarget()
		tgt.Errors = map[string]config.ErrorSpec{"discovery": "503"}
		srv := newTestServer(t, tgt)

		resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
		if err != nil {
			t.Fatalf("GET discovery: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", resp.StatusCode)
		}
	})
}

// TestConfiguredError_AuthorizeOAuthCodeRedirects is the /authorize case
// where the configured error IS an OAuth error code: per RFC 6749
// §4.1.2.1, once client_id/redirect_uri validate, it goes back to
// redirect_uri as ?error=...&state=..., exactly like any other
// /authorize error.
func TestConfiguredError_AuthorizeOAuthCodeRedirects(t *testing.T) {
	tgt := testTarget()
	tgt.DefaultUser = "user-1"
	tgt.Errors = map[string]config.ErrorSpec{"authorize": "access_denied"}
	srv := newTestServer(t, tgt)

	resp, err := noRedirectClient().Get(srv.URL + "/authorize?response_type=code&client_id=client-1&redirect_uri=https://app.example/cb&state=cfg-st")
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parsing Location: %v", err)
	}
	if got := loc.Query().Get("error"); got != "access_denied" {
		t.Fatalf("error = %q, want access_denied", got)
	}
	if got := loc.Query().Get("state"); got != "cfg-st" {
		t.Fatalf("state = %q, want cfg-st (byte-identical passthrough)", got)
	}
}

// TestConfiguredError_AuthorizeBareStatusIsDirect is /authorize's other
// errors: shape -- a bare HTTP status has no meaningful "error=" redirect
// encoding under RFC 6749, so it is rendered directly instead, exactly
// like every other endpoint's bare-status case.
func TestConfiguredError_AuthorizeBareStatusIsDirect(t *testing.T) {
	tgt := testTarget()
	tgt.DefaultUser = "user-1"
	tgt.Errors = map[string]config.ErrorSpec{"authorize": "503"}
	srv := newTestServer(t, tgt)

	resp, err := noRedirectClient().Get(srv.URL + "/authorize?response_type=code&client_id=client-1&redirect_uri=https://app.example/cb&state=cfg-st2")
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (rendered directly, not a redirect)", resp.StatusCode)
	}
}

// TestConfiguredError_UnaffectedTargetsStillWork is the safety net for
// the errors: feature: a target with no errors: configured must behave
// exactly as it would if the feature did not exist -- the feature must
// not be able to silently break the happy path for targets that never
// opted into it.
func TestConfiguredError_UnaffectedTargetsStillWork(t *testing.T) {
	tgt := testTarget()
	tgt.DefaultUser = "user-1"
	// Deliberately no tgt.Errors at all.
	srv := newTestServer(t, tgt)

	code := codeFromAuthorize(t, srv, "client-1", "https://app.example/cb")
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://app.example/cb"},
		"client_id":     {"client-1"},
		"client_secret": {"secret-1"},
	}
	resp, err := http.PostForm(srv.URL+"/token", form)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200 (body: %s)", resp.StatusCode, body)
	}

	jwksResp, err := http.Get(srv.URL + "/jwks")
	if err != nil {
		t.Fatalf("GET /jwks: %v", err)
	}
	defer jwksResp.Body.Close()
	if jwksResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /jwks status = %d, want 200", jwksResp.StatusCode)
	}

	discResp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("GET discovery: %v", err)
	}
	defer discResp.Body.Close()
	if discResp.StatusCode != http.StatusOK {
		t.Fatalf("GET discovery status = %d, want 200", discResp.StatusCode)
	}
}
