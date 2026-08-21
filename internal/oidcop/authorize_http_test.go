package oidcop

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/mackee/authside/config"
)

func newTestServer(t *testing.T, tgt *config.Target) *httptest.Server {
	t.Helper()
	h, err := New(tgt, nil, nil)
	if err != nil {
		t.Fatalf("New() = %v", err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

// noRedirectClient never follows redirects, so the test can inspect the
// 302's Location header directly.
func noRedirectClient() *http.Client {
	return &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

func TestAuthorize_UnknownClientIDIsRenderedDirectlyNotRedirected(t *testing.T) {
	srv := newTestServer(t, testTarget())

	resp, err := noRedirectClient().Get(srv.URL + "/authorize?response_type=code&client_id=no-such-client&redirect_uri=https://app.example/cb&state=xyz")
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer resp.Body.Close()

	// RFC 6749 §4.1.2.1: an invalid client_id must NOT be redirected.
	if resp.StatusCode == http.StatusFound {
		t.Fatalf("status = %d (redirected to %q), want a direct, non-redirect error", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAuthorize_UnregisteredRedirectURIIsRenderedDirectlyNotRedirected(t *testing.T) {
	srv := newTestServer(t, testTarget())

	resp, err := noRedirectClient().Get(srv.URL + "/authorize?response_type=code&client_id=client-1&redirect_uri=https://evil.example/cb&state=xyz")
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusFound {
		t.Fatalf("status = %d (redirected to %q), want a direct, non-redirect error", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAuthorize_UnsupportedResponseTypeRedirectsWithError(t *testing.T) {
	tgt := testTarget()
	tgt.DefaultUser = "user-1"
	srv := newTestServer(t, tgt)

	resp, err := noRedirectClient().Get(srv.URL + "/authorize?response_type=token&client_id=client-1&redirect_uri=https://app.example/cb&state=xyz")
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
	if got := loc.Query().Get("error"); got != "unsupported_response_type" {
		t.Fatalf("error = %q, want unsupported_response_type", got)
	}
	if got := loc.Query().Get("state"); got != "xyz" {
		t.Fatalf("state = %q, want xyz (byte-identical passthrough)", got)
	}
}

func TestAuthorize_RequirePKCERejectsMissingChallenge(t *testing.T) {
	tgt := testTarget()
	tgt.DefaultUser = "user-1"
	tgt.Clients[0].RequirePKCE = true
	srv := newTestServer(t, tgt)

	resp, err := noRedirectClient().Get(srv.URL + "/authorize?response_type=code&client_id=client-1&redirect_uri=https://app.example/cb&state=xyz")
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
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
	if got := loc.Query().Get("error"); got != "invalid_request" {
		t.Fatalf("error = %q, want invalid_request", got)
	}
}

func TestAuthorize_NoSubjectIsLoginRequiredRedirect(t *testing.T) {
	// No authside_sub cookie sent, and no default_user configured.
	srv := newTestServer(t, testTarget())

	resp, err := noRedirectClient().Get(srv.URL + "/authorize?response_type=code&client_id=client-1&redirect_uri=https://app.example/cb&state=xyz")
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
	if got := loc.Query().Get("error"); got != "login_required" {
		t.Fatalf("error = %q, want login_required", got)
	}
}

func TestAuthorize_SuccessRedirectsWithCodeAndUntouchedState(t *testing.T) {
	tgt := testTarget()
	tgt.DefaultUser = "user-1"
	srv := newTestServer(t, tgt)

	const state = "some-random-state-value-123"
	resp, err := noRedirectClient().Get(srv.URL + "/authorize?response_type=code&client_id=client-1&redirect_uri=https://app.example/cb&state=" + state)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
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
	if got := loc.Query().Get("code"); got == "" {
		t.Fatalf("code missing from redirect")
	}
	if got := loc.Query().Get("state"); got != state {
		t.Fatalf("state = %q, want %q (byte-identical passthrough)", got, state)
	}
	if resp.Header.Get("X-Authside") == "" {
		t.Fatalf("X-Authside marker header missing")
	}
}
