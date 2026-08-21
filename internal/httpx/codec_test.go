package httpx_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mackee/authside/internal/httpx"
	"github.com/mackee/tanukirpc"
)

type reg struct{}

// loginPage is a response value implementing httpx.RenderHTML, standing in
// for the login picker / login form.
type loginPage struct {
	Title string
}

func (p loginPage) RenderHTML(w io.Writer) error {
	_, err := io.WriteString(w, "<html><body>"+p.Title+"</body></html>")
	return err
}

type jsonResp struct {
	Message string `json:"message"`
}

func newTestRouter(t *testing.T) *tanukirpc.Router[reg] {
	t.Helper()
	return httpx.NewRouter(reg{})
}

// --- 1 & 2: HTML dispatch, with a real browser Accept header and with none
// at all. Regression test for fact 1 (Accept-header exact match).

func TestHTML_WithBrowserAcceptHeader(t *testing.T) {
	router := newTestRouter(t)
	router.Get("/login", tanukirpc.NewHandler(func(ctx tanukirpc.Context[reg], _ struct{}) (loginPage, error) {
		return loginPage{Title: "Sign in"}, nil
	}))
	srv := httptest.NewServer(router)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/login", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Fatalf("Content-Type = %q, want text/html; charset=utf-8", ct)
	}
	if want := "<html><body>Sign in</body></html>"; string(body) != want {
		t.Fatalf("body = %q, want %q", body, want)
	}
}

func TestHTML_NoAcceptHeaderAtAll(t *testing.T) {
	router := newTestRouter(t)
	router.Get("/login", tanukirpc.NewHandler(func(ctx tanukirpc.Context[reg], _ struct{}) (loginPage, error) {
		return loginPage{Title: "Sign in"}, nil
	}))
	srv := httptest.NewServer(router)
	defer srv.Close()

	// http.Get sets no Accept header at all.
	resp, err := http.Get(srv.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Fatalf("Content-Type = %q, want text/html; charset=utf-8", ct)
	}
	if want := "<html><body>Sign in</body></html>"; string(body) != want {
		t.Fatalf("body = %q, want %q", body, want)
	}
}

// --- 3: JSON response, no Accept header.

func TestJSON_NoAcceptHeader(t *testing.T) {
	router := newTestRouter(t)
	router.Get("/hello", tanukirpc.NewHandler(func(ctx tanukirpc.Context[reg], _ struct{}) (*jsonResp, error) {
		return &jsonResp{Message: "hello"}, nil
	}))
	srv := httptest.NewServer(router)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/hello")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	if want := `{"message":"hello"}` + "\n"; string(body) != want {
		t.Fatalf("body = %q, want %q", body, want)
	}
}

// --- 4: form decoding tolerant of charset parameter, bare content type, and
// mixed case. Regression test for fact 2.

type formRequest struct {
	GrantType string `form:"grant_type"`
	Code      string `form:"code"`
}

func postForm(t *testing.T, srv *httptest.Server, path, contentType string) *http.Response {
	t.Helper()
	body := strings.NewReader("grant_type=authorization_code&code=abc123")
	req, err := http.NewRequest(http.MethodPost, srv.URL+path, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestForm_ContentTypeVariants(t *testing.T) {
	cases := []struct {
		name        string
		contentType string
	}{
		{"bare", "application/x-www-form-urlencoded"},
		{"with charset", "application/x-www-form-urlencoded; charset=UTF-8"},
		{"mixed case with whitespace", "Application/X-WWW-Form-Urlencoded ; Charset=utf-8"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got formRequest
			router := httpx.NewRouter(reg{})
			router.Post("/form", tanukirpc.NewHandler(func(ctx tanukirpc.Context[reg], req formRequest) (*jsonResp, error) {
				got = req
				return &jsonResp{Message: "ok"}, nil
			}))
			srv := httptest.NewServer(router)
			defer srv.Close()

			resp := postForm(t, srv, "/form", tc.contentType)
			defer resp.Body.Close()
			io.Copy(io.Discard, resp.Body)

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", resp.StatusCode)
			}
			if got.GrantType != "authorization_code" || got.Code != "abc123" {
				t.Fatalf("decoded request = %+v, want fully populated", got)
			}
		})
	}
}

// Unknown form keys must be ignored, not fatal: a real IdP ignores
// parameters it doesn't recognise (x/oauth2 AuthCodeOptions, scope,
// resource, provider-specific extras, ...), and authside's codec must not
// fail where a real provider would succeed. This is the regression test
// for that tolerance in isolation; TestOAuth2Exchange_ErrorParsedAsRetrieveError
// in oauth2_test.go exercises the same behavior end-to-end against a real
// client-library retry.
func TestForm_UnknownKeyIgnored(t *testing.T) {
	var got formRequest
	router := httpx.NewRouter(reg{})
	router.Post("/form", tanukirpc.NewHandler(func(ctx tanukirpc.Context[reg], req formRequest) (*jsonResp, error) {
		got = req
		return &jsonResp{Message: "ok"}, nil
	}))
	srv := httptest.NewServer(router)
	defer srv.Close()

	body := strings.NewReader("grant_type=authorization_code&code=abc123&totally_unknown_param=1")
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/form", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (unknown key must not be fatal)", resp.StatusCode)
	}
	if got.GrantType != "authorization_code" || got.Code != "abc123" {
		t.Fatalf("decoded request = %+v, want fully populated despite unknown key", got)
	}
}

// Tolerance for unknown keys must not become tolerance for malformed input:
// a value that fails to convert into a declared field's type is still a
// real decode error, mapped by ErrorHooker to 400 invalid_request (see
// hooker.go and TestFormDecode_MalformedField_MapsToInvalidRequest in
// error_test.go for the full status/body assertion).
type formIntRequest struct {
	Count int `form:"count"`
}

func TestForm_MalformedFieldIsStillAnError(t *testing.T) {
	router := httpx.NewRouter(reg{})
	router.Post("/count", tanukirpc.NewHandler(func(ctx tanukirpc.Context[reg], req formIntRequest) (*jsonResp, error) {
		return &jsonResp{Message: "ok"}, nil
	}))
	srv := httptest.NewServer(router)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/count", strings.NewReader("count=not-a-number"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode == http.StatusOK {
		t.Fatalf("status = %d, want a real error for a malformed int field, not 200", resp.StatusCode)
	}
}

// --- 5: /token-shaped handler: Cache-Control: no-store and application/json.

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}

func (r *tokenResponse) ResponseHeader(h http.Header) {
	h.Set("Cache-Control", "no-store")
}

func TestToken_CacheControlNoStore(t *testing.T) {
	router := httpx.NewRouter(reg{})
	router.Post("/token", tanukirpc.NewHandler(func(ctx tanukirpc.Context[reg], req formRequest) (*tokenResponse, error) {
		return &tokenResponse{AccessToken: "tok", TokenType: "Bearer"}, nil
	}))
	srv := httptest.NewServer(router)
	defer srv.Close()

	resp := postForm(t, srv, "/token", "application/x-www-form-urlencoded")
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", cc)
	}
	if !strings.Contains(string(body), `"access_token":"tok"`) {
		t.Fatalf("body = %q, missing access_token", body)
	}
}
