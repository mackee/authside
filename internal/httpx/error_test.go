package httpx_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mackee/authside/internal/httpx"
	"github.com/mackee/tanukirpc"
)

// --- 6: OIDC error return -> correct status, application/json, and a body
// that parses as {"error":"invalid_grant",...}. Regression test for fact 3
// (Content-Type dropped by upstream error hooker's header-after-status bug).

func TestOIDCError_InvalidGrant(t *testing.T) {
	router := httpx.NewRouter(reg{})
	router.Get("/fail", tanukirpc.NewHandler(func(ctx tanukirpc.Context[reg], _ struct{}) (*struct{}, error) {
		return nil, httpx.InvalidGrant("the code is invalid")
	}))
	srv := httptest.NewServer(router)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/fail")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", cc)
	}

	var parsed struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("body did not parse as JSON: %v (body=%q)", err, body)
	}
	if parsed.Error != "invalid_grant" {
		t.Fatalf("error = %q, want invalid_grant", parsed.Error)
	}
	if parsed.ErrorDescription != "the code is invalid" {
		t.Fatalf("error_description = %q", parsed.ErrorDescription)
	}
}

// invalid_client -> 401 + WWW-Authenticate when the client used HTTP Basic.

func TestOIDCError_InvalidClientBasicAuth(t *testing.T) {
	router := httpx.NewRouter(reg{})
	router.Get("/fail", tanukirpc.NewHandler(func(ctx tanukirpc.Context[reg], _ struct{}) (*struct{}, error) {
		return nil, httpx.InvalidClient("unknown client", true)
	}))
	srv := httptest.NewServer(router)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/fail")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	if wa := resp.Header.Get("WWW-Authenticate"); wa != `Basic realm="authside"` {
		t.Fatalf("WWW-Authenticate = %q", wa)
	}
	var parsed struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("body did not parse as JSON: %v (body=%q)", err, body)
	}
	if parsed.Error != "invalid_client" {
		t.Fatalf("error = %q, want invalid_client", parsed.Error)
	}
}

// invalid_client without Basic auth carries no WWW-Authenticate.

func TestOIDCError_InvalidClientNoBasicAuth(t *testing.T) {
	router := httpx.NewRouter(reg{})
	router.Get("/fail", tanukirpc.NewHandler(func(ctx tanukirpc.Context[reg], _ struct{}) (*struct{}, error) {
		return nil, httpx.InvalidClient("unknown client", false)
	}))
	srv := httptest.NewServer(router)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/fail")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if wa := resp.Header.Get("WWW-Authenticate"); wa != "" {
		t.Fatalf("WWW-Authenticate = %q, want empty", wa)
	}
}

// A bare-status configured failure (the `errors: {userinfo: 503}` form)
// writes just the configured status.

func TestStatusError_BareStatus(t *testing.T) {
	router := httpx.NewRouter(reg{})
	router.Get("/fail", tanukirpc.NewHandler(func(ctx tanukirpc.Context[reg], _ struct{}) (*struct{}, error) {
		return nil, httpx.NewStatusError(http.StatusServiceUnavailable)
	}))
	srv := httptest.NewServer(router)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/fail")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
}

// An unexpected internal error becomes a 500 server_error body, without
// leaking the underlying error message.

func TestUnexpectedError_ServerError(t *testing.T) {
	router := httpx.NewRouter(reg{})
	router.Get("/fail", tanukirpc.NewHandler(func(ctx tanukirpc.Context[reg], _ struct{}) (*struct{}, error) {
		return nil, io.ErrUnexpectedEOF
	}))
	srv := httptest.NewServer(router)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/fail")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	var parsed struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("body did not parse as JSON: %v (body=%q)", err, body)
	}
	if parsed.Error != "server_error" {
		t.Fatalf("error = %q, want server_error", parsed.Error)
	}
	if bodyStr := string(body); strings.Contains(bodyStr, "unexpected EOF") {
		t.Fatalf("body leaked underlying error message: %q", bodyStr)
	}
}

// A malformed request body (a form field that fails to convert into its
// declared field's type) maps to 400 invalid_request, not the generic 500
// server_error branch above -- RFC 6749 places a malformed request at 400,
// and telling the client "our fault, retry later" (500) would be wrong
// when the truth is "your request was malformed, fix it". The underlying
// decoder error text must not leak into error_description.

func TestFormDecode_MalformedField_MapsToInvalidRequest(t *testing.T) {
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
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	var parsed struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("body did not parse as JSON: %v (body=%q)", err, body)
	}
	if parsed.Error != "invalid_request" {
		t.Fatalf("error = %q, want invalid_request", parsed.Error)
	}
	if parsed.ErrorDescription != "" {
		t.Fatalf("error_description = %q, want empty (must not leak decoder internals)", parsed.ErrorDescription)
	}
	if strings.Contains(string(body), "not-a-number") {
		t.Fatalf("body leaked the malformed value: %q", body)
	}
}

// --- 7: redirect-style error -> 302 with the exact expected Location,
// including state round-tripping and a redirect URI that already has a
// query string.

func TestRedirectError_StateAndExistingQuery(t *testing.T) {
	router := httpx.NewRouter(reg{})
	router.Get("/authorize", tanukirpc.NewHandler(func(ctx tanukirpc.Context[reg], _ struct{}) (*struct{}, error) {
		redirectErr, err := httpx.NewRedirectError(
			http.StatusFound,
			"https://client.example/cb?foo=bar",
			httpx.AccessDenied(""),
			"xyz-state",
		)
		if err != nil {
			t.Fatal(err)
		}
		return nil, redirectErr
	}))
	srv := httptest.NewServer(router)
	defer srv.Close()

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(srv.URL + "/authorize")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	loc, err := resp.Location()
	if err != nil {
		t.Fatal(err)
	}
	q := loc.Query()
	if q.Get("foo") != "bar" {
		t.Fatalf("existing query param dropped: %s", loc)
	}
	if q.Get("error") != "access_denied" {
		t.Fatalf("error param = %q, want access_denied: %s", q.Get("error"), loc)
	}
	if q.Get("state") != "xyz-state" {
		t.Fatalf("state param = %q, want xyz-state: %s", q.Get("state"), loc)
	}
	if loc.Scheme != "https" || loc.Host != "client.example" || loc.Path != "/cb" {
		t.Fatalf("unexpected redirect target: %s", loc)
	}
}

func TestLookupErrorCode(t *testing.T) {
	e, ok := httpx.LookupErrorCode("invalid_grant")
	if !ok {
		t.Fatal("expected ok=true for invalid_grant")
	}
	if e.Code != httpx.ErrInvalidGrant || e.HTTPStatus != http.StatusBadRequest {
		t.Fatalf("unexpected error: %+v", e)
	}

	if _, ok := httpx.LookupErrorCode("not_a_real_code"); ok {
		t.Fatal("expected ok=false for unknown code")
	}
}
