package oidcop

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/mackee/authside/config"
)

// mountedTestServer serves target under a non-root mount ("/oidc"), the
// way the README quick-start config (and authside.go, which this task
// does not own) actually does: an outer http.ServeMux strips the mount
// prefix before handing the request to oidcop.New's own router, which
// registers every route relative to its own root (target.go's New doc
// comment). Every other test in this package instead uses Mount: "" and
// serves at root, which sidesteps this composition entirely -- this is
// the one test that puts it back, so a browser-fidelity assumption (the
// picker/form page's <form> submitting correctly under a real mount)
// gets checked at all.
func mountedTestServer(t *testing.T, tgt *config.Target) *httptest.Server {
	t.Helper()
	tgt.Mount = "/oidc"
	h, err := New(tgt, nil, nil)
	if err != nil {
		t.Fatalf("New() = %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/oidc/", http.StripPrefix("/oidc", h))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// resolveFormSubmitURL mimics what a real browser does when it submits a
// <form> with no action attribute: per the HTML spec, it POSTs to the
// page's own URL. pageURL is the URL the GET was fetched from.
func resolveFormSubmitURL(t *testing.T, pageURL string) string {
	t.Helper()
	u, err := url.Parse(pageURL)
	if err != nil {
		t.Fatalf("parsing page URL %q: %v", pageURL, err)
	}
	return u.String()
}

// TestPicker_SubmitsCorrectlyUnderANonRootMount is the browser-fidelity
// regression test for the picker/form templates' deliberately-omitted
// <form action="..."> (see authorize_picker.go's pickerTemplateSrc
// comment): with a hard-coded action="/authorize", this exact scenario
// -- a target served under a non-root mount, exactly like the README
// quick-start's mount: /oidc -- would have the browser POST to the origin
// root instead of ".../oidc/authorize", missing the mount and 404ing. A
// regexp-based hidden-field check (as used elsewhere in this package's
// tests) cannot catch this, because it never resolves the <form>'s
// submission target the way a browser does; this test does.
func TestPicker_SubmitsCorrectlyUnderANonRootMount(t *testing.T) {
	tgt := pickerTarget()
	srv := mountedTestServer(t, tgt)

	pageURL := srv.URL + "/oidc/authorize?response_type=code&client_id=client-1&redirect_uri=https://app.example/cb&state=mount-st"
	resp, err := http.Get(pageURL)
	if err != nil {
		t.Fatalf("GET %s: %v", pageURL, err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET status = %d, want 200 (body: %s)", resp.StatusCode, body)
	}
	hidden := extractHiddenInputs(string(body))

	submitURL := resolveFormSubmitURL(t, pageURL)
	if submitURL != pageURL {
		// Sanity: with no action attribute, a browser resolves the
		// submission target to the page's own URL (query string and
		// all) -- confirming the premise this test exercises.
		t.Fatalf("resolveFormSubmitURL = %q, want the page's own URL %q", submitURL, pageURL)
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
	postResp, err := noRedirectHTTPClient().PostForm(submitURL, form)
	if err != nil {
		t.Fatalf("POST %s: %v", submitURL, err)
	}
	defer postResp.Body.Close()

	if postResp.StatusCode != http.StatusFound {
		b, _ := io.ReadAll(postResp.Body)
		t.Fatalf("POST %s status = %d, want 302 (a hard-coded action=\"/authorize\" would 404 here instead, missing the /oidc mount). body: %s", submitURL, postResp.StatusCode, b)
	}
	loc, err := url.Parse(postResp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parsing Location: %v", err)
	}
	if loc.Query().Get("code") == "" {
		t.Fatalf("no code in the redirect")
	}
	if got := loc.Query().Get("state"); got != "mount-st" {
		t.Fatalf("state = %q, want mount-st", got)
	}
}

// TestForm_SubmitsCorrectlyUnderANonRootMount is login: form's twin of
// TestPicker_SubmitsCorrectlyUnderANonRootMount.
func TestForm_SubmitsCorrectlyUnderANonRootMount(t *testing.T) {
	tgt := formTarget(false)
	srv := mountedTestServer(t, tgt)

	pageURL := srv.URL + "/oidc/authorize?response_type=code&client_id=client-1&redirect_uri=https://app.example/cb&state=mount-st2"
	resp, err := http.Get(pageURL)
	if err != nil {
		t.Fatalf("GET %s: %v", pageURL, err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	hidden := extractHiddenInputs(string(body))

	submitURL := resolveFormSubmitURL(t, pageURL)
	form := url.Values{
		"response_type": {hidden["response_type"]},
		"client_id":     {hidden["client_id"]},
		"redirect_uri":  {hidden["redirect_uri"]},
		"scope":         {hidden["scope"]},
		"state":         {hidden["state"]},
		"nonce":         {hidden["nonce"]},
		"username":      {"user-1"},
		"password":      {"whatever"},
	}
	postResp, err := noRedirectHTTPClient().PostForm(submitURL, form)
	if err != nil {
		t.Fatalf("POST %s: %v", submitURL, err)
	}
	defer postResp.Body.Close()

	if postResp.StatusCode != http.StatusFound {
		b, _ := io.ReadAll(postResp.Body)
		t.Fatalf("POST %s status = %d, want 302 (a hard-coded action=\"/authorize\" would 404 here instead, missing the /oidc mount). body: %s", submitURL, postResp.StatusCode, b)
	}
	loc, err := url.Parse(postResp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parsing Location: %v", err)
	}
	if got := loc.Query().Get("state"); got != "mount-st2" {
		t.Fatalf("state = %q, want mount-st2", got)
	}
}
