package oidcop

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/mackee/authside/config"
	"github.com/mackee/authside/internal/httpx"
	"github.com/mackee/tanukirpc"
)

// capturingAccessLogger is a tanukirpc.AccessLogger that records the last
// request's err argument -- the same argument tanukirpc's own accesslog.go
// turns into its `error` field. Installing this in place of authside's
// disabled default lets a test assert directly on the classification
// Task 1 changes, independent of internal/reqlog (which has no "error"
// concept of its own -- see reqlog_test.go for that layer instead).
type capturingAccessLogger struct {
	mu    sync.Mutex
	seen  bool
	err   error
	count int
}

func (c *capturingAccessLogger) Log(_ context.Context, _ *slog.Logger, _ tanukirpc.WrapResponseWriter, _ *http.Request, err error, _ time.Time, _ time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seen = true
	c.err = err
	c.count++
	return nil
}

func (c *capturingAccessLogger) result() (seen bool, err error, count int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.seen, c.err, c.count
}

// newCapturingServer builds a target router exactly the way newRouter
// does (router.go), except with a capturingAccessLogger installed instead
// of the nil one production wiring uses, so the test can observe what
// tanukirpc's own error/success classification decided for each request.
func newCapturingServer(t *testing.T, cfgTarget *config.Target) (*httptest.Server, *capturingAccessLogger) {
	t.Helper()
	target, err := buildTarget(cfgTarget, nil)
	if err != nil {
		t.Fatalf("buildTarget() = %v", err)
	}

	cap := &capturingAccessLogger{}
	r := httpx.NewRouter[*Target](target, tanukirpc.WithAccessLogger[*Target](cap))
	r.Get("/authorize", authorizeHandler(target))
	switch target.login {
	case config.LoginPicker:
		r.Post("/authorize", pickerSubmitHandler(target))
	case config.LoginForm:
		r.Post("/authorize", formSubmitHandler(target))
	}
	r.Post("/token", tokenHandler(target))

	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv, cap
}

// TestAuthorize_SuccessRedirect_AutoIsNotLoggedAsAnError is the regression
// test for the bug this task fixes: a successful /authorize (login: auto)
// used to travel through tanukirpc's error path (completeLogin returned
// tanukirpc.ErrorRedirectTo(...) as an "error"), which is what made
// tanukirpc's own accesslog report `error=true` for a plain, successful
// login. It must not, for any of the three login modes.
func TestAuthorize_SuccessRedirect_AutoIsNotLoggedAsAnError(t *testing.T) {
	tgt := testTarget()
	tgt.Login = config.LoginAuto
	tgt.DefaultUser = "user-1"
	srv, cap := newCapturingServer(t, tgt)

	resp, err := noRedirectClient().Get(srv.URL + "/authorize?response_type=code&client_id=client-1&redirect_uri=https://app.example/cb&state=st-auto")
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}

	seen, cerr, _ := cap.result()
	if !seen {
		t.Fatalf("access logger never invoked")
	}
	if cerr != nil {
		t.Fatalf("a successful login: auto redirect was logged as an error: %v", cerr)
	}
}

// TestAuthorize_SuccessRedirect_PickerClickIsNotLoggedAsAnError covers the
// picker's POST /authorize click.
func TestAuthorize_SuccessRedirect_PickerClickIsNotLoggedAsAnError(t *testing.T) {
	tgt := pickerTarget()
	srv, cap := newCapturingServer(t, tgt)

	form := url.Values{
		"response_type": {"code"},
		"client_id":     {"client-1"},
		"redirect_uri":  {"https://app.example/cb"},
		"state":         {"st-picker"},
		"sub":           {"user-1"},
	}
	resp, err := noRedirectHTTPClient().PostForm(srv.URL+"/authorize", form)
	if err != nil {
		t.Fatalf("POST /authorize: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}

	seen, cerr, _ := cap.result()
	if !seen {
		t.Fatalf("access logger never invoked")
	}
	if cerr != nil {
		t.Fatalf("a successful picker click was logged as an error: %v", cerr)
	}
}

// TestAuthorize_SuccessRedirect_FormSubmitIsNotLoggedAsAnError covers
// login: form's POST /authorize submission.
func TestAuthorize_SuccessRedirect_FormSubmitIsNotLoggedAsAnError(t *testing.T) {
	tgt := formTarget(false)
	srv, cap := newCapturingServer(t, tgt)

	form := url.Values{
		"response_type": {"code"},
		"client_id":     {"client-1"},
		"redirect_uri":  {"https://app.example/cb"},
		"state":         {"st-form"},
		"username":      {"user-1"},
		"password":      {"whatever"},
	}
	resp, err := noRedirectHTTPClient().PostForm(srv.URL+"/authorize", form)
	if err != nil {
		t.Fatalf("POST /authorize: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}

	seen, cerr, _ := cap.result()
	if !seen {
		t.Fatalf("access logger never invoked")
	}
	if cerr != nil {
		t.Fatalf("a successful form submit was logged as an error: %v", cerr)
	}
}

// TestAuthorize_ErrorRedirect_IsStillLoggedAsAnError is the twin
// regression guard: an actual protocol error redirect
// (?error=...&state=...) must keep being reported as an error by
// tanukirpc's own classification -- Task 1 only changes the success path.
func TestAuthorize_ErrorRedirect_IsStillLoggedAsAnError(t *testing.T) {
	tgt := testTarget()
	tgt.Login = config.LoginAuto
	tgt.DefaultUser = "user-1"
	srv, cap := newCapturingServer(t, tgt)

	// response_type=token is unsupported: redirectError, not completeLogin.
	resp, err := noRedirectClient().Get(srv.URL + "/authorize?response_type=token&client_id=client-1&redirect_uri=https://app.example/cb&state=st-err")
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

	seen, cerr, _ := cap.result()
	if !seen {
		t.Fatalf("access logger never invoked")
	}
	if cerr == nil {
		t.Fatalf("an error redirect (?error=unsupported_response_type) was NOT logged as an error, want it to be")
	}
}
