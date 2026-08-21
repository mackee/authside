package oidcop

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/mackee/authside/config"
	"github.com/mackee/authside/internal/clock"
	"github.com/mackee/authside/internal/reqlog"
	"github.com/mackee/tanukirpc"
)

// newRecordingServer builds tgt's handler with recorder wired in via
// New's recorder parameter (Task 2), and mounts it exactly the way
// authside.go actually does -- tanukirpc.Router.Mount, i.e. go-chi's
// Mount -- rather than the http.StripPrefix approximation
// authorize_mount_test.go's mountedTestServer uses. That distinction
// matters here specifically: StripPrefix rewrites req.URL.Path, which
// would make a path assertion pass (or fail) for the wrong reason; a real
// chi Mount does not touch req.URL.Path at all (see router.go's newRouter
// doc comment), which is the actual behaviour this test has to pin down.
func newRecordingServer(t *testing.T, tgt *config.Target, recorder *reqlog.Recorder) *httptest.Server {
	t.Helper()
	handler, err := New(tgt, nil, recorder)
	if err != nil {
		t.Fatalf("New() = %v", err)
	}
	root := tanukirpc.NewRouter(struct{}{})
	if tgt.Mount == "" {
		// login: auto etc. tests elsewhere in this package use Mount ""
		// to serve at root; Mount("", h) would collide with chi's own
		// root route registration, so serve unmounted in that case.
		srv := httptest.NewServer(handler)
		t.Cleanup(srv.Close)
		return srv
	}
	root.Mount(tgt.Mount, handler)
	srv := httptest.NewServer(root)
	t.Cleanup(srv.Close)
	return srv
}

// TestRequestLog_FullPathUnderMount is the regression test for the path a
// mounted target logs: reqlog.Middleware must log the full
// externally-visible path ("/oidc/authorize"), not the mount-relative
// path the target's own router sees for routing purposes ("/authorize"),
// for a target mounted the way authside.go actually mounts one.
func TestRequestLog_FullPathUnderMount(t *testing.T) {
	tgt := testTarget()
	tgt.Mount = "/oidc"
	tgt.Login = config.LoginAuto
	tgt.DefaultUser = "user-1"

	var buf bytes.Buffer
	recorder := reqlog.New(&buf, clock.NewTest(time.Unix(0, 0)))
	srv := newRecordingServer(t, tgt, recorder)

	resp, err := noRedirectClient().Get(srv.URL + "/oidc/authorize?response_type=code&client_id=client-1&redirect_uri=https://app.example/cb&state=st")
	if err != nil {
		t.Fatalf("GET /oidc/authorize: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}

	recs := recorder.Find(reqlog.Filter{Target: "oidc"})
	if len(recs) != 1 {
		t.Fatalf("got %d matching records, want 1 (all records: %+v)", len(recs), recorder.Records())
	}
	rec := recs[0]
	if rec.Path != "/oidc/authorize" {
		t.Fatalf("Path = %q, want %q (the full externally-visible path, not the mount-relative \"/authorize\")", rec.Path, "/oidc/authorize")
	}
	if rec.Method != http.MethodGet {
		t.Fatalf("Method = %q, want GET", rec.Method)
	}
	if rec.Status != http.StatusFound {
		t.Fatalf("Status = %d, want 302", rec.Status)
	}
	if rec.ClientID != "client-1" {
		t.Fatalf("ClientID = %q, want client-1", rec.ClientID)
	}
	if rec.Sub != "user-1" {
		t.Fatalf("Sub = %q, want user-1 (set by completeLogin on a successful auto redirect)", rec.Sub)
	}

	// The JSON actually written to the recorder's writer must carry the
	// same full path -- this is what ends up on stdout in the real
	// binary, and what the README's example line shows.
	if !bytes.Contains(buf.Bytes(), []byte(`"path":"/oidc/authorize"`)) {
		t.Fatalf("stdout JSON does not contain the full path: %s", buf.String())
	}
}

// TestRequestLog_TokenRecordsProtocolFields exercises a full
// authorize->token flow and checks that /token's record carries
// client_id, grant_type and sub, and that pkce is present (carrying the
// challenge method used) only when the exchanged code actually had one.
func TestRequestLog_TokenRecordsProtocolFields(t *testing.T) {
	t.Run("without PKCE, pkce is absent", func(t *testing.T) {
		tgt := testTarget()
		tgt.Mount = ""
		tgt.DefaultUser = "user-1"

		var buf bytes.Buffer
		recorder := reqlog.New(&buf, clock.NewTest(time.Unix(0, 0)))
		srv := newRecordingServer(t, tgt, recorder)

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
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}

		recs := recorder.Find(reqlog.Filter{Method: http.MethodPost, Path: "/token"})
		if len(recs) != 1 {
			t.Fatalf("got %d /token records, want 1: %+v", len(recs), recorder.Records())
		}
		rec := recs[0]
		if rec.ClientID != "client-1" {
			t.Fatalf("ClientID = %q, want client-1", rec.ClientID)
		}
		if rec.GrantType != "authorization_code" {
			t.Fatalf("GrantType = %q, want authorization_code", rec.GrantType)
		}
		if rec.Sub != "user-1" {
			t.Fatalf("Sub = %q, want user-1", rec.Sub)
		}
		if rec.PKCE != "" {
			t.Fatalf("PKCE = %q, want absent (empty): this exchange used no code_challenge", rec.PKCE)
		}
		if bytes.Contains(buf.Bytes(), []byte(`"pkce"`)) {
			t.Fatalf("stdout JSON contains a \"pkce\" key even though no PKCE was used: %s", buf.String())
		}
	})

	t.Run("with S256 PKCE, pkce carries the challenge method", func(t *testing.T) {
		tgt := testTarget()
		tgt.Mount = ""
		tgt.DefaultUser = "user-1"

		var buf bytes.Buffer
		recorder := reqlog.New(&buf, clock.NewTest(time.Unix(0, 0)))
		srv := newRecordingServer(t, tgt, recorder)

		const verifier = "a-fixed-code-verifier-that-is-long-enough-1234567890"
		sum := sha256.Sum256([]byte(verifier))
		challenge := base64.RawURLEncoding.EncodeToString(sum[:])

		u, err := url.Parse(srv.URL + "/authorize")
		if err != nil {
			t.Fatalf("parsing authorize URL: %v", err)
		}
		q := u.Query()
		q.Set("response_type", "code")
		q.Set("client_id", "client-1")
		q.Set("redirect_uri", "https://app.example/cb")
		q.Set("state", "st")
		q.Set("code_challenge", challenge)
		q.Set("code_challenge_method", "S256")
		u.RawQuery = q.Encode()

		resp, err := noRedirectClient().Get(u.String())
		if err != nil {
			t.Fatalf("GET /authorize: %v", err)
		}
		loc, err := url.Parse(resp.Header.Get("Location"))
		resp.Body.Close()
		if err != nil {
			t.Fatalf("parsing Location: %v", err)
		}
		code := loc.Query().Get("code")
		if code == "" {
			t.Fatalf("no code in the /authorize redirect")
		}

		form := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"redirect_uri":  {"https://app.example/cb"},
			"client_id":     {"client-1"},
			"client_secret": {"secret-1"},
			"code_verifier": {verifier},
		}
		tokResp, err := http.PostForm(srv.URL+"/token", form)
		if err != nil {
			t.Fatalf("POST /token: %v", err)
		}
		defer tokResp.Body.Close()
		if tokResp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", tokResp.StatusCode)
		}

		recs := recorder.Find(reqlog.Filter{Method: http.MethodPost, Path: "/token"})
		if len(recs) != 1 {
			t.Fatalf("got %d /token records, want 1: %+v", len(recs), recorder.Records())
		}
		if got := recs[0].PKCE; got != "S256" {
			t.Fatalf("PKCE = %q, want S256", got)
		}
	})
}

// TestRequestLog_OneRecorderSharedAcrossTargets is the wiring-level proof
// for README "Request log"'s "single stream with a target field, not one
// per target": one *reqlog.Recorder, passed to two different New() calls
// (as authside.New does for every configured target), must accumulate
// both targets' records together, distinguished only by their Target
// field -- not two independent logs.
func TestRequestLog_OneRecorderSharedAcrossTargets(t *testing.T) {
	var buf bytes.Buffer
	recorder := reqlog.New(&buf, clock.NewTest(time.Unix(0, 0)))

	tgtA := testTarget()
	tgtA.Name = "oidc-a"
	tgtA.Mount = ""
	tgtA.DefaultUser = "user-1"
	srvA := newRecordingServer(t, tgtA, recorder)

	tgtB := testTarget()
	tgtB.Name = "oidc-b"
	tgtB.Mount = ""
	tgtB.DefaultUser = "user-1"
	srvB := newRecordingServer(t, tgtB, recorder)

	for _, srv := range []*httptest.Server{srvA, srvB} {
		resp, err := http.Get(srv.URL + "/jwks")
		if err != nil {
			t.Fatalf("GET /jwks: %v", err)
		}
		resp.Body.Close()
	}

	recsA := recorder.Find(reqlog.Filter{Target: "oidc-a"})
	recsB := recorder.Find(reqlog.Filter{Target: "oidc-b"})
	if len(recsA) != 1 {
		t.Fatalf("target oidc-a: got %d records, want 1: %+v", len(recsA), recorder.Records())
	}
	if len(recsB) != 1 {
		t.Fatalf("target oidc-b: got %d records, want 1: %+v", len(recsB), recorder.Records())
	}
	if all := recorder.Records(); len(all) != 2 {
		t.Fatalf("Records() = %d entries, want 2 (one shared recorder, two targets)", len(all))
	}
}
