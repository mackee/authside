package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mackee/authside/config"
)

// probeLog runs probeTargets against targets and returns everything it
// logged, as one string, so a test can assert on both the level and the
// wording (the wording carries the meaning here: an unreachable
// advertise.internal is a legitimate configuration, and the message has
// to say so rather than read as a verdict).
func probeLog(t *testing.T, targets []config.Target, client *http.Client) string {
	t.Helper()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	probeTargets(context.Background(), logger, targets, client)
	return buf.String()
}

// TestProbe_Reachable: a base that answers is reported at INFO, with the
// status included and no warning raised.
func TestProbe_Reachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != wellKnownPath {
			t.Errorf("probe requested %q, want %q", r.URL.Path, wellKnownPath)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	out := probeLog(t, []config.Target{{
		Name:      "oidc",
		Advertise: config.Advertise{Internal: srv.URL},
	}}, probeClient())

	if strings.Contains(out, "level=WARN") {
		t.Errorf("a reachable advertise.internal must not warn; got:\n%s", out)
	}
	if !strings.Contains(out, "answered") {
		t.Errorf("want an INFO line saying the base answered; got:\n%s", out)
	}
	if !strings.Contains(out, "200 OK") {
		t.Errorf("want the status reported; got:\n%s", out)
	}
}

// TestProbe_ReachableNon2xx: any status at all means the name resolved
// and something replied, which is the only question the probe asks. A
// 404 is expected under `discovery: off` and behind a path-rewriting
// ingress, so it must be reported, not judged.
func TestProbe_ReachableNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	out := probeLog(t, []config.Target{{
		Name:      "oidc",
		Advertise: config.Advertise{Internal: srv.URL},
	}}, probeClient())

	if strings.Contains(out, "level=WARN") {
		t.Errorf("a 404 is not a probe failure; got:\n%s", out)
	}
	if !strings.Contains(out, "404 Not Found") {
		t.Errorf("want the status reported; got:\n%s", out)
	}
}

// TestProbe_SelfSignedTLSIsReachable pins the InsecureSkipVerify
// decision: the probe measures reachability, not trust, so a dev ingress
// with a self-signed certificate must come back reachable. If this ever
// starts warning, the runtime image would also need a CA bundle it does
// not ship (see Dockerfile).
func TestProbe_SelfSignedTLSIsReachable(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	out := probeLog(t, []config.Target{{
		Name:      "oidc",
		Advertise: config.Advertise{Internal: srv.URL},
	}}, probeClient())

	if strings.Contains(out, "level=WARN") {
		t.Errorf("a self-signed dev certificate must not make the base look unreachable; got:\n%s", out)
	}
	if !strings.Contains(out, "200 OK") {
		t.Errorf("want the status reported; got:\n%s", out)
	}
}

// TestProbe_Unreachable is the case the probe exists for: a typo in the
// hostname. It must warn, name the target and the URL, and say that the
// application may still reach the base by another route -- unreachable
// from authside is not by itself a misconfiguration.
func TestProbe_Unreachable(t *testing.T) {
	// .invalid is reserved by RFC 2606 and never resolves.
	const base = "http://authsdie.invalid:5556/oidc"

	out := probeLog(t, []config.Target{{
		Name:      "oidc",
		Advertise: config.Advertise{Internal: base},
	}}, probeClient())

	if !strings.Contains(out, "level=WARN") {
		t.Errorf("an unreachable advertise.internal must warn; got:\n%s", out)
	}
	if !strings.Contains(out, "target=oidc") {
		t.Errorf("want the target named; got:\n%s", out)
	}
	if !strings.Contains(out, base+wellKnownPath) {
		t.Errorf("want the probed URL logged; got:\n%s", out)
	}
	if !strings.Contains(out, "another route") {
		t.Errorf("the warning must say the application may still reach it another way; got:\n%s", out)
	}
}

// TestProbe_NoAdvertiseInternal: with advertise unset the advertised base
// is derived per-request and there is no URL to try at startup. That is
// the common, correct configuration, so it must not warn -- but it must
// also not be silent, or an enabled probe that checked nothing would
// read as a probe that passed.
func TestProbe_NoAdvertiseInternal(t *testing.T) {
	out := probeLog(t, []config.Target{
		{Name: "oidc"},
		// advertise.browser alone is not probed: it only has to work
		// from the browser.
		{Name: "entra", Advertise: config.Advertise{Browser: "https://auth.local.test/entra"}},
	}, probeClient())

	if strings.Contains(out, "level=WARN") {
		t.Errorf("an unset advertise.internal is not a problem; got:\n%s", out)
	}
	for _, name := range []string{"target=oidc", "target=entra"} {
		if !strings.Contains(out, name) {
			t.Errorf("want a skip line for %s; got:\n%s", name, out)
		}
	}
	if !strings.Contains(out, "checked nothing") {
		t.Errorf("want the aggregate line saying nothing was checked; got:\n%s", out)
	}
}

// TestProbe_TrailingSlashTrimmed: advertise.internal is trimmed of
// trailing slashes exactly as internal/oidcop's baseURL trims it, so the
// probe hits the same URL the discovery document would advertise --
// rather than a doubled slash that a strict ingress could 404.
func TestProbe_TrailingSlashTrimmed(t *testing.T) {
	gotPath := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case gotPath <- r.URL.Path:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	probeLog(t, []config.Target{{
		Name:      "oidc",
		Advertise: config.Advertise{Internal: srv.URL + "/oidc/"},
	}}, probeClient())

	select {
	case p := <-gotPath:
		if p != "/oidc"+wellKnownPath {
			t.Errorf("probed path = %q, want %q", p, "/oidc"+wellKnownPath)
		}
	default:
		t.Fatal("the probe made no request")
	}
}

// TestProbe_ContextCanceled: a probe still in flight when the process is
// shutting down is abandoned rather than holding shutdown open for its
// own timeout. It reports the abandonment as a warning, which is honest
// -- it did not establish reachability.
func TestProbe_ContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	probeTargets(ctx, logger, []config.Target{{
		Name:      "oidc",
		Advertise: config.Advertise{Internal: "http://127.0.0.1:1/oidc"},
	}}, probeClient())

	if !strings.Contains(buf.String(), "level=WARN") {
		t.Errorf("an abandoned probe must warn rather than claim success; got:\n%s", buf.String())
	}
}

// --- the --probe flag, end to end through run() --------------------------

// safeBuffer is a bytes.Buffer that survives being written from the probe
// goroutine while the test reads it. The probe outlives run() by
// construction (it is a goroutine deliberately not waited on, so a slow
// probe cannot delay shutdown), so an unsynchronised buffer here would be
// a genuine data race, not a theoretical one.
type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// waitFor polls b until it contains want, or fails the test.
func waitFor(t *testing.T, b *safeBuffer, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(b.String(), want) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("log never contained %q; got:\n%s", want, b.String())
}

// probeWiringConfig is a config whose advertise.internal points at base.
// It points at a separate test server rather than at authside itself so
// that the test never has to know the port authside picked (listen is
// :0) -- what is under test here is the flag wiring, not the URL, which
// probeTargets' own tests cover.
func probeWiringConfig(base string) string {
	return `
listen: 127.0.0.1:0
targets:
  - name: oidc
    type: oidc
    issuer: http://127.0.0.1/oidc
    advertise:
      internal: ` + base + `
    clients:
      - client_id: local-app
        client_secret: local-secret
        redirect_uris: [http://localhost:8080/auth/callback]
    users:
      - sub: user-1
`
}

// TestRun_ProbeFlagRunsTheProbe: --probe makes the running server GET
// advertise.internal once, and the result reaches the command's own log.
func TestRun_ProbeFlagRunsTheProbe(t *testing.T) {
	hit := make(chan string, 1)
	probed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case hit <- r.URL.Path:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer probed.Close()

	t.Setenv(config.InlineConfigEnvVar, probeWiringConfig(probed.URL+"/oidc"))

	var out safeBuffer
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- run(ctx, []string{"--probe"}, io.Discard, &out) }()

	select {
	case path := <-hit:
		if path != "/oidc"+wellKnownPath {
			t.Errorf("probe requested %q, want %q", path, "/oidc"+wellKnownPath)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the probe never made a request")
	}

	waitFor(t, &out, "probe: advertise.internal answered")

	cancel()
	select {
	case err := <-errCh:
		// The probe is advisory: whatever it found, run() exits cleanly.
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return after cancel")
	}
}

// TestRun_NoProbeFlagProbesNothing: the probe is opt-in. Without the flag
// nothing is dialled, however inviting advertise.internal looks.
//
// The barrier is the "listening" line: serve() calls ready (which is
// where a probe would be launched) before it starts serving, so by the
// time that line is logged any probe would already have been launched
// against a local test server that answers immediately.
func TestRun_NoProbeFlagProbesNothing(t *testing.T) {
	var hits int32
	probed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer probed.Close()

	t.Setenv(config.InlineConfigEnvVar, probeWiringConfig(probed.URL+"/oidc"))

	var out safeBuffer
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- run(ctx, nil, io.Discard, &out) }()

	waitFor(t, &out, "listening")
	time.Sleep(100 * time.Millisecond)

	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Errorf("advertise.internal was requested %d time(s) without --probe", n)
	}
	if strings.Contains(out.String(), "probe") {
		t.Errorf("no probe output expected without the flag; got:\n%s", out.String())
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return after cancel")
	}
}
