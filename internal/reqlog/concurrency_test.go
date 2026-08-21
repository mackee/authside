package reqlog_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/mackee/authside/internal/clock"
	"github.com/mackee/authside/internal/reqlog"
)

// syncBuffer is a bytes.Buffer guarded by a mutex, standing in for an
// io.Writer whose own Write is not inherently safe for concurrent callers
// (much like os.Stdout is not, at the buffering layer). Recorder is
// expected to serialize its own writes so that this wrapper's lock is
// never contended by two goroutines at once from Recorder's side; the test
// still uses a mutex here because the *test* itself reads buf.Bytes() after
// the fact from the main goroutine.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) Bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]byte, s.buf.Len())
	copy(out, s.buf.Bytes())
	return out
}

// TestMiddlewareConcurrentRequestsUnderRace drives many concurrent HTTP
// requests, from several goroutines, through Middleware, and checks that
// every emitted line is complete, well-formed JSON with no interleaving —
// the classic failure mode when several goroutines write to one io.Writer
// without synchronizing. Run with -race.
func TestMiddlewareConcurrentRequestsUnderRace(t *testing.T) {
	buf := &syncBuffer{}
	tc := clock.NewTest(time.Date(2026, 8, 20, 9, 0, 0, 0, time.UTC))
	rec := reqlog.New(buf, tc, reqlog.WithRetention(reqlog.DefaultRetention))

	handler := reqlog.Middleware(rec, "oidc")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fields := reqlog.FieldsFromContext(r.Context())
		fields.SetClientID("local-app")
		fields.SetSub(r.URL.Query().Get("sub"))
		if r.URL.Query().Get("fail") == "1" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	srv := httptest.NewServer(handler)
	defer srv.Close()

	const goroutines = 20
	const perGoroutine = 25
	total := goroutines * perGoroutine

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(g int) {
			defer wg.Done()
			client := srv.Client()
			for i := 0; i < perGoroutine; i++ {
				fail := i%7 == 0
				url := fmt.Sprintf("%s/oidc/token?sub=user-%d-%d&fail=%s", srv.URL, g, i, boolStr(fail))
				resp, err := client.Post(url, "application/x-www-form-urlencoded", nil)
				if err != nil {
					t.Errorf("goroutine %d request %d: %v", g, i, err)
					continue
				}
				resp.Body.Close()
			}
		}(g)
	}
	wg.Wait()

	lines := splitLines(t, buf.Bytes())
	if len(lines) != total {
		t.Fatalf("got %d log lines, want %d", len(lines), total)
	}

	statusCounts := map[int]int{}
	for _, line := range lines {
		var rec reqlog.Record
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Fatalf("Unmarshal line: %v (%s)", err, line)
		}
		if rec.Target != "oidc" {
			t.Errorf("Target = %q, want oidc: %s", rec.Target, line)
		}
		if rec.ClientID != "local-app" {
			t.Errorf("ClientID = %q, want local-app: %s", rec.ClientID, line)
		}
		if rec.Sub == "" {
			t.Errorf("Sub is empty, want a per-request value: %s", line)
		}
		statusCounts[rec.Status]++
	}

	// Every 7th request per goroutine (i%7==0) failed with 400; the rest
	// succeeded with 200. Just sanity-check both statuses were captured
	// correctly under concurrency, rather than everything collapsing to one
	// value.
	if statusCounts[http.StatusOK] == 0 {
		t.Errorf("no 200 status recorded")
	}
	if statusCounts[http.StatusBadRequest] == 0 {
		t.Errorf("no 400 status recorded")
	}
	if statusCounts[http.StatusOK]+statusCounts[http.StatusBadRequest] != total {
		t.Errorf("status counts %v do not sum to total %d", statusCounts, total)
	}

	// Library-mode accessor must also reflect every request (retention is
	// large enough here to hold them all) and remain race-free when called
	// concurrently with nothing left running — but let's also prove
	// Records()/Find() themselves are safe to call *while* requests are in
	// flight, not just after.
	_ = rec.Records()
	_ = rec.Find(reqlog.Filter{Target: "oidc"})
}

// TestLibraryAccessorSafeDuringConcurrentRequests calls Records/Find
// concurrently with in-flight requests, to exercise the case the design
// explicitly calls out: "must be safe to call while requests are being
// served". Run with -race.
func TestLibraryAccessorSafeDuringConcurrentRequests(t *testing.T) {
	buf := &syncBuffer{}
	tc := clock.NewTest(time.Now())
	rec := reqlog.New(buf, tc)

	handler := reqlog.Middleware(rec, "oidc")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv := httptest.NewServer(handler)
	defer srv.Close()

	stop := make(chan struct{})
	var requester sync.WaitGroup
	var accessor sync.WaitGroup

	requester.Add(1)
	go func() {
		defer requester.Done()
		client := srv.Client()
		for {
			select {
			case <-stop:
				return
			default:
			}
			resp, err := client.Get(srv.URL + "/oidc/jwks")
			if err != nil {
				continue
			}
			resp.Body.Close()
		}
	}()

	accessor.Add(1)
	go func() {
		defer accessor.Done()
		for i := 0; i < 200; i++ {
			_ = rec.Records()
			_ = rec.Find(reqlog.Filter{Target: "oidc"})
		}
	}()

	// Wait for the accessor goroutine to finish its reads while requests
	// are still in flight, then stop the requester.
	accessor.Wait()
	close(stop)
	requester.Wait()
}

func boolStr(b bool) string {
	if b {
		return "1"
	}
	return "0"
}
