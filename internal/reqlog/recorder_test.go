package reqlog_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/mackee/authside/internal/clock"
	"github.com/mackee/authside/internal/reqlog"
)

func emit(t *testing.T, rec *reqlog.Recorder, handlerTarget, path string) {
	t.Helper()
	h := reqlog.Middleware(rec, handlerTarget)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, path, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
}

func TestRecordsReturnsACopy(t *testing.T) {
	var buf bytes.Buffer
	tc := clock.NewTest(time.Now())
	rec := reqlog.New(&buf, tc)

	emit(t, rec, "oidc", "/oidc/jwks")

	got := rec.Records()
	if len(got) != 1 {
		t.Fatalf("len(Records()) = %d, want 1", len(got))
	}
	got[0].Path = "/mutated"
	got[0].Target = "mutated"

	again := rec.Records()
	if len(again) != 1 {
		t.Fatalf("len(Records()) = %d, want 1", len(again))
	}
	if again[0].Path != "/oidc/jwks" {
		t.Errorf("second Records() call observed the mutation: Path = %q", again[0].Path)
	}
	if again[0].Target != "oidc" {
		t.Errorf("second Records() call observed the mutation: Target = %q", again[0].Target)
	}
}

func TestFindFiltersByTargetAndPath(t *testing.T) {
	var buf bytes.Buffer
	tc := clock.NewTest(time.Now())
	rec := reqlog.New(&buf, tc)

	emit(t, rec, "oidc", "/oidc/token")
	emit(t, rec, "oidc", "/oidc/jwks")
	emit(t, rec, "entra", "/entra/token")

	tokenCalls := rec.Find(reqlog.Filter{Path: "/oidc/token"})
	if len(tokenCalls) != 1 || tokenCalls[0].Target != "oidc" {
		t.Fatalf("Find(Path=/oidc/token) = %+v, want one oidc record", tokenCalls)
	}

	oidcCalls := rec.Find(reqlog.Filter{Target: "oidc"})
	if len(oidcCalls) != 2 {
		t.Fatalf("Find(Target=oidc) = %d records, want 2", len(oidcCalls))
	}

	all := rec.Find(reqlog.Filter{})
	if len(all) != 3 {
		t.Fatalf("Find(zero Filter) = %d records, want 3", len(all))
	}
}

func TestRetentionBoundEvictsOldest(t *testing.T) {
	var buf bytes.Buffer
	tc := clock.NewTest(time.Now())
	rec := reqlog.New(&buf, tc, reqlog.WithRetention(3))

	for i := 0; i < 5; i++ {
		emit(t, rec, "oidc", pathN(i))
	}

	got := rec.Records()
	if len(got) != 3 {
		t.Fatalf("len(Records()) = %d, want 3", len(got))
	}
	want := []string{pathN(2), pathN(3), pathN(4)}
	for i, w := range want {
		if got[i].Path != w {
			t.Errorf("Records()[%d].Path = %q, want %q", i, got[i].Path, w)
		}
	}
}

func TestRetentionZeroDisablesInMemoryRetention(t *testing.T) {
	var buf bytes.Buffer
	tc := clock.NewTest(time.Now())
	rec := reqlog.New(&buf, tc, reqlog.WithRetention(0))

	emit(t, rec, "oidc", "/oidc/jwks")

	if got := rec.Records(); len(got) != 0 {
		t.Fatalf("len(Records()) = %d, want 0 with retention disabled", len(got))
	}
	// The JSON line is still written even with retention off.
	if buf.Len() == 0 {
		t.Fatalf("expected a log line to still be written with retention disabled")
	}
}

func TestDefaultRetentionKeepsUpToDefaultRetentionRecords(t *testing.T) {
	var buf bytes.Buffer
	tc := clock.NewTest(time.Now())
	rec := reqlog.New(&buf, tc) // no WithRetention: exercises DefaultRetention

	const extra = 10
	total := reqlog.DefaultRetention + extra
	for i := 0; i < total; i++ {
		emit(t, rec, "oidc", pathN(i))
	}

	got := rec.Records()
	if len(got) != reqlog.DefaultRetention {
		t.Fatalf("len(Records()) = %d, want DefaultRetention (%d)", len(got), reqlog.DefaultRetention)
	}
	// The oldest `extra` records should have been evicted; the retained
	// window should start at index `extra` and run to `total-1`.
	if got[0].Path != pathN(extra) {
		t.Errorf("Records()[0].Path = %q, want %q (oldest should have been evicted)", got[0].Path, pathN(extra))
	}
	last := got[len(got)-1]
	if last.Path != pathN(total-1) {
		t.Errorf("Records()[last].Path = %q, want %q", last.Path, pathN(total-1))
	}
}

func pathN(i int) string {
	return "/oidc/path-" + strconv.Itoa(i)
}
