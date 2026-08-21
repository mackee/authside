package reqlog_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mackee/authside/internal/clock"
	"github.com/mackee/authside/internal/reqlog"
)

func TestMiddlewareOneRequestOneLine(t *testing.T) {
	var buf bytes.Buffer
	tc := clock.NewTest(time.Date(2026, 8, 20, 9, 0, 0, 0, time.UTC))
	rec := reqlog.New(&buf, tc)

	handler := reqlog.Middleware(rec, "oidc")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	srv := httptest.NewServer(handler)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/oidc/jwks")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()

	lines := splitLines(t, buf.Bytes())
	if len(lines) != 1 {
		t.Fatalf("got %d lines, want 1: %q", len(lines), buf.String())
	}

	var got reqlog.Record
	if err := json.Unmarshal(lines[0], &got); err != nil {
		t.Fatalf("Unmarshal line: %v (%s)", err, lines[0])
	}

	if !got.Time.AsTime().Equal(tc.Now()) {
		t.Errorf("Time = %v, want %v", got.Time.AsTime(), tc.Now())
	}
	if got.Target != "oidc" {
		t.Errorf("Target = %q, want oidc", got.Target)
	}
	if got.Method != http.MethodGet {
		t.Errorf("Method = %q, want GET", got.Method)
	}
	if got.Path != "/oidc/jwks" {
		t.Errorf("Path = %q, want /oidc/jwks", got.Path)
	}
	if got.Status != http.StatusOK {
		t.Errorf("Status = %d, want 200", got.Status)
	}

	// Fields that don't apply must be entirely absent, not present-and-empty.
	var m map[string]json.RawMessage
	if err := json.Unmarshal(lines[0], &m); err != nil {
		t.Fatalf("Unmarshal to map: %v", err)
	}
	for _, key := range []string{"client_id", "grant_type", "pkce", "sub"} {
		if _, present := m[key]; present {
			t.Errorf("field %q present, want absent: %s", key, lines[0])
		}
	}
}

func TestMiddlewareAttachesProtocolFieldsAndNonOKStatus(t *testing.T) {
	var buf bytes.Buffer
	tc := clock.NewTest(time.Date(2026, 8, 20, 9, 0, 0, 0, time.UTC))
	rec := reqlog.New(&buf, tc)

	handler := reqlog.Middleware(rec, "oidc")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fields := reqlog.FieldsFromContext(r.Context())
		fields.SetClientID("local-app")
		fields.SetGrantType("authorization_code")
		fields.SetPKCE("S256")
		fields.SetSub("user-1")
		w.WriteHeader(http.StatusBadRequest)
	}))

	srv := httptest.NewServer(handler)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/oidc/token", "application/x-www-form-urlencoded", nil)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	resp.Body.Close()

	lines := splitLines(t, buf.Bytes())
	if len(lines) != 1 {
		t.Fatalf("got %d lines, want 1", len(lines))
	}

	var got reqlog.Record
	if err := json.Unmarshal(lines[0], &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if got.Status != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400", got.Status)
	}
	if got.ClientID != "local-app" {
		t.Errorf("ClientID = %q, want local-app", got.ClientID)
	}
	if got.GrantType != "authorization_code" {
		t.Errorf("GrantType = %q, want authorization_code", got.GrantType)
	}
	if got.PKCE != "S256" {
		t.Errorf("PKCE = %q, want S256", got.PKCE)
	}
	if got.Sub != "user-1" {
		t.Errorf("Sub = %q, want user-1", got.Sub)
	}
}

func TestFieldsFromContextNilSafe(t *testing.T) {
	// FieldsFromContext on a plain context.Background() (no Middleware
	// involved) returns nil; every setter on it must be a no-op, not a
	// panic.
	fields := reqlog.FieldsFromContext(context.Background())
	if fields != nil {
		t.Fatalf("expected nil Fields, got %v", fields)
	}
	fields.SetClientID("x")
	fields.SetGrantType("x")
	fields.SetPKCE("x")
	fields.SetSub("x")
}

func TestMiddlewareDefaultStatusIsOKWhenWriteHeaderNeverCalled(t *testing.T) {
	var buf bytes.Buffer
	tc := clock.NewTest(time.Now())
	rec := reqlog.New(&buf, tc)

	handler := reqlog.Middleware(rec, "oidc")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))

	srv := httptest.NewServer(handler)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/oidc/userinfo")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()

	lines := splitLines(t, buf.Bytes())
	var got reqlog.Record
	if err := json.Unmarshal(lines[0], &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.Status != http.StatusOK {
		t.Errorf("Status = %d, want 200", got.Status)
	}
}

// splitLines splits raw log output into non-empty lines, and fails the
// test if any line is not valid, complete JSON — the torn/interleaved-write
// failure mode this package guards against would show up here as a line
// that fails to parse.
func splitLines(t *testing.T, raw []byte) [][]byte {
	t.Helper()
	var lines [][]byte
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := append([]byte(nil), scanner.Bytes()...)
		if len(line) == 0 {
			continue
		}
		if !json.Valid(line) {
			t.Fatalf("line is not valid JSON (torn/interleaved write?): %s", line)
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scanner: %v", err)
	}
	return lines
}
