package reqlog_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/mackee/authside/internal/reqlog"
)

func TestTimeMarshalMillisecondPrecision(t *testing.T) {
	ts := time.Date(2026, 8, 20, 12, 0, 0, 5*int(time.Millisecond), time.UTC)
	b, err := reqlog.Time(ts).MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	got := string(b)
	want := `"2026-08-20T12:00:00.005Z"`
	if got != want {
		t.Fatalf("MarshalJSON = %s, want %s", got, want)
	}
}

func TestTimeRoundTrip(t *testing.T) {
	ts := time.Date(2026, 8, 20, 12, 34, 56, 789*int(time.Millisecond), time.FixedZone("", 9*60*60))
	b, err := reqlog.Time(ts).MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}

	var got reqlog.Time
	if err := got.UnmarshalJSON(b); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}
	if !got.AsTime().Equal(ts) {
		t.Fatalf("round trip = %v, want %v", got.AsTime(), ts)
	}
}

func TestRecordFieldOrderAndOmitempty(t *testing.T) {
	rec := reqlog.Record{
		Time:      reqlog.Time(time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)),
		Target:    "oidc",
		Method:    "POST",
		Path:      "/oidc/token",
		Status:    200,
		ClientID:  "local-app",
		GrantType: "authorization_code",
		PKCE:      "S256",
		Sub:       "user-1",
	}
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := `{"time":"2026-08-20T12:00:00.000Z","target":"oidc","method":"POST","path":"/oidc/token","status":200,"client_id":"local-app","grant_type":"authorization_code","pkce":"S256","sub":"user-1"}`
	if string(b) != want {
		t.Fatalf("Marshal = %s, want %s", b, want)
	}
}

func TestRecordOmitsInapplicableFields(t *testing.T) {
	rec := reqlog.Record{
		Time:   reqlog.Time(time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)),
		Target: "oidc",
		Method: "GET",
		Path:   "/oidc/jwks",
		Status: 200,
	}
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	for _, key := range []string{"client_id", "grant_type", "pkce", "sub"} {
		if _, present := m[key]; present {
			t.Errorf("field %q present in JSON, want absent: %s", key, b)
		}
	}
	for _, key := range []string{"time", "target", "method", "path", "status"} {
		if _, present := m[key]; !present {
			t.Errorf("field %q absent from JSON, want present: %s", key, b)
		}
	}
}
