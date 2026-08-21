package oidcop

import (
	"encoding/json"
	"net/http"
	"slices"
	"testing"

	"github.com/mackee/authside/config"
)

// TestDiscovery_IsByteStableAcrossFetches pins down that fetching the
// same target's discovery document twice returns identical bytes.
//
// It did not, before: claimsSupported built claims_supported by ranging
// over Go maps -- the protocol-claim set, then every user's claims -- so
// the array came back in a different order on essentially every request.
// Nothing about a target changes between two GETs, so nothing about the
// document it serves should either, and a client that caches or hashes
// discovery would otherwise see churn that means nothing.
//
// Several users with several claims each are configured deliberately:
// with the single-user testTarget() the map iteration has too little to
// permute for a regression to reliably show up.
func TestDiscovery_IsByteStableAcrossFetches(t *testing.T) {
	tgt := testTarget()
	tgt.DefaultUser = "user-1"
	tgt.Users = []config.User{
		{Sub: "user-1", Claims: map[string]any{
			"email": "alice@example.com", "name": "Alice", "groups": "admin",
		}},
		{Sub: "user-2", Claims: map[string]any{
			"email": "bob@example.net", "tid": "t-2", "department": "eng",
		}},
		{Sub: "user-3", Claims: map[string]any{
			"email": "carol@example.org", "roles": "viewer", "locale": "ja-JP",
		}},
	}

	srv := newTestServer(t, tgt)

	fetch := func() []byte {
		t.Helper()
		resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
		if err != nil {
			t.Fatalf("GET discovery: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("discovery status = %d, want 200", resp.StatusCode)
		}
		var doc map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
			t.Fatalf("decode discovery: %v", err)
		}
		// Re-encode through encoding/json (which sorts map keys) rather
		// than comparing the raw body: this compares the *values*,
		// including every array's order, without depending on the field
		// order the handler's struct happens to marshal in.
		canonical, err := json.Marshal(doc)
		if err != nil {
			t.Fatalf("re-encode discovery: %v", err)
		}
		return canonical
	}

	// Ten fetches, not two: a map with nine distinct user claims can
	// coincidentally repeat an order once, but not ten times running.
	first := fetch()
	for i := 2; i <= 10; i++ {
		if got := fetch(); string(got) != string(first) {
			t.Fatalf("discovery document differs between fetch 1 and fetch %d\n first = %s\n got   = %s", i, first, got)
		}
	}

	// And the user-derived tail is sorted, so the order is a documented
	// one rather than merely whatever happened to be stable today.
	var doc struct {
		ClaimsSupported []string `json:"claims_supported"`
	}
	if err := json.Unmarshal(first, &doc); err != nil {
		t.Fatalf("unmarshal claims_supported: %v", err)
	}
	got := doc.ClaimsSupported
	if len(got) < len(protocolClaims) {
		t.Fatalf("claims_supported = %v, want at least the %d protocol claims", got, len(protocolClaims))
	}
	if !slices.Equal(got[:len(protocolClaims)], protocolClaims) {
		t.Errorf("claims_supported starts with %v, want the protocol claims %v", got[:len(protocolClaims)], protocolClaims)
	}
	tail := got[len(protocolClaims):]
	if !slices.IsSorted(tail) {
		t.Errorf("user-derived claims %v are not sorted", tail)
	}
	// The union of all three users' claim names, sorted. "email" is
	// here rather than among the protocol claims because it is not one:
	// it is a claim these users happen to be configured with.
	want := []string{"department", "email", "groups", "locale", "name", "roles", "tid"}
	if !slices.Equal(tail, want) {
		t.Errorf("user-derived claims = %v, want %v", tail, want)
	}
}
