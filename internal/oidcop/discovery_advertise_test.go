package oidcop

// This file closes a hole left open by the existing discovery tests
// (discovery_test.go): TestDiscovery_NoAdvertise_UnreachableIssuer_...
// never sets advertise at all, and TestDiscovery_M7Fields (via
// testTarget/newTestServer) never sets advertise.browser and
// advertise.internal to two DIFFERENT values -- so nothing in the
// existing suite would notice if discoveryHandler's audience selection
// were built backwards. In particular: swap `browserBase` and
// `internalBase` at the call sites inside discoveryHandler
// (internal/oidcop/discovery.go) and every existing test in this package
// still passes. TestDiscovery_AdvertiseSplit_EndpointsUseCorrectAudience
// below is written specifically to go red the moment that swap happens.

import (
	"encoding/json"
	"net/http"
	"testing"
)

// TestDiscovery_AdvertiseSplit_EndpointsUseCorrectAudience configures
// advertise.browser, advertise.internal and issuer as three distinct,
// unmistakable values, then asserts every discovery field is built from
// the correct one of the three. This pins down two separate things at
// once:
//
//  1. authorization_endpoint and end_session_endpoint must be built from
//     advertise.browser; token_endpoint, jwks_uri, userinfo_endpoint and
//     revocation_endpoint must be built from advertise.internal. Getting
//     this backwards is exactly the "swap browser and internal in
//     discovery.go" regression this test exists to catch (see
//     internal/oidcop/discovery.go's baseURL/advertiseFor).
//  2. issuer is never consulted to derive ANY endpoint (baseURL's own
//     doc comment: "issuer itself is never consulted here"). Because
//     issuer here is a third, distinct value that shares no substring
//     with either advertise base, any endpoint accidentally built from
//     issuer instead of the correct advertise base would be caught by
//     the same table below.
func TestDiscovery_AdvertiseSplit_EndpointsUseCorrectAudience(t *testing.T) {
	const (
		browserBase  = "https://browser-side.invalid/oidc-browser-leg"
		internalBase = "https://internal-side.invalid/oidc-internal-leg"
		issuer       = "https://issuer-only.invalid/oidc-issuer-leg"
	)

	tgt := testTarget()
	tgt.Issuer = issuer
	tgt.Advertise.Browser = browserBase
	tgt.Advertise.Internal = internalBase
	tgt.DefaultUser = "user-1" // keeps login: auto's own gate out of this test's way

	srv := newTestServer(t, tgt)

	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("GET discovery: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery status = %d, want 200", resp.StatusCode)
	}

	var doc struct {
		Issuer                string `json:"issuer"`
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
		JWKSURI               string `json:"jwks_uri"`
		UserinfoEndpoint      string `json:"userinfo_endpoint"`
		RevocationEndpoint    string `json:"revocation_endpoint"`
		EndSessionEndpoint    string `json:"end_session_endpoint"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decoding discovery document: %v", err)
	}

	// issuer comes from config, verbatim -- never from either advertise
	// base.
	if doc.Issuer != issuer {
		t.Fatalf("issuer = %q, want the configured issuer %q unchanged", doc.Issuer, issuer)
	}

	tests := []struct {
		field      string
		got        string
		wantBase   string
		wantSuffix string
		audience   string // for the failure message only
	}{
		{"authorization_endpoint", doc.AuthorizationEndpoint, browserBase, "/authorize", "advertise.browser"},
		{"end_session_endpoint", doc.EndSessionEndpoint, browserBase, "/end_session", "advertise.browser"},
		{"token_endpoint", doc.TokenEndpoint, internalBase, "/token", "advertise.internal"},
		{"jwks_uri", doc.JWKSURI, internalBase, "/jwks", "advertise.internal"},
		{"userinfo_endpoint", doc.UserinfoEndpoint, internalBase, "/userinfo", "advertise.internal"},
		{"revocation_endpoint", doc.RevocationEndpoint, internalBase, "/revocation", "advertise.internal"},
	}

	for _, tt := range tests {
		want := tt.wantBase + tt.wantSuffix
		if tt.got != want {
			t.Errorf("%s = %q, want %q (must be built from %s, not from the other audience's base or from issuer)", tt.field, tt.got, want, tt.audience)
		}
	}
}
