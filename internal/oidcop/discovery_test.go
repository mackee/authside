package oidcop

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
)

// TestDiscovery_NoAdvertise_UnreachableIssuer_EndpointsPointAtServer is
// task Part 5's acceptance test: with no advertise configured and an
// issuer whose host is not where authside is actually served (an
// Entra-shaped issuer, or one behind a TLS-terminating ingress -- README
// "Issuer, mount and advertise"), the published jwks_uri and
// token_endpoint must point at the server that is actually answering,
// not at the unreachable issuer host -- and must be genuinely fetchable
// from there, not merely well-formed.
func TestDiscovery_NoAdvertise_UnreachableIssuer_EndpointsPointAtServer(t *testing.T) {
	tgt := testTarget()
	// Deliberately NOT the server's own address (127.0.0.1:PORT): a host
	// authside itself cannot possibly be listening on. Mount is left ""
	// so this test's root-mounted httptest.Server matches the
	// request-derived base exactly (see baseURL's doc comment; the
	// mount-composition behaviour itself belongs to the root package).
	tgt.Issuer = "https://login.example.test/some/tenant/v2.0"
	tgt.Mount = ""
	tgt.DefaultUser = "user-1" // so login: auto's own gate doesn't get in the way, unrelated to this test
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
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decoding discovery document: %v", err)
	}

	// The issuer *field* is unaffected by Part 5 -- it still comes from
	// config, verbatim.
	if doc.Issuer != tgt.Issuer {
		t.Fatalf("issuer field = %q, want the configured issuer %q unchanged", doc.Issuer, tgt.Issuer)
	}

	// Every endpoint must be rooted at the server that is actually
	// serving this response (srv.URL), never at the unreachable issuer
	// host.
	for name, got := range map[string]string{
		"authorization_endpoint": doc.AuthorizationEndpoint,
		"token_endpoint":         doc.TokenEndpoint,
		"jwks_uri":               doc.JWKSURI,
		"userinfo_endpoint":      doc.UserinfoEndpoint,
	} {
		if !strings.HasPrefix(got, srv.URL) {
			t.Errorf("%s = %q, want it rooted at the server %q, not the unreachable issuer host", name, got, srv.URL)
		}
		if strings.Contains(got, "login.example.test") {
			t.Errorf("%s = %q, want it to NOT contain the unreachable issuer host", name, got)
		}
	}

	// Not just well-formed -- actually fetchable: GET jwks_uri and
	// confirm it serves a real JWKS from this same server.
	jwksResp, err := http.Get(doc.JWKSURI)
	if err != nil {
		t.Fatalf("GET jwks_uri (%s): %v", doc.JWKSURI, err)
	}
	defer jwksResp.Body.Close()
	if jwksResp.StatusCode != http.StatusOK {
		t.Fatalf("GET jwks_uri status = %d, want 200", jwksResp.StatusCode)
	}
	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.NewDecoder(jwksResp.Body).Decode(&jwks); err != nil {
		t.Fatalf("decoding jwks_uri body: %v", err)
	}
	if len(jwks.Keys) == 0 {
		t.Fatalf("jwks_uri served no keys")
	}

	// token_endpoint: confirm it is reachable at all (a POST with no
	// body/grant_type is expected to fail with a 400 invalid_request --
	// what matters here is that the request reaches this package's own
	// /token handler at all, not a connection error to a dead host).
	tokResp, err := http.Post(doc.TokenEndpoint, "application/x-www-form-urlencoded", strings.NewReader(""))
	if err != nil {
		t.Fatalf("POST token_endpoint (%s): %v", doc.TokenEndpoint, err)
	}
	defer tokResp.Body.Close()
	if tokResp.StatusCode == 0 {
		t.Fatalf("token_endpoint unreachable")
	}
}

// TestDiscovery_SimpleMode_Unchanged is the "nothing regresses" half of
// Part 5: when issuer already IS the served URL (simple mode, README
// "Client compatibility" tier 1), the new request-derived precedence
// must produce the identical result the old issuer-derived rule did.
func TestDiscovery_SimpleMode_Unchanged(t *testing.T) {
	srv := httptest.NewUnstartedServer(nil)
	baseURL := "http://" + srv.Listener.Addr().String()

	tgt := testTarget()
	tgt.Issuer = baseURL
	tgt.Mount = ""
	tgt.DefaultUser = "user-1"

	handler, err := New(tgt, nil, nil)
	if err != nil {
		t.Fatalf("New() = %v", err)
	}
	srv.Config.Handler = handler
	srv.Start()
	defer srv.Close()

	resp, err := http.Get(baseURL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("GET discovery: %v", err)
	}
	defer resp.Body.Close()

	var doc struct {
		Issuer        string `json:"issuer"`
		TokenEndpoint string `json:"token_endpoint"`
		JWKSURI       string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decoding discovery document: %v", err)
	}
	if doc.Issuer != baseURL {
		t.Fatalf("issuer = %q, want %q", doc.Issuer, baseURL)
	}
	if doc.TokenEndpoint != baseURL+"/token" {
		t.Fatalf("token_endpoint = %q, want %q (issuer-derived and request-derived must agree in simple mode)", doc.TokenEndpoint, baseURL+"/token")
	}
	if doc.JWKSURI != baseURL+"/jwks" {
		t.Fatalf("jwks_uri = %q, want %q", doc.JWKSURI, baseURL+"/jwks")
	}
}

// TestDiscovery_M7Fields is task Part 6: revocation_endpoint uses the
// internal audience base, end_session_endpoint uses the browser audience
// base (same split as token/jwks/userinfo vs. authorize), "refresh_token"
// is advertised in grant_types_supported, and
// revocation_endpoint_auth_methods_supported names both client
// authentication methods this package actually accepts there.
func TestDiscovery_M7Fields(t *testing.T) {
	tgt := testTarget()
	tgt.Mount = ""
	tgt.DefaultUser = "user-1"
	srv := newTestServer(t, tgt)

	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("GET discovery: %v", err)
	}
	defer resp.Body.Close()

	var doc struct {
		RevocationEndpoint                     string   `json:"revocation_endpoint"`
		EndSessionEndpoint                     string   `json:"end_session_endpoint"`
		GrantTypesSupported                    []string `json:"grant_types_supported"`
		RevocationEndpointAuthMethodsSupported []string `json:"revocation_endpoint_auth_methods_supported"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decoding discovery document: %v", err)
	}

	if doc.RevocationEndpoint != srv.URL+"/revocation" {
		t.Fatalf("revocation_endpoint = %q, want %q", doc.RevocationEndpoint, srv.URL+"/revocation")
	}
	if doc.EndSessionEndpoint != srv.URL+"/end_session" {
		t.Fatalf("end_session_endpoint = %q, want %q", doc.EndSessionEndpoint, srv.URL+"/end_session")
	}
	if !slices.Contains(doc.GrantTypesSupported, "refresh_token") {
		t.Fatalf("grant_types_supported = %v, want it to contain refresh_token", doc.GrantTypesSupported)
	}
	if !slices.Contains(doc.GrantTypesSupported, "authorization_code") {
		t.Fatalf("grant_types_supported = %v, want it to still contain authorization_code", doc.GrantTypesSupported)
	}
	for _, method := range []string{"client_secret_basic", "client_secret_post"} {
		if !slices.Contains(doc.RevocationEndpointAuthMethodsSupported, method) {
			t.Errorf("revocation_endpoint_auth_methods_supported = %v, want it to contain %q", doc.RevocationEndpointAuthMethodsSupported, method)
		}
	}

	// Both endpoints must actually be reachable at this server.
	revResp, err := http.PostForm(doc.RevocationEndpoint, url.Values{})
	if err != nil {
		t.Fatalf("POST revocation_endpoint: %v", err)
	}
	revResp.Body.Close()
	if revResp.StatusCode == 0 {
		t.Fatalf("revocation_endpoint unreachable")
	}

	esResp, err := http.Get(doc.EndSessionEndpoint)
	if err != nil {
		t.Fatalf("GET end_session_endpoint: %v", err)
	}
	esResp.Body.Close()
	if esResp.StatusCode != http.StatusOK {
		t.Fatalf("GET end_session_endpoint status = %d, want 200", esResp.StatusCode)
	}
}
