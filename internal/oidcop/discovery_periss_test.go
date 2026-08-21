package oidcop

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mackee/authside/config"
)

// perIssuerTarget is a two-tenant target: the issuer templates on each
// user's tid claim, so the rendered issuers -- and therefore the discovery
// routes -- differ per user.
func perIssuerTarget() *config.Target {
	d := config.Duration(0)
	return &config.Target{
		Name:      "entra",
		Type:      "oidc",
		Issuer:    "http://authside.example/entra/${claims.tid}",
		Mount:     "/entra",
		Login:     config.LoginAuto,
		Discovery: config.DiscoverPerIssuer,
		Clients: []config.Client{
			{ClientID: "client-1", ClientSecret: "secret-1", RedirectURIs: []string{"https://app.example/cb"}},
		},
		Users: []config.User{
			{Sub: "user-a", Claims: map[string]any{"tid": "tenant-a"}},
			{Sub: "user-b", Claims: map[string]any{"tid": "tenant-b"}},
		},
		IDTokenTTL:     &d,
		AccessTokenTTL: &d,
		NBFSkew:        &d,
	}
}

// getDiscovery GETs path and returns the status, the raw body, and the
// decoded document (zero value when the status is not 200).
func getDiscovery(t *testing.T, srv *httptest.Server, path string) (int, []byte, discoveryResponse) {
	t.Helper()
	resp, err := http.Get(srv.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.Header.Get(authsideMarkerHeader) == "" {
		t.Errorf("GET %s: response is missing the %s marker header", path, authsideMarkerHeader)
	}
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, body, discoveryResponse{}
	}
	var doc discoveryResponse
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("decoding %s: %v (body: %s)", path, err, body)
	}
	return resp.StatusCode, body, doc
}

// TestPerIssuer_OneDocumentPerRenderedIssuer is the feature itself: each
// tenant's own URL serves a document whose issuer field is that same URL,
// which is the equality vanilla discovery checks and the only reason
// oidc.NewProvider can work against a per-tenant issuer without
// InsecureIssuerURLContext.
func TestPerIssuer_OneDocumentPerRenderedIssuer(t *testing.T) {
	srv := newTestServer(t, perIssuerTarget())

	for _, tc := range []struct{ path, wantIssuer string }{
		{"/tenant-a/.well-known/openid-configuration", "http://authside.example/entra/tenant-a"},
		{"/tenant-b/.well-known/openid-configuration", "http://authside.example/entra/tenant-b"},
	} {
		status, _, doc := getDiscovery(t, srv, tc.path)
		if status != http.StatusOK {
			t.Fatalf("GET %s status = %d, want 200", tc.path, status)
		}
		if doc.Issuer != tc.wantIssuer {
			t.Fatalf("GET %s issuer = %q, want %q", tc.path, doc.Issuer, tc.wantIssuer)
		}
	}
}

// TestPerIssuer_EndpointsStayAtTheTargetRoot: the tenant lives in the
// issuer, not in the endpoint URLs. /authorize and /token are shared by
// every tenant -- which tenant a login belongs to is decided by who logs
// in -- so a per-tenant document must not advertise per-tenant endpoints.
func TestPerIssuer_EndpointsStayAtTheTargetRoot(t *testing.T) {
	srv := newTestServer(t, perIssuerTarget())

	_, _, doc := getDiscovery(t, srv, "/tenant-a/.well-known/openid-configuration")

	for name, got := range map[string]string{
		"authorization_endpoint": doc.AuthorizationEndpoint,
		"token_endpoint":         doc.TokenEndpoint,
		"jwks_uri":               doc.JWKSURI,
		"userinfo_endpoint":      doc.UserinfoEndpoint,
	} {
		if strings.Contains(got, "tenant-a") {
			t.Errorf("%s = %q, want no tenant segment: endpoints are shared across tenants", name, got)
		}
		if !strings.HasSuffix(got, "/authorize") && !strings.HasSuffix(got, "/token") &&
			!strings.HasSuffix(got, "/jwks") && !strings.HasSuffix(got, "/userinfo") {
			t.Errorf("%s = %q, want a target-root endpoint path", name, got)
		}
	}
}

// TestPerIssuer_NoDocumentAtTheTargetRootOrForAnUnknownTenant: per_issuer
// serves documents for the enumerated issuers and nothing else. The root
// has no single issuer it could name, and an unconfigured tenant is just
// an unmatched path -- both 404 through the ordinary router, marker header
// included (asserted by getDiscovery).
func TestPerIssuer_NoDocumentAtTheTargetRootOrForAnUnknownTenant(t *testing.T) {
	srv := newTestServer(t, perIssuerTarget())

	for _, path := range []string{
		"/.well-known/openid-configuration",
		"/tenant-zzz/.well-known/openid-configuration",
	} {
		if status, _, _ := getDiscovery(t, srv, path); status != http.StatusNotFound {
			t.Fatalf("GET %s status = %d, want 404", path, status)
		}
	}
}

// TestPerIssuer_DocumentIsByteStable is the per-issuer twin of
// discovery_stable_test.go's check on the shared document: two GETs of an
// unchanged target must be byte-identical, so a client that caches or
// hashes the document sees no churn.
func TestPerIssuer_DocumentIsByteStable(t *testing.T) {
	srv := newTestServer(t, perIssuerTarget())
	const path = "/tenant-a/.well-known/openid-configuration"

	_, first, _ := getDiscovery(t, srv, path)
	for i := 0; i < 5; i++ {
		_, again, _ := getDiscovery(t, srv, path)
		if !bytes.Equal(first, again) {
			t.Fatalf("GET %s differs between requests:\n first: %s\nlater: %s", path, first, again)
		}
	}
}

// TestPerIssuer_ConfiguredErrorStillApplies: `errors: {discovery: ...}`
// is checked before anything else on every endpoint, and a per-issuer
// document is not an exception.
func TestPerIssuer_ConfiguredErrorStillApplies(t *testing.T) {
	tgt := perIssuerTarget()
	tgt.Errors = map[string]config.ErrorSpec{"discovery": config.ErrorSpec("503")}
	srv := newTestServer(t, tgt)

	status, body, _ := getDiscovery(t, srv, "/tenant-a/.well-known/openid-configuration")
	if status != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (body: %s)", status, body)
	}
}

// TestPerIssuer_EnumeratesOverClientsToo: a claim can itself template on
// ${client_id}, so the same user renders a different issuer per client.
// Enumerating over users alone would miss one of these documents.
func TestPerIssuer_EnumeratesOverClientsToo(t *testing.T) {
	tgt := perIssuerTarget()
	tgt.Clients = append(tgt.Clients, config.Client{
		ClientID: "client-2", ClientSecret: "secret-2", RedirectURIs: []string{"https://app.example/cb"},
	})
	tgt.Users = []config.User{{Sub: "user-a", Claims: map[string]any{"tid": "tenant-of-${client_id}"}}}
	srv := newTestServer(t, tgt)

	for _, clientID := range []string{"client-1", "client-2"} {
		path := "/tenant-of-" + clientID + "/.well-known/openid-configuration"
		status, body, doc := getDiscovery(t, srv, path)
		if status != http.StatusOK {
			t.Fatalf("GET %s status = %d, want 200 (body: %s)", path, status, body)
		}
		if want := "http://authside.example/entra/tenant-of-" + clientID; doc.Issuer != want {
			t.Fatalf("GET %s issuer = %q, want %q", path, doc.Issuer, want)
		}
	}
}

// TestPerIssuer_IdenticalIssuersAreOneDocumentNotACollision: two users in
// the same tenant render the same issuer, which is one document -- not a
// route conflict.
func TestPerIssuer_IdenticalIssuersAreOneDocumentNotACollision(t *testing.T) {
	tgt := perIssuerTarget()
	tgt.Users = []config.User{
		{Sub: "user-a", Claims: map[string]any{"tid": "tenant-a"}},
		{Sub: "user-b", Claims: map[string]any{"tid": "tenant-a"}},
	}
	srv := newTestServer(t, tgt)

	status, _, doc := getDiscovery(t, srv, "/tenant-a/.well-known/openid-configuration")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200: two users in one tenant is one document", status)
	}
	if doc.Issuer != "http://authside.example/entra/tenant-a" {
		t.Fatalf("issuer = %q", doc.Issuer)
	}
}

// TestPerIssuer_RefusedAtConstruction covers every config per_issuer
// cannot serve. Each has to fail at authside.New -- serving something
// almost-right here means a client fails at discovery time with no clue
// which config line caused it.
func TestPerIssuer_RefusedAtConstruction(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate  func(*config.Target)
		wantMsg string
	}{
		"issuer path outside the mount": {
			mutate: func(tgt *config.Target) {
				tgt.Issuer = "http://authside.example/elsewhere/${claims.tid}"
			},
			wantMsg: "not under this target's mount",
		},
		"two issuers colliding on one route": {
			mutate: func(tgt *config.Target) {
				// Same path, different host: two distinct issuers that
				// both want the route "/t/.well-known/...".
				tgt.Issuer = "http://${claims.host}/entra/t"
				tgt.Users = []config.User{
					{Sub: "user-a", Claims: map[string]any{"host": "a.example"}},
					{Sub: "user-b", Claims: map[string]any{"host": "b.example"}},
				}
			},
			wantMsg: "one path cannot serve two issuers",
		},
		"tenant value containing a route metacharacter": {
			mutate: func(tgt *config.Target) {
				tgt.Users = []config.User{{Sub: "user-a", Claims: map[string]any{"tid": "t{1}"}}}
			},
			wantMsg: "not usable in a route",
		},
		"no users to enumerate from": {
			mutate: func(tgt *config.Target) {
				tgt.Issuer = "http://authside.example/entra"
				tgt.Users = nil
			},
			wantMsg: "at least one user and one client",
		},
	} {
		t.Run(name, func(t *testing.T) {
			tgt := perIssuerTarget()
			tc.mutate(tgt)
			_, err := New(tgt, nil, nil)
			if err == nil {
				t.Fatalf("New() = nil, want an error mentioning %q", tc.wantMsg)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("error = %q, want it to mention %q", err.Error(), tc.wantMsg)
			}
		})
	}
}

// TestPerIssuer_IssuerEqualToTheMountServesTheRoot: an issuer with no
// tenant segment below the mount is not an error -- its document simply
// sits at the target root, exactly where discovery: shared would have put
// it. This is the degenerate case, and it should fall out of the same
// rule rather than needing one of its own.
func TestPerIssuer_IssuerEqualToTheMountServesTheRoot(t *testing.T) {
	tgt := perIssuerTarget()
	tgt.Issuer = "http://authside.example/entra"
	srv := newTestServer(t, tgt)

	status, _, doc := getDiscovery(t, srv, "/.well-known/openid-configuration")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if doc.Issuer != "http://authside.example/entra" {
		t.Fatalf("issuer = %q, want the un-templated issuer verbatim", doc.Issuer)
	}
}

func TestPathBelowMount(t *testing.T) {
	for _, tc := range []struct {
		mount, issuerPath string
		wantSuffix        string
		wantOK            bool
	}{
		{"/entra", "/entra/tenant-a", "/tenant-a", true},
		{"/entra", "/entra", "", true},
		{"/entra", "/entra/", "", true},
		{"/entra/", "/entra", "", true},
		{"/entra", "/entra/a/b", "/a/b", true},
		{"/", "/tenant-a", "/tenant-a", true},
		{"/", "/", "", true},
		// "/entra2" is not a path segment inside "/entra", the same rule
		// config.mountsCollide applies to mounts.
		{"/entra", "/entra2/x", "", false},
		{"/entra", "/elsewhere", "", false},
		{"/entra", "", "", false},
	} {
		gotSuffix, gotOK := pathBelowMount(tc.mount, tc.issuerPath)
		if gotSuffix != tc.wantSuffix || gotOK != tc.wantOK {
			t.Errorf("pathBelowMount(%q, %q) = (%q, %v), want (%q, %v)",
				tc.mount, tc.issuerPath, gotSuffix, gotOK, tc.wantSuffix, tc.wantOK)
		}
	}
}
