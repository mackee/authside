package oidcop

import (
	"net/http"
	"slices"
	"strings"

	"github.com/mackee/tanukirpc"
)

// discoveryResponse is the OpenID Connect Discovery 1.0 metadata document
// this target serves at /.well-known/openid-configuration.
type discoveryResponse struct {
	Issuer                                 string   `json:"issuer"`
	AuthorizationEndpoint                  string   `json:"authorization_endpoint"`
	TokenEndpoint                          string   `json:"token_endpoint"`
	JWKSURI                                string   `json:"jwks_uri"`
	UserinfoEndpoint                       string   `json:"userinfo_endpoint"`
	RevocationEndpoint                     string   `json:"revocation_endpoint"`
	EndSessionEndpoint                     string   `json:"end_session_endpoint"`
	IDTokenSigningAlgValuesSupported       []string `json:"id_token_signing_alg_values_supported"`
	ResponseTypesSupported                 []string `json:"response_types_supported"`
	SubjectTypesSupported                  []string `json:"subject_types_supported"`
	GrantTypesSupported                    []string `json:"grant_types_supported"`
	ScopesSupported                        []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported      []string `json:"token_endpoint_auth_methods_supported"`
	RevocationEndpointAuthMethodsSupported []string `json:"revocation_endpoint_auth_methods_supported"`
	ClaimsSupported                        []string `json:"claims_supported"`
}

// discoveryHandler serves the shared discovery document, the one whose
// issuer field keeps its placeholders unresolved. It is only ever
// registered when the target's discovery mode is "shared"
// (config.DiscoverShared); "off" is implemented by simply not registering
// this route at all (see router.go), so it falls through to the target
// router's ordinary 404; "per_issuer" registers one
// perIssuerDiscoveryHandler per rendered issuer instead
// (discovery_periss.go).
func discoveryHandler(t *Target) tanukirpc.Handler[*Target] {
	return tanukirpc.NewHandler(func(ctx tanukirpc.Context[*Target], _ struct{}) (*discoveryResponse, error) {
		if err := t.configuredError("discovery"); err != nil {
			return nil, err
		}
		return t.discoveryDocument(ctx.Request(), t.issuerTmpl.Placeholderize(nil)), nil
	})
}

// discoveryDocument builds the metadata document for one request, with
// issuer used verbatim as the "issuer" field.
//
// issuer is a parameter rather than something read off t because it is the
// single field the two discovery modes disagree about: shared emits the
// placeholderized template, per_issuer emits one rendered issuer per
// route. Everything else -- every endpoint URL, and every supported-values
// list -- is identical between them by construction, which is exactly the
// property worth having in one function instead of two.
func (t *Target) discoveryDocument(req *http.Request, issuer string) *discoveryResponse {
	browserBase := t.baseURL(req, "browser")
	internalBase := t.baseURL(req, "internal")

	return &discoveryResponse{
		Issuer:                                 issuer,
		AuthorizationEndpoint:                  browserBase + "/authorize",
		TokenEndpoint:                          internalBase + "/token",
		JWKSURI:                                internalBase + "/jwks",
		UserinfoEndpoint:                       internalBase + "/userinfo",
		RevocationEndpoint:                     internalBase + "/revocation",
		EndSessionEndpoint:                     browserBase + "/end_session",
		IDTokenSigningAlgValuesSupported:       []string{"RS256"},
		ResponseTypesSupported:                 []string{"code"},
		SubjectTypesSupported:                  []string{"public"},
		GrantTypesSupported:                    []string{"authorization_code", "refresh_token"},
		ScopesSupported:                        t.scopesSupported(),
		TokenEndpointAuthMethodsSupported:      []string{"client_secret_basic", "client_secret_post"},
		RevocationEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post"},
		ClaimsSupported:                        t.claimsSupported(),
	}
}

// scopesSupported is a fixed, conventional list: authside does not track
// which scopes a client actually asked for at load time, and go-oidc's
// NewProvider does not validate this field's contents -- any reasonable
// value works for tier-1 discovery.
func (t *Target) scopesSupported() []string {
	return []string{"openid", "profile", "email"}
}

// protocolClaims are the claims every ID token carries regardless of
// which user logged in. A slice, not a map, so the order is fixed --
// see claimsSupported for why that matters.
var protocolClaims = []string{
	"sub", "iss", "aud", "exp", "iat", "nonce", "at_hash",
}

// claimsSupported lists the protocol claims every ID token carries plus
// the union of every configured user's claim names.
//
// The result is deterministic: protocolClaims in their fixed order, then
// the user-derived names sorted. It used to be assembled by ranging over
// two Go maps, so claims_supported came out in a different order on
// essentially every request -- two GETs of the same unchanged discovery
// document could differ byte-for-byte, and a client that caches or
// hashes the document would see churn that means nothing. Nothing about
// a target changes between two requests, so neither should the document
// it serves.
func (t *Target) claimsSupported() []string {
	seen := make(map[string]bool, len(protocolClaims))
	for _, k := range protocolClaims {
		seen[k] = true
	}

	extra := make([]string, 0, 8)
	for _, u := range t.users {
		for k := range u.claims {
			if !seen[k] {
				seen[k] = true
				extra = append(extra, k)
			}
		}
	}
	slices.Sort(extra)

	out := make([]string, 0, len(protocolClaims)+len(extra))
	out = append(out, protocolClaims...)
	return append(out, extra...)
}

// audience selects which of a target's advertise.internal /
// advertise.browser / request-derived base URLs applies: an explicit
// advertise value for that audience wins; otherwise the base is derived
// from the incoming request's scheme, Host and this target's mount,
// honouring X-Forwarded-Proto / X-Forwarded-Host from a TLS-terminating
// ingress in front of authside.
//
// issuer itself is never consulted here (see baseURL's comment for why).
type audience string

const (
	audienceBrowser  audience = "browser"
	audienceInternal audience = "internal"
)

// advertiseFor returns the configured advertise override for which
// audience, or "" when none is set.
func (t *Target) advertiseFor(which audience) string {
	if which == audienceBrowser {
		return t.advertiseBrowser
	}
	return t.advertiseInternal
}

// baseURL resolves the base URL to publish for one audience
// ("browser" or "internal"), against the incoming request req.
//
// Precedence: advertise.{browser,internal} when configured; otherwise
// the request itself -- never the configured issuer, even when the
// issuer has no template placeholder.
//
// issuer is an *identifier*, not necessarily a reachable address (README
// "Issuer, mount and advertise"): when it is not the address authside is
// actually served at -- an Entra-shaped issuer, or an issuer behind a
// TLS-terminating ingress that authside itself sits behind on plain HTTP
// -- endpoints derived from it are unreachable, and a discovery document
// full of unreachable URLs is worse than useless. The request, by
// contrast, tells us an address that demonstrably reaches us: the client
// just used it to get here. In simple mode (README "Client
// compatibility" tier 1), the issuer IS the served URL, so this and the
// old issuer-derived rule produce the identical result -- nothing
// regresses there. advertise remains the explicit override for
// split-horizon setups where the browser and the app need different
// bases than the request they happen to arrive on. The base therefore
// always comes from the request, never from a listen address.
func (t *Target) baseURL(req *http.Request, which audience) string {
	// advertise is read from the request's own target association, not a
	// package-level global: callers pass the *Target itself (t), so this
	// method reads t's own config-carried advertise value. See router.go
	// for where advertise is threaded through.
	if v := t.advertiseFor(which); v != "" {
		return strings.TrimRight(v, "/")
	}
	return requestBase(req) + t.mount
}

// requestBase derives scheme://host from the incoming request, honouring
// X-Forwarded-Proto / X-Forwarded-Host from a TLS-terminating ingress
// (README "Split-horizon dev environments" is an explicitly supported
// topology here).
func requestBase(req *http.Request) string {
	scheme := "http"
	if v := req.Header.Get("X-Forwarded-Proto"); v != "" {
		scheme = v
	} else if req.TLS != nil {
		scheme = "https"
	}
	host := req.Host
	if v := req.Header.Get("X-Forwarded-Host"); v != "" {
		host = v
	}
	return scheme + "://" + host
}
