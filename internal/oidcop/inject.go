package oidcop

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/mackee/authside/internal/httpx"
)

// authsideClaimsCookie is the cookie a caller sets to supply the whole
// identity for one login -- sub and every claim -- on a target with
// accept_injected_claims. It is read exactly where login: auto reads
// authsideSubCookie, on authside's own browser-facing origin, and
// authside never sets it (only clears it, at /end_session, alongside
// authside_sub).
//
// Why a cookie rather than a query parameter on /authorize: in the flow
// this exists for, the application under test builds the /authorize URL
// itself and redirects the browser to it, so the test never holds that
// URL to add a parameter to. A cookie is set once on authside's origin
// before the flow starts and rides the redirect. It is also the same
// mechanism authside_sub already uses, rather than a second kind of
// input to learn.
//
// Cookies are scoped to a browser context, not to a request, so two
// logins as different identities in one context are sequential (set,
// log in, set again) -- the same property authside_sub has. Tests that
// need two identities at once use two contexts, which is what isolates
// their cookie jars from each other in the first place.
const authsideClaimsCookie = "authside_claims"

// injectedIdentity is one login's identity as carried by the request
// itself: the subject, plus the complete set of claims to mint. It
// replaces the configured user wholesale -- there is no merge with a
// users: entry of the same sub -- so what a test writes in the payload
// is exactly what comes back in the ID token and at /userinfo.
type injectedIdentity struct {
	sub    string
	claims map[string]any
}

// injectedClaimsPayloadDoc describes the wire format in one place, for
// the error messages below to stay consistent with each other.
const injectedClaimsPayloadDoc = `base64url of a flat JSON object with a non-empty string "sub", e.g. base64url({"sub":"u-1","email":"u-1@example.com"})`

// decodeInjectedIdentity parses the authside_claims cookie value: a
// base64url-encoded (padded or not) flat JSON object. "sub" is required
// and becomes the subject; every other key becomes a claim, taken
// verbatim.
//
// Claim values are literals, never templates: a "${...}" in an injected
// value is the string "${...}", not something to resolve. Config claims
// are templates because they are written once and reused by every login;
// an injected claim is already specific to the one login carrying it, so
// there is nothing left for a template to vary -- and keeping them
// literal means a request can never introduce a template syntax error
// (internal/tmpl's parse-time errors all belong to authside.New).
//
// The target's issuer template still resolves against these claims, so
// "issuer: https://.../${claims.tid}/v2.0" picks up an injected tid.
func decodeInjectedIdentity(raw string) (injectedIdentity, error) {
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(raw, "="))
	if err != nil {
		return injectedIdentity{}, fmt.Errorf("base64url decode: %w", err)
	}

	var obj map[string]any
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.UseNumber() // keep integers exact; internal/tmpl stringifies json.Number
	if err := dec.Decode(&obj); err != nil {
		return injectedIdentity{}, fmt.Errorf("json decode: %w", err)
	}
	if obj == nil {
		return injectedIdentity{}, fmt.Errorf("payload is JSON null, want an object")
	}

	subVal, ok := obj["sub"]
	if !ok {
		return injectedIdentity{}, fmt.Errorf(`payload has no "sub"`)
	}
	sub, ok := subVal.(string)
	if !ok {
		return injectedIdentity{}, fmt.Errorf(`"sub" has type %T, want a string`, subVal)
	}
	if sub == "" {
		return injectedIdentity{}, fmt.Errorf(`"sub" must not be empty`)
	}

	claims := make(map[string]any, len(obj))
	for k, v := range obj {
		if k == "sub" {
			// sub is the subject, not a claim: buildIDToken and
			// /userinfo both write it from the subject after the
			// custom claims, so carrying it in the claim map too
			// would be a value that is always overwritten.
			continue
		}
		claims[k] = v
	}
	return injectedIdentity{sub: sub, claims: claims}, nil
}

// injectedIdentityFrom reads the authside_claims cookie off req, if this
// target accepts one and the request carries one.
//
// A cookie present on a target without accept_injected_claims is ignored
// rather than rejected: every target in one authside process shares one
// origin, so a cookie set for target A rides along to target B, and
// failing B's logins over it would make enabling the feature anywhere
// break it everywhere else. Ignoring it silently is its own trap, though
// -- "I set the cookie and got default_user" -- so the first time it
// happens the target says so once (see Target.warnIgnoredInjection).
func injectedIdentityFrom(req *http.Request, t *Target) (injectedIdentity, bool, *httpx.OIDCError) {
	c, err := req.Cookie(authsideClaimsCookie)
	if err != nil || c.Value == "" {
		return injectedIdentity{}, false, nil
	}
	if !t.acceptInjectedClaims {
		t.warnIgnoredInjection()
		return injectedIdentity{}, false, nil
	}

	id, decErr := decodeInjectedIdentity(c.Value)
	if decErr != nil {
		// Loud, not ignored: a payload the caller meant to be used and
		// that authside cannot read must not quietly fall through to
		// default_user, which would log the test in as the wrong
		// identity and fail somewhere far away from the cause.
		return injectedIdentity{}, false, httpx.InvalidRequest(fmt.Sprintf(
			"%s cookie is malformed: %v (want %s)", authsideClaimsCookie, decErr, injectedClaimsPayloadDoc))
	}
	return id, true, nil
}
