package oidcop

import (
	"fmt"
	"strconv"

	"github.com/mackee/authside/internal/httpx"
)

// Error codes this package needs that internal/httpx does not define a
// constructor for (it only ships the RFC 6749 §5.2 core set plus the two
// OIDC prompt=none codes it happens to need elsewhere). httpx.ErrorCode
// is a plain string type, so these live here as ordinary constants and
// building an *httpx.OIDCError with one of them needs no new constructor
// in internal/httpx.
const (
	// errCodeUnsupportedResponseType is RFC 6749 §4.1.2.1's error for an
	// /authorize request whose response_type isn't "code".
	errCodeUnsupportedResponseType httpx.ErrorCode = "unsupported_response_type"

	// errCodeInvalidToken is RFC 6750 §3.1's error for a bearer token that
	// is missing, malformed, expired or otherwise invalid at a resource
	// endpoint (here, /userinfo).
	errCodeInvalidToken httpx.ErrorCode = "invalid_token"
)

// errInvalidGrantf builds an httpx.InvalidGrant error with a formatted
// description.
func errInvalidGrantf(format string, args ...any) error {
	return httpx.InvalidGrant(fmt.Sprintf(format, args...))
}

// errInvalidRequestf builds an httpx.InvalidRequest error with a formatted
// description.
func errInvalidRequestf(format string, args ...any) error {
	return httpx.InvalidRequest(fmt.Sprintf(format, args...))
}

// errUnsupportedResponseType builds the RFC 6749 §4.1.2.1
// "unsupported_response_type" error for a redirect back to the client.
func errUnsupportedResponseType(description string) *httpx.OIDCError {
	return &httpx.OIDCError{
		Code:        errCodeUnsupportedResponseType,
		Description: description,
		HTTPStatus:  400,
	}
}

// errInvalidToken builds the RFC 6750 §3.1 "invalid_token" error for
// /userinfo, with its required WWW-Authenticate challenge.
func errInvalidToken(description string) *httpx.OIDCError {
	wa := `Bearer realm="authside", error="invalid_token"`
	if description != "" {
		wa = fmt.Sprintf(`Bearer realm="authside", error="invalid_token", error_description=%q`, description)
	}
	return &httpx.OIDCError{
		Code:            errCodeInvalidToken,
		Description:     description,
		HTTPStatus:      401,
		WWWAuthenticate: wa,
	}
}

// errors: {revocation: ...} and errors: {end_session: ...} are wired in
// revocation.go's revocationHandler and endsession.go's
// endSessionHandler respectively, the same way every other endpoint here
// does: configuredError is the first thing each calls.

// configuredError implements the `errors:` config feature (README
// "Negative testing" / "Scenarios are configuration"): it returns the
// error a target's `errors:` map demands for endpoint, or nil when the
// target has no canned failure configured there. Every handler that
// wires this in calls it before doing any real work, so the target
// *always* fails at that endpoint, deterministically, with no dependence
// on what the request actually contains.
//
// config.Validate already guarantees every configured config.ErrorSpec is
// either a known OAuth error code or a well-formed 3-digit HTTP status
// (config/validate.go's validErrorSpec) before a Target is ever built from
// it, so the two "unreachable in practice" branches below are fail-closed
// defences against that invariant somehow not holding, not expected
// outcomes.
func (t *Target) configuredError(endpoint string) error {
	spec, ok := t.errors[endpoint]
	if !ok {
		return nil
	}
	if spec.IsHTTPStatus() {
		n, err := strconv.Atoi(string(spec))
		if err != nil {
			return httpx.ServerError(fmt.Sprintf("misconfigured errors[%s]: %q is not a valid HTTP status", endpoint, spec))
		}
		return httpx.NewStatusError(n)
	}
	oerr, ok := httpx.LookupErrorCode(string(spec))
	if !ok {
		return httpx.ServerError(fmt.Sprintf("misconfigured errors[%s]: %q is not a known OAuth error code", endpoint, spec))
	}
	return oerr
}

// authorizeConfiguredError builds the `errors: {authorize: ...}` failure
// for a request whose client_id and redirect_uri are already known good
// -- callers must only invoke this after validateClientAndRedirectURI has
// succeeded, mirroring RFC 6749 §4.1.2.1: an error may only be delivered
// to redirect_uri once the party to redirect to is actually known.
//
// The two config.ErrorSpec shapes get different treatment here because
// only one of them has a meaningful redirect encoding:
//   - An OAuth error code (e.g. "access_denied") is a genuine protocol-level
//     authorization error, so it goes back to redirect_uri exactly like any
//     other /authorize error: "?error=...&error_description=...&state=...".
//   - A bare HTTP status (e.g. 503) models a transport-level failure, not
//     an OAuth error -- there is no "error=503" in RFC 6749's vocabulary --
//     so it is returned as-is and rendered directly, the same way it is at
//     every other endpoint this feature applies to.
func authorizeConfiguredError(t *Target, redirectURI, state string) error {
	cerr := t.configuredError("authorize")
	if cerr == nil {
		return nil
	}
	if oerr, ok := cerr.(*httpx.OIDCError); ok {
		return redirectError(redirectURI, state, oerr)
	}
	return cerr
}
