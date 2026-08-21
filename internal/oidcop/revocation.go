package oidcop

import (
	"github.com/mackee/authside/internal/httpx"
	"github.com/mackee/authside/internal/reqlog"
	"github.com/mackee/tanukirpc"
)

// revocationRequest is POST /revocation's form body (RFC 7009 §2.1):
// the token to revoke, an optional hint at its type, and client
// authentication -- either via HTTP Basic (client_secret_basic) or these
// two form fields (client_secret_post), exactly as at /token.
type revocationRequest struct {
	Token         string `form:"token"`
	TokenTypeHint string `form:"token_type_hint"`
	ClientID      string `form:"client_id"`
	ClientSecret  string `form:"client_secret"`
}

// revocationResponse is POST /revocation's success body. RFC 7009 defines
// no response payload for a successful revocation; an empty JSON object
// is emitted only because this package's dispatch codec always encodes
// *something* as the handler's return value -- no field here is part of
// the protocol, and no client should parse this body.
type revocationResponse struct{}

// revocationHandler implements POST /revocation (RFC 7009).
//
// Per RFC 7009 §2.2, VERBATIM: "the authorization server responds with
// HTTP status code 200 if the token has been revoked successfully or if
// the client submitted an invalid token" -- and further, "Note: invalid
// tokens do not cause an error response since the client cannot handle
// such an error in a reasonable way. Moreover, the purpose of the
// revocation request, invalidating the particular token, is already
// achieved." This handler therefore returns 200 for an unknown token, an
// already-revoked token, and a token that belongs to a different client,
// exactly as it does for a token it actually revokes -- a client must not
// be able to use this endpoint to probe whether some token is currently
// valid. Do NOT "fix" this into a 404/400 for an unrecognised token; that
// would reopen exactly the oracle RFC 7009 closes.
//
// The two failures this endpoint IS allowed to report are client
// authentication failure (invalid_client, same as /token) and a
// malformed request (missing token, via httpx.InvalidRequest) -- both
// per RFC 7009 §2.1's "the authorization server MUST first validate the
// client credentials" step, which happens before anything about the
// token itself is even inspected.
func revocationHandler(t *Target) tanukirpc.Handler[*Target] {
	return tanukirpc.NewHandler(func(ctx tanukirpc.Context[*Target], req revocationRequest) (*revocationResponse, error) {
		// `errors: {revocation: ...}` (README "Negative testing"): checked
		// before anything else, same as every other endpoint.
		if err := t.configuredError("revocation"); err != nil {
			return nil, err
		}

		clientID, cerr := authenticateClient(t, ctx.Request(), tokenRequest{
			ClientID:     req.ClientID,
			ClientSecret: req.ClientSecret,
		})
		if cerr != nil {
			return nil, cerr
		}
		reqlog.FieldsFromContext(ctx).SetClientID(clientID)

		if req.Token == "" {
			return nil, httpx.InvalidRequest("token is required")
		}

		// token_type_hint only decides which lookup to try first: RFC
		// 7009 §2.1 requires falling back across every supported token
		// type when the hinted one does not match, since the hint is
		// only ever a hint the server may ignore.
		hintAccessToken := req.TokenTypeHint == "access_token"

		var sub string
		revoked := false

		tryAccessToken := func() bool {
			sess, ok := t.sessions.find(req.Token)
			if !ok || sess.clientID != clientID {
				return false
			}
			t.sessions.revoke(req.Token)
			sub = sess.subject
			return true
		}
		tryRefreshToken := func() bool {
			s, ok := t.refreshTokens.revokeByRefreshToken(t.sessions, req.Token, clientID)
			if !ok {
				return false
			}
			sub = s
			return true
		}

		if hintAccessToken {
			revoked = tryAccessToken() || tryRefreshToken()
		} else {
			// Revoking a refresh token revokes its whole family
			// (README "Refresh tokens" / refresh.go's
			// revokeByRefreshToken) -- consistent with reuse detection.
			// Revoking an access token only invalidates that access
			// token and deliberately does NOT cascade into its refresh
			// token/family: RFC 7009 §2.1 says the authorization server
			// "MAY" revoke other tokens it considers related, it is not
			// required to, and a client that revokes just its current
			// access token (e.g. to force a re-fetch) has no reason to
			// expect its ability to silently refresh later to be taken
			// away too. See revocation_test.go for both directions
			// tested explicitly.
			revoked = tryRefreshToken() || tryAccessToken()
		}

		if revoked && sub != "" {
			reqlog.FieldsFromContext(ctx).SetSub(sub)
		}

		return &revocationResponse{}, nil
	})
}
