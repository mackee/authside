package oidcop

import (
	"net/http"
	"strings"

	"github.com/mackee/authside/internal/reqlog"
	"github.com/mackee/tanukirpc"
)

// userinfoHandler implements GET /userinfo: a Bearer access token resolves
// (by lookup in t.sessions, not by re-parsing the JWT -- see sessions.go)
// to the subject and claims it was issued for.
func userinfoHandler(t *Target) tanukirpc.Handler[*Target] {
	return tanukirpc.NewHandler(func(ctx tanukirpc.Context[*Target], _ struct{}) (map[string]any, error) {
		// `errors: {userinfo: ...}` (README "Negative testing"): checked
		// before the bearer token is even inspected, so the target fails
		// here deterministically regardless of request validity.
		if err := t.configuredError("userinfo"); err != nil {
			return nil, err
		}

		token, err := bearerToken(ctx.Request())
		if err != nil {
			return nil, err
		}

		sess, ok := t.sessions.lookup(t.clock.Now(), token)
		if !ok {
			return nil, errInvalidToken("the access token is missing, malformed, expired, or unknown")
		}
		reqlog.FieldsFromContext(ctx).SetSub(sess.subject)

		out := make(map[string]any, len(sess.claims)+1)
		for k, v := range sess.claims {
			out[k] = v
		}
		out["sub"] = sess.subject
		return out, nil
	})
}

// bearerToken extracts the token from "Authorization: Bearer <token>",
// returning an RFC 6750 §3.1 invalid_token error (with its required
// WWW-Authenticate challenge) when the header is absent or malformed.
func bearerToken(req *http.Request) (string, error) {
	auth := req.Header.Get("Authorization")
	if auth == "" {
		return "", errInvalidToken("missing Authorization header")
	}
	rest, ok := strings.CutPrefix(auth, "Bearer ")
	if !ok || rest == "" {
		return "", errInvalidToken(`Authorization header must be "Bearer <token>"`)
	}
	return rest, nil
}
