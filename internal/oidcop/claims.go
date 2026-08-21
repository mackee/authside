package oidcop

import (
	"fmt"

	"github.com/mackee/authside/config"
	"github.com/mackee/authside/internal/tmpl"
)

// preparedUser is one config.User with its claim values pre-parsed as
// templates at construction time, so a malformed "${...}" in a claim value
// fails loudly at authside.New rather than the first time some client
// happens to log in as this user (see internal/tmpl's package doc on
// parse-time vs. resolve-time errors).
type preparedUser struct {
	sub    string
	raw    map[string]any // the original config claims, used as the ${claims.x} lookup table when resolving a sibling claim's own template
	claims map[string]claimTemplate
}

// claimTemplate is one claim value, either a parsed template (when the
// config value was a string) or a literal value passed through unchanged
// (anything else -- bool, number, nested structures once claim resolution
// supports them, ...).
type claimTemplate struct {
	tmpl    *tmpl.Template
	literal any
}

// prepareUser parses every string-valued claim of u as a tmpl.Template. It
// returns an error naming the target, user and claim on a syntax error.
func prepareUser(targetName string, u config.User) (preparedUser, error) {
	claims := make(map[string]claimTemplate, len(u.Claims))
	for k, v := range u.Claims {
		if s, ok := v.(string); ok {
			t, err := tmpl.Parse(s)
			if err != nil {
				return preparedUser{}, fmt.Errorf("target %q: user %q: claim %q: %w", targetName, u.Sub, k, err)
			}
			claims[k] = claimTemplate{tmpl: t}
			continue
		}
		claims[k] = claimTemplate{literal: v}
	}
	return preparedUser{sub: u.Sub, raw: u.Claims, claims: claims}, nil
}

// resolveClaims renders every claim for one login (this user, running as
// clientID) into a plain map[string]any ready to be merged into an ID
// token / userinfo response / access token.
func (u preparedUser) resolveClaims(clientID string) (map[string]any, error) {
	out := make(map[string]any, len(u.claims))
	login := tmpl.Login{Subject: u.sub, ClientID: clientID, Claims: u.raw}
	for k, ct := range u.claims {
		if ct.tmpl == nil {
			out[k] = ct.literal
			continue
		}
		v, err := ct.tmpl.Resolve(login)
		if err != nil {
			return nil, fmt.Errorf("user %q: claim %q: %w", u.sub, k, err)
		}
		out[k] = v
	}
	return out, nil
}

// loginIdentity is who one login is for, in the form that travels from
// /authorize through the authorization code and the refresh family to
// every token minted along that chain.
//
// Carrying the claims (rather than re-deriving them from the subject at
// each grant) is what makes an injected identity survive a refresh. The
// configured-user case does re-derive, and must: a user's claims are
// resolved per client_id, so they are not a property of the subject
// alone.
type loginIdentity struct {
	subject string

	// claims is the complete claim set for this login, set only when
	// injected is true. It is never mutated after the /authorize request
	// that built it returns, and is shared by every token minted for
	// this login (read-only in all of them).
	claims map[string]any

	// injected records that the identity came from the request
	// (authside_claims) rather than from users:. It is a separate field
	// rather than "claims != nil" so that an injected identity carrying
	// no claims beyond sub stays distinguishable from a configured one.
	injected bool
}

// login converts a decoded authside_claims payload into the identity
// form the rest of a login carries.
func (i injectedIdentity) login() loginIdentity {
	return loginIdentity{subject: i.sub, claims: i.claims, injected: true}
}

// claimsFor returns the claims to mint for one login, running as
// clientID: the injected claims verbatim when the login carried them,
// otherwise the configured user's claim templates resolved for this
// client.
//
// ok is false only in the configured case, when the subject names no
// user the target knows any more -- callers treat that as an internal
// error, since /authorize validated the subject before the login got
// this far.
func (t *Target) claimsFor(id loginIdentity, clientID string) (claims map[string]any, ok bool, err error) {
	if id.injected {
		// Injected claims are literals, already specific to this login:
		// there is no template to resolve and no per-client variation
		// to apply.
		return id.claims, true, nil
	}
	user, found := t.lookupUser(id.subject)
	if !found {
		return nil, false, nil
	}
	resolved, err := user.resolveClaims(clientID)
	if err != nil {
		return nil, true, err
	}
	return resolved, true, nil
}
