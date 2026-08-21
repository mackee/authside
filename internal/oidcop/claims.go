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
