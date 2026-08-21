// Package oidcop implements one OIDC target's tanukirpc handlers and
// in-memory state: discovery, authorize, token, userinfo, JWKS,
// revocation, end_session, and the authorization-code / access-token /
// refresh-token bookkeeping behind them.
//
// Every configuration option this package accepts is implemented: all
// three login modes -- auto (subject from the authside_sub cookie or
// default_user, no UI), picker (a one-click list of configured users) and
// form (a username/password form; any password is accepted -- see
// authorize_form.go); all three discovery modes, shared, off and
// per_issuer (discovery_periss.go); the authorization_code and
// refresh_token grants, with rotation and reuse detection (refresh.go);
// both access token formats, jwt and opaque (token.go's
// mintAccessToken); RFC 7009 revocation; RP-initiated logout; and the two
// negative-testing surfaces, tamper (tamper.go) and errors: (errors.go).
// Mint (mint.go) issues the same tokens with no HTTP request involved, for
// the `authside token` subcommand.
//
// New still fails at construction rather than serving something broken --
// a per_issuer target whose rendered issuers cannot be served is the one
// remaining case -- but no mode is refused merely for being unimplemented.
package oidcop
