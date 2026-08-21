package oidcop

import (
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/mackee/authside/config"
	"github.com/mackee/authside/internal/tmpl"
)

// MintParams names who a headless mint is for: which client the tokens
// are addressed to, which configured user they speak for, and the scope
// to stamp on the access token.
type MintParams struct {
	ClientID string
	Subject  string
	Scope    string
}

// Minted is one headless mint's result: the same two tokens POST /token
// would have returned for this client and user, plus the JWKS holding the
// key they were signed with.
//
// JWKS is included for the case where the target configures no signing
// key of its own: the key was then generated for this call alone, so
// nothing else -- including a running authside on the same config -- has
// anything that verifies these tokens, and this key set is the only one
// that does. A caller that wants them verified hands it to its verifier
// (go-oidc's oidc.StaticKeySet, for instance). With key_pem/key_file set
// the tokens verify against the running server normally, and this field
// is merely redundant rather than essential.
type Minted struct {
	IDToken     string
	AccessToken string
	ExpiresIn   int64
	JWKS        json.RawMessage
}

// Mint issues one ID token and one access token for a configured user
// without any browser, client, or HTTP request involved -- the `authside
// token` subcommand's whole implementation (README "Minting a token
// directly").
//
// It is deliberately the same code path POST /token takes, reached
// through buildTarget and mintAccessToken/buildIDToken rather than
// reimplemented: claim resolution, the issuer template, TTLs (negative
// ones included), nbf_skew and tamper all apply here exactly as they do
// to a token from a real login. A caller comparing the two is meant to
// find no difference beyond what is listed below.
//
// What a headless mint does not produce, and why:
//
//   - No refresh token. A refresh token is a handle into state that dies
//     with this process; handing one out would only ever fail.
//   - No nonce claim. nonce is defined as the value sent in an
//     authentication request, and there was no authentication request --
//     the same reason the refresh grant omits it (token.go's
//     issueFromRefresh).
//   - No session record. Nothing is registered in the target's session
//     store, so an access token from here does not resolve at any
//     /userinfo, and on an access_token: opaque target -- where the token
//     carries no claims at all -- the ID token is the only usable
//     artifact. The mint still happens rather than being refused: the
//     configuration is the API, and a config the server accepts is not
//     one this subcommand gets to reject.
func Mint(t *config.Target, logger *slog.Logger, p MintParams, opts ...Option) (*Minted, error) {
	target, err := buildTarget(t, logger, opts...)
	if err != nil {
		return nil, err
	}

	if _, ok := target.clients[p.ClientID]; !ok {
		return nil, fmt.Errorf("oidcop: target %q has no client %q", t.Name, p.ClientID)
	}
	user, ok := target.lookupUser(p.Subject)
	if !ok {
		return nil, fmt.Errorf("oidcop: target %q has no user %q (and accept_any_username is not set)", t.Name, p.Subject)
	}
	resolvedClaims, err := user.resolveClaims(p.ClientID)
	if err != nil {
		return nil, fmt.Errorf("oidcop: target %q: user %q: resolving claims: %w", t.Name, p.Subject, err)
	}

	issuer, err := target.issuerTmpl.Resolve(tmpl.Login{
		Subject:  p.Subject,
		ClientID: p.ClientID,
		Claims:   resolvedClaims,
	})
	if err != nil {
		return nil, fmt.Errorf("oidcop: target %q: user %q: resolving issuer: %w", t.Name, p.Subject, err)
	}

	now := target.clock.Now()
	atExp := now.Add(target.accessTokenTTL)
	idExp := now.Add(target.idTokenTTL)
	nbf := nbfFor(target, now)

	accessToken, err := target.mintAccessToken(accessTokenInput{
		issuer:    issuer,
		subject:   p.Subject,
		audience:  p.ClientID,
		clientID:  p.ClientID,
		scope:     p.Scope,
		issuedAt:  now,
		expiresAt: atExp,
		tamper:    target.tamper,
	})
	if err != nil {
		return nil, err
	}

	idToken, err := buildIDToken(target.keys, idTokenInput{
		issuer:       issuer,
		subject:      p.Subject,
		audience:     p.ClientID,
		nonce:        "", // see the doc comment: a headless mint had no authentication request
		nbf:          nbf,
		issuedAt:     now,
		expiresAt:    idExp,
		accessToken:  accessToken,
		customClaims: resolvedClaims,
		tamper:       target.tamper,
	})
	if err != nil {
		return nil, err
	}

	return &Minted{
		IDToken:     idToken,
		AccessToken: accessToken,
		ExpiresIn:   int64(target.accessTokenTTL.Seconds()),
		JWKS:        json.RawMessage(target.keys.JWKS()),
	}, nil
}
