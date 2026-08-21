package oidcop

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// codeTTL is how long an authorization code stays exchangeable. Real
// providers use a short, fixed window; authside does the same rather than
// making it configurable, since the interesting scenarios ("a token that
// arrives already expired") are expressed through id_token_ttl /
// access_token_ttl instead (README "Scenarios are configuration").
const codeTTL = 5 * time.Minute

// authCode is everything /token needs to remember about one /authorize
// success: who is logging in, for which client, under which redirect_uri,
// with which PKCE challenge (if any) and nonce.
type authCode struct {
	// loginIdentity is the subject and, when the login was injected via
	// authside_claims, its claims. Keeping the claims on the code is
	// what makes an injected identity survive the /authorize -> /token
	// hop: /token has no request-scoped cookie to re-read.
	loginIdentity

	clientID            string
	redirectURI         string
	scope               string
	nonce               string
	codeChallenge       string
	codeChallengeMethod string
	expiresAt           time.Time
	consumed            bool
}

// codeStore holds the authorization codes issued by one target. It is
// safe for concurrent use.
//
// The single-use guarantee is deliberate about *when* a code is marked
// consumed: Consume takes every check (existence, expiry, client match,
// redirect_uri match, PKCE) and the "mark used" mutation under one lock,
// but a caller that wants to authenticate the client *before* looking at
// the code at all (so that a rejected client_secret_basic attempt never
// touches the code, only a client_secret_post retry with the same code
// does, which is exactly how x/oauth2 behaves) does that itself, ahead
// of calling Consume. See token.go.
type codeStore struct {
	mu    sync.Mutex
	codes map[string]*authCode
}

func newCodeStore() *codeStore {
	return &codeStore{codes: make(map[string]*authCode)}
}

// issue mints a fresh, random authorization code and stores ac under it,
// expiring codeTTL from now.
func (s *codeStore) issue(now time.Time, ac authCode) (string, error) {
	code, err := randomToken(32)
	if err != nil {
		return "", err
	}
	ac.expiresAt = now.Add(codeTTL)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[code] = &ac
	return code, nil
}

// consume validates code against clientID, redirectURI and now, then --
// only if every check passes -- marks it consumed so no later call can
// succeed against the same code again. It returns a copy of the stored
// authCode on success.
//
// Checking and marking-consumed happen under one lock so two concurrent
// exchanges of the same code cannot both observe "not yet consumed".
func (s *codeStore) consume(now time.Time, code, clientID, redirectURI string) (authCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ac, ok := s.codes[code]
	if !ok {
		return authCode{}, errInvalidGrantf("unknown or already-exchanged authorization code")
	}
	if ac.consumed {
		return authCode{}, errInvalidGrantf("authorization code has already been used")
	}
	if now.After(ac.expiresAt) {
		return authCode{}, errInvalidGrantf("authorization code has expired")
	}
	if ac.clientID != clientID {
		return authCode{}, errInvalidGrantf("authorization code was not issued to this client")
	}
	if ac.redirectURI != redirectURI {
		return authCode{}, errInvalidGrantf("redirect_uri does not match the one used at /authorize")
	}

	ac.consumed = true
	return *ac, nil
}

// randomToken returns a base64url (unpadded)-encoded random token of n
// random bytes.
func randomToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
