package oidcop

import (
	"sync"
	"time"
)

// accessTokenSession is what /userinfo needs to answer a Bearer token: the
// subject and resolved claims it was issued for, and when it expires.
//
// clientID is who this access token was minted for. /userinfo never
// consults it (a bearer token is a bearer token there), but POST
// /revocation does: revoking someone else's access token by guessing its
// value is not something client authentication alone should permit -- see
// revocation.go.
type accessTokenSession struct {
	subject   string
	claims    map[string]any
	clientID  string
	expiresAt time.Time
}

// sessionStore maps an access token string to the session it represents.
//
// This exists so /userinfo resolves a token by lookup rather than by
// re-parsing whichever access token format the target is configured for.
// That indirection is what keeps access_token: opaque to a single branch
// -- token.go's mintAccessToken, and nothing else: an opaque token is
// just a different kind of map key into this same store, and /userinfo's
// lookup path is identical either way.
type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]*accessTokenSession
}

func newSessionStore() *sessionStore {
	return &sessionStore{sessions: make(map[string]*accessTokenSession)}
}

func (s *sessionStore) put(token string, sess accessTokenSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[token] = &sess
}

// lookup returns the session for token, if any exists and has not expired
// as of now. ok is false for an unknown token and for one that has expired
// (including one minted with a negative access_token_ttl, expired the
// moment it was issued -- README "Scenarios are configuration").
func (s *sessionStore) lookup(now time.Time, token string) (accessTokenSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[token]
	if !ok {
		return accessTokenSession{}, false
	}
	if now.After(sess.expiresAt) {
		return accessTokenSession{}, false
	}
	return *sess, true
}

// find returns the session for token regardless of expiry, for a caller
// (POST /revocation) that needs to check ownership (clientID) rather than
// validity -- an already-expired access token must still revoke cleanly
// (and idempotently) rather than being reported as "unknown".
func (s *sessionStore) find(token string) (accessTokenSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[token]
	if !ok {
		return accessTokenSession{}, false
	}
	return *sess, true
}

// revoke deletes token unconditionally. A token that was never issued, or
// was already revoked, is a silent no-op -- callers (reuse-detection
// family revocation, POST /revocation) rely on that idempotence.
func (s *sessionStore) revoke(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, token)
}
