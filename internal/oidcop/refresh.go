package oidcop

import (
	"sync"

	"github.com/mackee/authside/config"
)

// refreshRecord is one refresh token's bookkeeping: which family it
// descends from, which client and subject it was issued to, and (under
// rotate) whether it has already been used once.
//
// Refresh tokens carry no expiry here -- unlike authorization codes and
// access tokens, README "Refresh tokens" describes no TTL for them, only
// a rotation/reuse-detection lifecycle. A token stops being valid by
// being retired (rotate) or by its family being revoked (reuse detection,
// or an explicit POST /revocation), never by clock.Now() alone.
type refreshRecord struct {
	familyID string
	clientID string
	subject  string
	scope    string
	retired  bool
}

// refreshFamily groups every refresh token descended from one
// authorization_code exchange, plus every access token minted anywhere
// along that chain (at the original exchange and at every refresh since).
// "Family" is modeled explicitly, rather than inferred from token
// contents: a familyID is created once, at code exchange, and every
// rotation inherits it unchanged.
//
// Revoking a family (reuse detection in rotate mode, or an explicit
// POST /revocation of any refresh token in it) kills every refresh token
// that shares its familyID and every access token ever tracked here --
// see revokeFamilyLocked.
type refreshFamily struct {
	clientID     string
	subject      string
	revoked      bool
	accessTokens map[string]struct{}
}

// refreshStore holds every refresh token and family for one target. It is
// safe for concurrent use.
//
// Lock ordering invariant: whenever a method here also needs to touch a
// *sessionStore (to kill access tokens on family revocation), it always
// takes s.mu first and calls into sessionStore's own locking methods
// while still holding it -- sessionStore never calls back into
// refreshStore. This is consistent everywhere in this file; do not
// introduce a path that takes the locks in the other order.
type refreshStore struct {
	mu       sync.Mutex
	mode     config.RefreshTokenMode
	tokens   map[string]*refreshRecord
	families map[string]*refreshFamily
}

// newRefreshStore builds a refreshStore honouring mode. An empty/unknown
// mode (a hand-built config.Target in a test that never went through
// config.ApplyDefaults) behaves as config.RefreshRotate, matching the
// README's stated default -- only the exact string "static" opts out.
func newRefreshStore(mode config.RefreshTokenMode) *refreshStore {
	return &refreshStore{
		mode:     mode,
		tokens:   make(map[string]*refreshRecord),
		families: make(map[string]*refreshFamily),
	}
}

// issue mints a brand-new family and its first refresh token, for the
// authorization_code grant (token.go's issueFromCode).
func (s *refreshStore) issue(clientID, subject, scope string) (token, familyID string, err error) {
	token, err = randomToken(32)
	if err != nil {
		return "", "", err
	}
	familyID, err = randomToken(16)
	if err != nil {
		return "", "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.families[familyID] = &refreshFamily{
		clientID:     clientID,
		subject:      subject,
		accessTokens: make(map[string]struct{}),
	}
	s.tokens[token] = &refreshRecord{
		familyID: familyID,
		clientID: clientID,
		subject:  subject,
		scope:    scope,
	}
	return token, familyID, nil
}

// trackAccessToken records that accessToken was minted under familyID, so
// a later family-wide revocation also invalidates it.
//
// This is called *after* issue/refresh has already returned success to
// its caller (token.go needs the family/subject/scope from that result
// before it can even build the access token), which leaves a window
// where a concurrent replay of a since-retired sibling token could revoke
// the family in between. Closing that window is exactly why this method
// re-checks the family's current state under the lock, rather than
// blindly inserting: if the family has since been revoked (or vanished,
// which should not happen but is treated the same defensively), the
// access token just minted is killed immediately instead of being
// registered into a family that will never revoke it. See
// TestRefreshStore_ConcurrentReplaySameToken for the race this closes.
func (s *refreshStore) trackAccessToken(familyID, accessToken string, sessions *sessionStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fam, ok := s.families[familyID]
	if !ok || fam.revoked {
		sessions.revoke(accessToken)
		return
	}
	fam.accessTokens[accessToken] = struct{}{}
}

// refreshResult is what a successful refresh (or the initial issue, via
// issueFromCode) reports back to the caller: the family/subject/scope the
// tokens it is about to mint should carry, plus which refresh token
// string the client should actually receive (nextToken).
type refreshResult struct {
	familyID  string
	clientID  string
	subject   string
	scope     string
	nextToken string
}

// refresh validates token against clientID and applies this store's
// configured rotation behaviour on success:
//
//   - rotate (default): token is retired and a new refresh token is
//     minted in the same family; nextToken is the new one.
//   - static: token stays valid; nextToken is the same token.
//
// Reuse detection (rotate mode only -- static never retires anything, so
// there is nothing to detect reuse of, and repeated use of the same
// static token is the documented, intended behaviour): replaying an
// already-retired refresh token revokes the *entire family* -- every
// refresh token descended from the original authorization, and every
// access token minted anywhere along that chain (via sessions, so they
// stop working at /userinfo immediately) -- then reports invalid_grant.
// A family that is already revoked (whether from an earlier reuse or
// from an explicit POST /revocation) rejects every token in it the same
// way, even one that was never itself retired.
func (s *refreshStore) refresh(sessions *sessionStore, token, clientID string) (refreshResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.tokens[token]
	if !ok {
		return refreshResult{}, errInvalidGrantf("unknown or already-revoked refresh token")
	}
	if rec.clientID != clientID {
		return refreshResult{}, errInvalidGrantf("refresh token was not issued to this client")
	}
	fam, famOK := s.families[rec.familyID]
	if !famOK || fam.revoked {
		return refreshResult{}, errInvalidGrantf("refresh token's family has been revoked")
	}
	if rec.retired {
		// Theft signal: this exact token was already rotated away from
		// once. Kill the whole family -- every sibling refresh token and
		// every access token minted along this chain -- then refuse.
		s.revokeFamilyLocked(rec.familyID, sessions)
		return refreshResult{}, errInvalidGrantf("refresh token has already been used; its token family has been revoked")
	}

	result := refreshResult{
		familyID: rec.familyID,
		clientID: rec.clientID,
		subject:  rec.subject,
		scope:    rec.scope,
	}

	if s.mode == config.RefreshStatic {
		result.nextToken = token
		return result, nil
	}

	// rotate: retire this token and mint its successor in the same
	// family. Concurrent callers are serialized by s.mu, so of any number
	// of simultaneous refreshes racing on the very same token, exactly
	// one observes rec.retired == false here and wins; every other one
	// either sees it already retired (the reuse-detection branch above,
	// which revokes the family the winner's new token belongs to as
	// well) or -- once that has happened -- sees the family revoked.
	rec.retired = true
	newToken, err := randomToken(32)
	if err != nil {
		return refreshResult{}, err
	}
	s.tokens[newToken] = &refreshRecord{
		familyID: rec.familyID,
		clientID: rec.clientID,
		subject:  rec.subject,
		scope:    rec.scope,
	}
	result.nextToken = newToken
	return result, nil
}

// revokeFamilyLocked marks familyID's family revoked and deletes every
// access token minted under it from sessions. Caller must hold s.mu.
// Idempotent: revoking an already-revoked family is a harmless no-op
// beyond re-deleting already-gone session entries.
func (s *refreshStore) revokeFamilyLocked(familyID string, sessions *sessionStore) {
	fam, ok := s.families[familyID]
	if !ok {
		return
	}
	fam.revoked = true
	for at := range fam.accessTokens {
		sessions.revoke(at)
	}
}

// revokeByRefreshToken implements POST /revocation (RFC 7009) for a
// refresh token: revoking a refresh token revokes its whole family,
// exactly as reuse detection does. ok reports whether token was a known
// refresh token issued to clientID; when false, revocation.go treats this
// exactly like an unrecognised token per RFC 7009 §2.2 -- 200, no error,
// no side effect. subject is the token's subject, for the request log,
// valid only when ok is true.
//
// A refresh token that exists but belongs to a *different* client is
// deliberately treated the same as "unknown" here (ok=false) rather than
// as a distinguishable error: telling the caller "this token exists, but
// isn't yours" would let /revocation be used to probe whether some other
// client's token is still live, which is exactly the oracle RFC 7009
// §2.2 says this endpoint must not provide.
func (s *refreshStore) revokeByRefreshToken(sessions *sessionStore, token, clientID string) (subject string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, found := s.tokens[token]
	if !found || rec.clientID != clientID {
		return "", false
	}
	s.revokeFamilyLocked(rec.familyID, sessions)
	return rec.subject, true
}
