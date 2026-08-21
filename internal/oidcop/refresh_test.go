package oidcop

import (
	"sync"
	"testing"

	"github.com/mackee/authside/config"
)

func TestRefreshStore_RotateRetiresOldTokenAndIssuesNew(t *testing.T) {
	s := newRefreshStore(config.RefreshRotate)
	sessions := newSessionStore()

	tokenA, familyID, err := s.issue("client-1", loginIdentity{subject: "user-1"}, "openid")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if familyID == "" {
		t.Fatalf("issue returned empty familyID")
	}

	result, err := s.refresh(sessions, tokenA, "client-1")
	if err != nil {
		t.Fatalf("first refresh(A): %v", err)
	}
	if result.nextToken == tokenA {
		t.Fatalf("rotate mode returned the SAME token, want a new one")
	}
	if result.familyID != familyID {
		t.Fatalf("familyID = %q, want %q (rotation must inherit the family)", result.familyID, familyID)
	}
	tokenB := result.nextToken

	// A is now retired: replaying it must fail.
	if _, err := s.refresh(sessions, tokenA, "client-1"); err == nil {
		t.Fatalf("replaying retired token A succeeded, want invalid_grant")
	}

	// B, freshly issued, must still work -- but that replay of A above
	// just revoked the whole family, so B (a sibling in that family) is
	// also dead now. See TestRefreshStore_ReuseDetectionRevokesWholeFamily
	// for the full assert-everything-is-dead version; here just confirm
	// B fails too.
	if _, err := s.refresh(sessions, tokenB, "client-1"); err == nil {
		t.Fatalf("refresh with B succeeded after A's reuse revoked the family, want invalid_grant")
	}
}

func TestRefreshStore_ReuseDetectionRevokesWholeFamily(t *testing.T) {
	s := newRefreshStore(config.RefreshRotate)
	sessions := newSessionStore()

	tokenA, familyID, err := s.issue("client-1", loginIdentity{subject: "user-1"}, "openid")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// Track two access tokens under this family, the way token.go does at
	// exchange and at every refresh.
	s.trackAccessToken(familyID, "AT-0", sessions)
	sessions.put("AT-0", accessTokenSession{subject: "user-1", clientID: "client-1"})

	resultB, err := s.refresh(sessions, tokenA, "client-1") // A retired, B issued
	if err != nil {
		t.Fatalf("refresh(A): %v", err)
	}
	tokenB := resultB.nextToken
	s.trackAccessToken(familyID, "AT-1", sessions)
	sessions.put("AT-1", accessTokenSession{subject: "user-1", clientID: "client-1"})

	resultC, err := s.refresh(sessions, tokenB, "client-1") // B works, retires, C issued
	if err != nil {
		t.Fatalf("refresh(B): %v", err)
	}
	tokenC := resultC.nextToken
	s.trackAccessToken(familyID, "AT-2", sessions)
	sessions.put("AT-2", accessTokenSession{subject: "user-1", clientID: "client-1"})

	// Replay the long-retired A: reuse detected, whole family revoked.
	if _, err := s.refresh(sessions, tokenA, "client-1"); err == nil {
		t.Fatalf("replaying A succeeded, want invalid_grant")
	}

	// C was never used and was never itself retired -- but its family is
	// now dead, so it must be rejected too. This is the real proof the
	// family model (not just per-token "retired" flags) is what is being
	// enforced.
	if _, err := s.refresh(sessions, tokenC, "client-1"); err == nil {
		t.Fatalf("refresh(C) succeeded after family revocation, want invalid_grant")
	}

	// Every access token minted anywhere along this chain must be dead.
	for _, at := range []string{"AT-0", "AT-1", "AT-2"} {
		if _, ok := sessions.find(at); ok {
			t.Errorf("access token %q still present after family revocation, want it gone", at)
		}
	}
}

func TestRefreshStore_StaticModeDoesNotRotateOrTripReuseDetection(t *testing.T) {
	s := newRefreshStore(config.RefreshStatic)
	sessions := newSessionStore()

	token, _, err := s.issue("client-1", loginIdentity{subject: "user-1"}, "openid")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	for i := 0; i < 3; i++ {
		result, err := s.refresh(sessions, token, "client-1")
		if err != nil {
			t.Fatalf("refresh #%d: %v", i, err)
		}
		if result.nextToken != token {
			t.Fatalf("refresh #%d returned a different token %q, want the same static token %q", i, result.nextToken, token)
		}
	}
}

func TestRefreshStore_WrongClientRejected(t *testing.T) {
	s := newRefreshStore(config.RefreshRotate)
	sessions := newSessionStore()

	token, _, err := s.issue("client-1", loginIdentity{subject: "user-1"}, "openid")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	if _, err := s.refresh(sessions, token, "client-2"); err == nil {
		t.Fatalf("refresh with a different client_id succeeded, want invalid_grant")
	}

	// The token must still be usable by its real owner afterwards -- the
	// wrong-client attempt above must not have consumed/retired it.
	if _, err := s.refresh(sessions, token, "client-1"); err != nil {
		t.Fatalf("refresh by the real owner after a wrong-client attempt failed: %v", err)
	}
}

func TestRefreshStore_UnknownTokenRejected(t *testing.T) {
	s := newRefreshStore(config.RefreshRotate)
	sessions := newSessionStore()
	if _, err := s.refresh(sessions, "no-such-token", "client-1"); err == nil {
		t.Fatalf("refresh of an unknown token succeeded, want invalid_grant")
	}
}

// TestRefreshStore_ConcurrentReplaySameToken races many goroutines
// refreshing the very same, not-yet-retired token at once. s.mu
// serializes them, so exactly one must observe "not retired yet" and
// win; every other one must fail. trackAccessToken's own re-check under
// the lock (see its doc comment) must then ensure that even the winner's
// own freshly-tracked access token ends up dead, since by the time
// trackAccessToken runs, the losers' replays have already revoked the
// family the winner's new token belongs to.
//
// Run with -race.
func TestRefreshStore_ConcurrentReplaySameToken(t *testing.T) {
	s := newRefreshStore(config.RefreshRotate)
	sessions := newSessionStore()

	token, familyID, err := s.issue("client-1", loginIdentity{subject: "user-1"}, "openid")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	const n = 20
	var (
		mu                sync.Mutex
		wg                sync.WaitGroup
		succeeded, failed int
		winner            refreshResult
	)

	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			result, err := s.refresh(sessions, token, "client-1")
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failed++
				return
			}
			succeeded++
			winner = result
		}()
	}
	wg.Wait()

	var startAT string
	if succeeded != 1 {
		t.Fatalf("succeeded = %d, want exactly 1 (rest must be invalid_grant)", succeeded)
	}
	if failed != n-1 {
		t.Fatalf("failed = %d, want %d", failed, n-1)
	}

	// The winner's own freshly-issued access token must be tracked and
	// then immediately killed: the concurrent replays are indistinguishable
	// from a genuine reuse-detection event, so the family the winner's
	// new token belongs to must already be revoked by the time
	// trackAccessToken runs.
	startAT = "AT-winner"
	sessions.put(startAT, accessTokenSession{subject: "user-1", clientID: "client-1"})
	s.trackAccessToken(winner.familyID, startAT, sessions)
	if _, ok := sessions.find(startAT); ok {
		t.Fatalf("winner's access token still present after concurrent-replay reuse detection, want it revoked")
	}
	if winner.familyID != familyID {
		t.Fatalf("winner familyID = %q, want %q", winner.familyID, familyID)
	}

	// The winner's own new refresh token must also be dead now.
	if _, err := s.refresh(sessions, winner.nextToken, "client-1"); err == nil {
		t.Fatalf("refresh with the winner's own new token succeeded after the family was revoked by concurrent replays, want invalid_grant")
	}
}
