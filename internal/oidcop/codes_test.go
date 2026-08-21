package oidcop

import (
	"testing"
	"time"
)

func TestCodeStore_SingleUse(t *testing.T) {
	s := newCodeStore()
	now := time.Now()

	code, err := s.issue(now, authCode{loginIdentity: loginIdentity{subject: "user-1"}, clientID: "client-1", redirectURI: "https://app.example/cb"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	ac, err := s.consume(now, code, "client-1", "https://app.example/cb")
	if err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if ac.subject != "user-1" {
		t.Fatalf("subject = %q, want user-1", ac.subject)
	}

	if _, err := s.consume(now, code, "client-1", "https://app.example/cb"); err == nil {
		t.Fatalf("second consume of the same code succeeded, want invalid_grant")
	}
}

// TestCodeStore_NotConsumedOnFailedCheck confirms that a consume() call
// that fails one of its checks (wrong client_id here, standing in for
// "the client authentication step that runs before consume is ever
// called" -- see token.go's authenticateClient, which runs first and can
// itself fail without ever touching the code store at all) leaves the
// code untouched: a later, correct call still succeeds. This is what
// makes x/oauth2's client_secret_basic-then-client_secret_post retry
// survive: whichever layer rejects the first attempt, the code itself
// must still be there for the retry.
func TestCodeStore_NotConsumedOnFailedCheck(t *testing.T) {
	s := newCodeStore()
	now := time.Now()

	code, err := s.issue(now, authCode{loginIdentity: loginIdentity{subject: "user-1"}, clientID: "client-1", redirectURI: "https://app.example/cb"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	if _, err := s.consume(now, code, "wrong-client", "https://app.example/cb"); err == nil {
		t.Fatalf("consume with wrong client_id succeeded, want an error")
	}
	if _, err := s.consume(now, code, "client-1", "https://wrong.example/cb"); err == nil {
		t.Fatalf("consume with wrong redirect_uri succeeded, want an error")
	}

	// The code must still be alive: the two failed attempts above must
	// not have consumed it.
	ac, err := s.consume(now, code, "client-1", "https://app.example/cb")
	if err != nil {
		t.Fatalf("consume after failed attempts: %v", err)
	}
	if ac.subject != "user-1" {
		t.Fatalf("subject = %q, want user-1", ac.subject)
	}
}

func TestCodeStore_Expiry(t *testing.T) {
	s := newCodeStore()
	issuedAt := time.Now()

	code, err := s.issue(issuedAt, authCode{loginIdentity: loginIdentity{subject: "user-1"}, clientID: "client-1", redirectURI: "https://app.example/cb"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	past := issuedAt.Add(codeTTL + time.Second)
	if _, err := s.consume(past, code, "client-1", "https://app.example/cb"); err == nil {
		t.Fatalf("consume after expiry succeeded, want invalid_grant")
	}
}

func TestCodeStore_UnknownCode(t *testing.T) {
	s := newCodeStore()
	if _, err := s.consume(time.Now(), "no-such-code", "client-1", "https://app.example/cb"); err == nil {
		t.Fatalf("consume of an unknown code succeeded, want invalid_grant")
	}
}
