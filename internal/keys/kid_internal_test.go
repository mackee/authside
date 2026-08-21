package keys

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// TestDeriveKidStable is a white-box test (package keys, not keys_test):
// it calls deriveKid twice on the SAME key material and checks the
// result is identical each time, and that it matches an independent
// recomputation of the RFC 7638 thumbprint. This is exit criterion 5
// ("the kid is stable for a given key: call the derivation twice"),
// which the black-box tests in keys_test.go cannot exercise directly
// since Set only ever derives a kid once per generated key.
func TestDeriveKidStable(t *testing.T) {
	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	key, err := jwk.Import(raw)
	if err != nil {
		t.Fatalf("jwk.Import: %v", err)
	}

	kid1, err := deriveKid(key)
	if err != nil {
		t.Fatalf("deriveKid (1st call): %v", err)
	}
	kid2, err := deriveKid(key)
	if err != nil {
		t.Fatalf("deriveKid (2nd call): %v", err)
	}

	if kid1 != kid2 {
		t.Fatalf("deriveKid is not stable: %q != %q", kid1, kid2)
	}

	// Independently recompute the RFC 7638 thumbprint and confirm the kid
	// is a function of it, not of a counter or anything else.
	thumbprint, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(thumbprint)
	want := kidPrefix + encoded[:kidThumbprintChars]

	if kid1 != want {
		t.Fatalf("deriveKid = %q, want %q (derived independently from the thumbprint)", kid1, want)
	}
}
