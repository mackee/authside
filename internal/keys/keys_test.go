package keys_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"

	"github.com/mackee/authside/internal/keys"
)

func newTestSet(t *testing.T) *keys.Set {
	t.Helper()
	s, err := keys.New(keys.Spec{}, slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil)))
	if err != nil {
		t.Fatalf("keys.New: %v", err)
	}
	return s
}

// 1. The JWKS from one Set is byte-identical across repeated calls.
func TestJWKSStableAcrossCalls(t *testing.T) {
	s := newTestSet(t)

	first := s.JWKS()
	second := s.JWKS()

	if !bytes.Equal(first, second) {
		t.Fatalf("JWKS differs across calls:\nfirst:  %s\nsecond: %s", first, second)
	}
}

// 2. Every kid in the JWKS has the authside- prefix.
func TestJWKSKidsHavePrefix(t *testing.T) {
	s := newTestSet(t)

	set, err := jwk.Parse(s.JWKS())
	if err != nil {
		t.Fatalf("parse JWKS: %v", err)
	}
	if set.Len() == 0 {
		t.Fatal("JWKS has no keys")
	}
	for i := range set.Len() {
		key, ok := set.Key(i)
		if !ok {
			t.Fatalf("key %d missing", i)
		}
		kid, ok := key.KeyID()
		if !ok || kid == "" {
			t.Fatalf("key %d has no kid", i)
		}
		if !strings.HasPrefix(kid, "authside-") {
			t.Errorf("kid %q does not have authside- prefix", kid)
		}
	}
}

// 3. A JWS produced by Sign verifies against the JWKS, and its protected
// header kid is present in the JWKS.
func TestSignVerifiesAgainstJWKS(t *testing.T) {
	s := newTestSet(t)

	payload := []byte(`{"hello":"world"}`)
	compact, err := s.Sign(payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	set, err := jwk.Parse(s.JWKS())
	if err != nil {
		t.Fatalf("parse JWKS: %v", err)
	}

	verified, err := jws.Verify([]byte(compact), jws.WithKeySet(set))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !bytes.Equal(verified, payload) {
		t.Fatalf("verified payload = %s, want %s", verified, payload)
	}

	msg, err := jws.Parse([]byte(compact))
	if err != nil {
		t.Fatalf("jws.Parse: %v", err)
	}
	sigs := msg.Signatures()
	if len(sigs) != 1 {
		t.Fatalf("got %d signatures, want 1", len(sigs))
	}
	kid, ok := sigs[0].ProtectedHeaders().KeyID()
	if !ok || kid == "" {
		t.Fatal("protected header has no kid")
	}
	if kid != s.Kid() {
		t.Fatalf("protected header kid = %q, want %q", kid, s.Kid())
	}
	if _, ok := set.LookupKeyID(kid); !ok {
		t.Fatalf("kid %q from protected header not found in JWKS", kid)
	}
}

// 4. A JWS produced by the unpublished key does NOT verify against the
// JWKS, and its kid is absent from the JWKS.
func TestSignUnpublishedDoesNotVerify(t *testing.T) {
	s := newTestSet(t)

	payload := []byte(`{"hello":"world"}`)
	compact, err := s.SignUnpublished(payload)
	if err != nil {
		t.Fatalf("SignUnpublished: %v", err)
	}

	set, err := jwk.Parse(s.JWKS())
	if err != nil {
		t.Fatalf("parse JWKS: %v", err)
	}

	if _, err := jws.Verify([]byte(compact), jws.WithKeySet(set)); err == nil {
		t.Fatal("Verify unexpectedly succeeded against JWKS for unpublished key's JWS")
	}

	if s.UnpublishedKid() == "" {
		t.Fatal("UnpublishedKid is empty")
	}
	if !strings.HasPrefix(s.UnpublishedKid(), "authside-") {
		t.Fatalf("UnpublishedKid() = %q, want authside- prefix", s.UnpublishedKid())
	}
	if s.UnpublishedKid() == s.Kid() {
		t.Fatal("UnpublishedKid must differ from Kid")
	}
	if _, ok := set.LookupKeyID(s.UnpublishedKid()); ok {
		t.Fatalf("unpublished kid %q unexpectedly present in JWKS", s.UnpublishedKid())
	}
}

// 5. The kid is stable for a given key (derive twice), and two
// independently generated Sets have different kids.
func TestKidStableAndUnique(t *testing.T) {
	s1 := newTestSet(t)

	// Derivation is stable: JWKS parsed twice yields the same kid, and
	// Kid() called twice agrees with itself.
	if s1.Kid() != s1.Kid() {
		t.Fatal("Kid() is not stable across calls")
	}

	set1, err := jwk.Parse(s1.JWKS())
	if err != nil {
		t.Fatalf("parse JWKS: %v", err)
	}
	key1, ok := set1.Key(0)
	if !ok {
		t.Fatal("no key at index 0")
	}
	kidFromJWKS, _ := key1.KeyID()
	if kidFromJWKS != s1.Kid() {
		t.Fatalf("kid from JWKS = %q, want %q", kidFromJWKS, s1.Kid())
	}

	s2 := newTestSet(t)
	if s1.Kid() == s2.Kid() {
		t.Fatalf("two independently generated Sets produced the same kid %q", s1.Kid())
	}
}

// 6. A supplied key makes the whole Set reproducible: two Sets built from
// the same PEM agree on the kid and on the JWKS byte-for-byte. This is the
// entire point of key_pem/key_file -- without it, nothing can verify a
// token minted by a different process.
func TestSuppliedKeyIsReproducibleAcrossSets(t *testing.T) {
	pkcs8 := testKeyPEMPKCS8(t)

	first := setFromSpec(t, keys.Spec{PEM: pkcs8})
	second := setFromSpec(t, keys.Spec{PEM: pkcs8})

	if first.Kid() != second.Kid() {
		t.Fatalf("kid differs between Sets built from the same key: %q vs %q", first.Kid(), second.Kid())
	}
	if !bytes.Equal(first.JWKS(), second.JWKS()) {
		t.Fatalf("JWKS differs between Sets built from the same key:\n %s\n %s", first.JWKS(), second.JWKS())
	}

	// And a token signed by one verifies against the other's JWKS -- the
	// cross-process case, in miniature.
	signed, err := first.Sign([]byte(`{"sub":"user-1"}`))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	set, err := jwk.Parse(second.JWKS())
	if err != nil {
		t.Fatalf("parsing the other Set's JWKS: %v", err)
	}
	if _, err := jws.Verify([]byte(signed), jws.WithKeySet(set)); err != nil {
		t.Fatalf("verifying one Set's token against the other's JWKS: %v", err)
	}
}

// 7. A generated key is NOT reproducible -- the contrast that makes the
// case above worth having, and the behaviour every target still gets by
// default.
func TestGeneratedKeyIsNotReproducible(t *testing.T) {
	if newTestSet(t).Kid() == newTestSet(t).Kid() {
		t.Fatal("two generated Sets share a kid; they are supposed to be independent")
	}
}

// 8. Both PEM encodings people actually have are accepted, and they are
// the same key: PKCS#8 ("BEGIN PRIVATE KEY", what openssl genpkey emits)
// and PKCS#1 ("BEGIN RSA PRIVATE KEY", still everywhere).
func TestSuppliedKeyAcceptsPKCS8AndPKCS1(t *testing.T) {
	fromPKCS8 := setFromSpec(t, keys.Spec{PEM: testKeyPEMPKCS8(t)})
	fromPKCS1 := setFromSpec(t, keys.Spec{PEM: testKeyPEMPKCS1(t)})

	if fromPKCS8.Kid() != fromPKCS1.Kid() {
		t.Fatalf("the same key in two encodings produced different kids: %q (PKCS#8) vs %q (PKCS#1)", fromPKCS8.Kid(), fromPKCS1.Kid())
	}
}

// 9. key_file reads the same key off disk.
func TestSuppliedKeyFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signing-key.pem")
	if err := os.WriteFile(path, []byte(testKeyPEMPKCS8(t)), 0o600); err != nil {
		t.Fatalf("writing the key: %v", err)
	}

	fromFile := setFromSpec(t, keys.Spec{File: path})
	inline := setFromSpec(t, keys.Spec{PEM: testKeyPEMPKCS8(t)})

	if fromFile.Kid() != inline.Kid() {
		t.Fatalf("key_file and key_pem disagree on the kid: %q vs %q", fromFile.Kid(), inline.Kid())
	}
}

// 10. The unpublished key (tamper: [signature]) stays random even when a
// key is supplied: its job is to be unverifiable, so reproducing it would
// buy nothing.
func TestUnpublishedKeyStaysRandomWithASuppliedKey(t *testing.T) {
	pkcs8 := testKeyPEMPKCS8(t)
	first := setFromSpec(t, keys.Spec{PEM: pkcs8})
	second := setFromSpec(t, keys.Spec{PEM: pkcs8})

	if first.UnpublishedKid() == second.UnpublishedKid() {
		t.Fatal("the unpublished kid was reproduced; it is supposed to be freshly random")
	}
	if first.UnpublishedKid() == first.Kid() {
		t.Fatal("the unpublished kid equals the published one")
	}
}

// 11. Everything that cannot work is refused at construction, with a
// message that says which input was wrong -- these are all config typos,
// and "import RSA key" alone sends people looking in the wrong place.
func TestSuppliedKeyRejectsWhatItCannotUse(t *testing.T) {
	tooSmall := pemEncode(t, "PRIVATE KEY", mustMarshalPKCS8(t, generateRSA(t, 1024)))
	ed25519PEM := pemEncode(t, "PRIVATE KEY", mustMarshalPKCS8Any(t, generateEd25519(t)))

	for name, tc := range map[string]struct {
		spec    keys.Spec
		wantMsg string
	}{
		"both key_pem and key_file": {
			spec:    keys.Spec{PEM: testKeyPEMPKCS8(t), File: "/some/path.pem"},
			wantMsg: "mutually exclusive",
		},
		"not PEM at all": {
			spec:    keys.Spec{PEM: "this is not a key"},
			wantMsg: "not PEM-encoded",
		},
		"PEM wrapping something that is not a key": {
			spec:    keys.Spec{PEM: pemEncode(t, "PRIVATE KEY", []byte("garbage DER"))},
			wantMsg: "could not be parsed as an RSA private key",
		},
		"an Ed25519 key": {
			spec:    keys.Spec{PEM: ed25519PEM},
			wantMsg: "needs an RSA key",
		},
		"an RSA key too small for RS256": {
			spec:    keys.Spec{PEM: tooSmall},
			wantMsg: "2048",
		},
		"a key_file that does not exist": {
			spec:    keys.Spec{File: filepath.Join(t.TempDir(), "absent.pem")},
			wantMsg: "reading key_file",
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := keys.New(tc.spec, discardLogger())
			if err == nil {
				t.Fatalf("keys.New(%+v) = nil, want an error mentioning %q", tc.spec, tc.wantMsg)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("error = %q, want it to mention %q", err.Error(), tc.wantMsg)
			}
		})
	}
}

// --- helpers ---------------------------------------------------------

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func setFromSpec(t *testing.T, spec keys.Spec) *keys.Set {
	t.Helper()
	s, err := keys.New(spec, discardLogger())
	if err != nil {
		t.Fatalf("keys.New(%+v): %v", spec, err)
	}
	return s
}

// testKey is generated once per test binary: RSA-2048 generation is slow
// enough (~100ms) that doing it per test case is noticeable, and every
// case that wants "a valid key" wants the same one.
var (
	testKeyOnce sync.Once
	testKey     *rsa.PrivateKey
)

func sharedTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	testKeyOnce.Do(func() { testKey = generateRSA(t, 2048) })
	return testKey
}

// Keys are generated at test time rather than checked in as fixtures: a
// committed PEM private key trips secret scanners and can be blocked
// outright by push protection, which would be a surprise the day this
// repository gains a remote.
func generateRSA(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("generating a %d-bit RSA key: %v", bits, err)
	}
	return k
}

func generateEd25519(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating an Ed25519 key: %v", err)
	}
	return priv
}

func testKeyPEMPKCS8(t *testing.T) string {
	t.Helper()
	return pemEncode(t, "PRIVATE KEY", mustMarshalPKCS8(t, sharedTestKey(t)))
}

func testKeyPEMPKCS1(t *testing.T) string {
	t.Helper()
	return pemEncode(t, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(sharedTestKey(t)))
}

func mustMarshalPKCS8(t *testing.T, k *rsa.PrivateKey) []byte {
	t.Helper()
	return mustMarshalPKCS8Any(t, k)
}

func mustMarshalPKCS8Any(t *testing.T, k any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatalf("marshalling PKCS#8: %v", err)
	}
	return der
}

func pemEncode(t *testing.T, blockType string, der []byte) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}))
}
