package keys

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

const (
	// rsaKeyBits is the RSA modulus size used for every signing key.
	// RS256 is the only algorithm this package produces: coreos/go-oidc's
	// verifier accepts only RS256 by default, so ES256/Ed25519 are not an
	// escape route from the rsa.GenerateKey limitation below.
	rsaKeyBits = 2048

	// kidPrefix marks every kid this package issues as belonging to
	// authside, so a token from this tool is recognisable in real logs
	// (README "Keys").
	kidPrefix = "authside-"

	// kidThumbprintChars is how many base64url characters of the RFC 7638
	// JWK thumbprint are kept after kidPrefix. It is a truncation for
	// readability only; the full 256-bit thumbprint is what makes the kid
	// a function of the key material rather than of a counter.
	kidThumbprintChars = 16
)

// Set holds the RSA signing keys for one target: the "published" key,
// whose public half is served from JWKS, and a second, structurally
// identical "unpublished" key whose public half never appears there.
//
// The unpublished key exists to exercise tamper: [signature] (README
// "Keys" / "Negative testing"): signing with it produces a JWS whose kid
// a client cannot find in the JWKS, which is exactly the shape of an
// unknown-kid situation during real key rotation.
//
// A *Set is safe for concurrent use: nothing on it mutates after New
// returns.
type Set struct {
	published    jwk.Key
	publishedKid string

	unpublished    jwk.Key
	unpublishedKid string

	jwksJSON []byte
}

// Spec says where a target's signing key comes from. The zero value means
// "generate a random RSA key at startup", which is the default and what
// every target got before a key could be supplied at all.
//
// At most one field may be set. Both empty is the generate case; both
// populated is a configuration error, not a precedence question.
type Spec struct {
	// PEM is a PEM-encoded RSA private key given inline (config
	// `key_pem`).
	PEM string

	// File is a path to a PEM-encoded RSA private key (config
	// `key_file`), resolved against the process's working directory.
	//
	// Working-directory-relative rather than config-file-relative
	// because a config can arrive through AUTHSIDE_CONFIG_INLINE, which
	// has no directory to be relative to -- and one rule that always
	// applies beats two that depend on how the config was supplied.
	File string
}

// supplied reports whether s names a key instead of asking for a
// generated one.
func (s Spec) supplied() bool { return s.PEM != "" || s.File != "" }

// New builds a Set for one target.
//
// spec selects the signing key. With the zero Spec, New generates a fresh
// random RSA-2048 key, which means the JWKS -- and every kid in it --
// changes on every process start: fine for a test that logs in and
// verifies within one process, useless for anything that has to verify a
// token across two of them. Supplying a key (Spec.PEM or Spec.File) makes
// the JWKS byte-stable and the kid fixed, because the kid is an RFC 7638
// thumbprint of the key material itself.
//
// A nil logger falls back to slog.Default().
//
// The *unpublished* key is always generated randomly, supplied key or
// not. Its entire purpose is to sign something no client can verify
// (tamper: [signature] -- an unknown kid), so stability would buy nothing
// and a second configurable key would only be a second thing to get
// wrong.
//
// Every key here is RS256-only, with a kid derived from the key's own RFC
// 7638 thumbprint and prefixed "authside-".
func New(spec Spec, logger *slog.Logger) (*Set, error) {
	if logger == nil {
		logger = slog.Default()
	}

	published, publishedKid, err := signingKey(spec)
	if err != nil {
		return nil, err
	}

	// Random, deliberately: see the doc comment above.
	unpublished, unpublishedKid, err := signingKeyFrom(generateRSAKey)
	if err != nil {
		return nil, fmt.Errorf("keys: generate unpublished key: %w", err)
	}

	pub, err := jwk.PublicKeyOf(published)
	if err != nil {
		return nil, fmt.Errorf("keys: derive public key: %w", err)
	}

	set := jwk.NewSet()
	if err := set.AddKey(pub); err != nil {
		return nil, fmt.Errorf("keys: add key to JWKS: %w", err)
	}

	jwksJSON, err := json.Marshal(set)
	if err != nil {
		return nil, fmt.Errorf("keys: marshal JWKS: %w", err)
	}

	return &Set{
		published:      published,
		publishedKid:   publishedKid,
		unpublished:    unpublished,
		unpublishedKid: unpublishedKid,
		jwksJSON:       jwksJSON,
	}, nil
}

// signingKey resolves spec into the published signing key.
func signingKey(spec Spec) (jwk.Key, string, error) {
	if spec.PEM != "" && spec.File != "" {
		return nil, "", fmt.Errorf("keys: key_pem and key_file are mutually exclusive; set one or neither")
	}
	if !spec.supplied() {
		key, kid, err := signingKeyFrom(generateRSAKey)
		if err != nil {
			return nil, "", fmt.Errorf("keys: generate published key: %w", err)
		}
		return key, kid, nil
	}
	return signingKeyFrom(func() (*rsa.PrivateKey, error) { return loadRSAKey(spec) })
}

// loadRSAKey reads and parses the RSA private key spec names.
func loadRSAKey(spec Spec) (*rsa.PrivateKey, error) {
	pemBytes := []byte(spec.PEM)
	source := "key_pem"
	if spec.File != "" {
		source = fmt.Sprintf("key_file %q", spec.File)
		b, err := os.ReadFile(spec.File)
		if err != nil {
			return nil, fmt.Errorf("keys: reading %s: %w", source, err)
		}
		pemBytes = b
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("keys: %s is not PEM-encoded (expected a block like \"-----BEGIN PRIVATE KEY-----\")", source)
	}

	// PKCS#8 first: it is what `openssl genpkey` emits today. PKCS#1
	// ("BEGIN RSA PRIVATE KEY") is still everywhere, so fall back to it.
	// The PEM block's type label is not consulted -- a hand-edited or
	// re-wrapped key with a mislabelled header still parses if its DER
	// is one of the two, and refusing it on the label alone would be a
	// pointless way to fail.
	if parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rsaKey, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("keys: %s holds a %T, but authside signs with RS256 and needs an RSA key", source, parsed)
		}
		return rsaKey, nil
	}
	if rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return rsaKey, nil
	}
	return nil, fmt.Errorf("keys: %s could not be parsed as an RSA private key in either PKCS#8 or PKCS#1 form", source)
}

// JWKS returns the JSON Web Key Set containing this Set's published
// public key, in the exact shape a jwks_uri handler must return.
// Repeated calls on the same Set return byte-identical output.
func (s *Set) JWKS() []byte {
	out := make([]byte, len(s.jwksJSON))
	copy(out, s.jwksJSON)
	return out
}

// Kid returns the kid of the published signing key, i.e. the one that
// appears in JWKS.
func (s *Set) Kid() string {
	return s.publishedKid
}

// UnpublishedKid returns the kid of the key whose public half is absent
// from JWKS. It always differs from Kid.
func (s *Set) UnpublishedKid() string {
	return s.unpublishedKid
}

// Sign produces a compact JWS over payload using the published signing
// key: protected header alg RS256, kid Kid().
//
// Sign deliberately does not build JWT claims. The caller
// (internal/oidcop) marshals its own claims JSON, because negative
// testing needs to emit deliberately malformed claims (a wrong at_hash,
// an exp of the wrong JSON type, a bad iss) and a claims-building API in
// this package would stand in the way of that.
func (s *Set) Sign(payload []byte) (string, error) {
	return sign(payload, s.published)
}

// SignUnpublished produces a compact JWS over payload using the
// unpublished signing key (see UnpublishedKid), to exercise a client's
// handling of an unknown kid -- README's tamper: [signature].
func (s *Set) SignUnpublished(payload []byte) (string, error) {
	return sign(payload, s.unpublished)
}

func sign(payload []byte, key jwk.Key) (string, error) {
	out, err := jws.Sign(payload, jws.WithKey(jwa.RS256(), key))
	if err != nil {
		return "", fmt.Errorf("keys: sign: %w", err)
	}
	return string(out), nil
}

// signingKeyFrom turns the RSA key produced by next into a jwk.Key
// stamped with its derived kid, alg (RS256) and use (sig).
//
// jwx enforces a 2048-bit minimum on import -- verified: jwk.Import on a
// 1024-bit key fails with "rsa modulus too small". So a too-small
// supplied key is refused here, at construction, rather than at the first
// login. The error says which bound was hit, because "import RSA key"
// alone sends people looking in the wrong place.
func signingKeyFrom(next func() (*rsa.PrivateKey, error)) (jwk.Key, string, error) {
	raw, err := next()
	if err != nil {
		return nil, "", err
	}

	key, err := jwk.Import(raw)
	if err != nil {
		return nil, "", fmt.Errorf("import RSA key (authside signs with RS256, which needs at least a 2048-bit key; this one is %d-bit): %w", raw.N.BitLen(), err)
	}

	kid, err := deriveKid(key)
	if err != nil {
		return nil, "", err
	}

	if err := key.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, "", fmt.Errorf("set kid: %w", err)
	}
	if err := key.Set(jwk.AlgorithmKey, jwa.RS256()); err != nil {
		return nil, "", fmt.Errorf("set alg: %w", err)
	}
	if err := key.Set(jwk.KeyUsageKey, jwk.ForSignature); err != nil {
		return nil, "", fmt.Errorf("set use: %w", err)
	}

	return key, kid, nil
}

// generateRSAKey returns a freshly generated, random RSA key of
// rsaKeyBits size. It is the fallback for a target that supplies no key
// of its own, and it is also always what the unpublished key is.
//
// There is deliberately no "derive a key from a short seed string" path
// here, and there is not going to be one. As of Go 1.26, rsa.GenerateKey
// ignores the io.Reader it is given (the GODEBUG=cryptocustomrand=1
// escape hatch is documented as scheduled for removal), so deriving an
// RSA key from a seed means hand-rolling prime search -- and then that
// search procedure becomes a compatibility surface, since changing it
// changes every kid and JWKS ever produced from a given seed. Supplying
// the key instead (Spec) gets the same stability for none of that: see
// README "Keys".
func generateRSAKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, rsaKeyBits)
}

// deriveKid derives a kid from key's own key material: the RFC 7638 JWK
// thumbprint (SHA-256), base64url-encoded and truncated to
// kidThumbprintChars characters, prefixed with kidPrefix. Because the
// thumbprint is a function of the key's required members only (for RSA:
// kty, e, n), this is stable across calls for the same key and, in
// practice, unique per key.
func deriveKid(key jwk.Key) (string, error) {
	thumbprint, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("compute JWK thumbprint: %w", err)
	}

	encoded := base64.RawURLEncoding.EncodeToString(thumbprint)
	if len(encoded) > kidThumbprintChars {
		encoded = encoded[:kidThumbprintChars]
	}

	return kidPrefix + encoded, nil
}
