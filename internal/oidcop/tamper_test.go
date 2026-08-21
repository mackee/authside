package oidcop

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"

	"github.com/mackee/authside/config"
	"github.com/mackee/authside/internal/keys"
)

// This file is the white-box (package oidcop) half of the tamper tests:
// it checks the corruptions themselves, and that building an ID/access
// token with one tamper value set corrupts exactly that claim while
// every other claim -- and, except for tamper: [signature], the
// signature itself -- stays exactly as a non-tampered build would leave
// it. The client-level half (a real go-oidc verifier rejecting each
// tampered token, for the documented reason) lives in the root package's
// tamper_test.go, which this package's tests cannot themselves exercise
// (this package has no dependency on coreos/go-oidc).

func testKeySet(t *testing.T) *keys.Set {
	t.Helper()
	s, err := keys.New(keys.Spec{}, slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil)))
	if err != nil {
		t.Fatalf("keys.New: %v", err)
	}
	return s
}

// decodeJWSPayload splits a compact JWS and returns its payload decoded
// into a map, without verifying the signature (callers that care about
// the signature check it separately via jws.Verify against the JWKS, or
// assert on which kid was used).
func decodeJWSPayload(t *testing.T, compact string) map[string]any {
	t.Helper()
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("compact JWS has %d parts, want 3: %s", len(parts), compact)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decoding JWS payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("unmarshaling JWS payload %s: %v", raw, err)
	}
	return claims
}

// kidOf returns the kid from a compact JWS's protected header.
func kidOf(t *testing.T, compact string) string {
	t.Helper()
	msg, err := jws.Parse([]byte(compact))
	if err != nil {
		t.Fatalf("jws.Parse: %v", err)
	}
	sigs := msg.Signatures()
	if len(sigs) != 1 {
		t.Fatalf("got %d signatures, want 1", len(sigs))
	}
	kid, ok := sigs[0].ProtectedHeaders().KeyID()
	if !ok {
		t.Fatalf("no kid in protected header")
	}
	return kid
}

func baseIDTokenInput(k *keys.Set, tamper tamperSet) idTokenInput {
	now := time.Unix(1_700_000_000, 0).UTC()
	return idTokenInput{
		issuer:       "https://authside.example/oidc",
		subject:      "user-1",
		audience:     "client-1",
		nonce:        "the-nonce-value",
		issuedAt:     now,
		expiresAt:    now.Add(time.Hour),
		accessToken:  "AT-plain-access-token",
		customClaims: map[string]any{"email": "alice@example.com"},
		tamper:       tamper,
	}
}

func baseAccessTokenInput(tamper tamperSet) accessTokenInput {
	now := time.Unix(1_700_000_000, 0).UTC()
	return accessTokenInput{
		issuer:    "https://authside.example/oidc",
		subject:   "user-1",
		audience:  "client-1",
		clientID:  "client-1",
		scope:     "openid",
		issuedAt:  now,
		expiresAt: now.Add(time.Hour),
		tamper:    tamper,
	}
}

// TestBuildIDToken_NoTamper_Baseline pins down the untampered shape every
// other test in this file diffs against.
func TestBuildIDToken_NoTamper_Baseline(t *testing.T) {
	k := testKeySet(t)
	in := baseIDTokenInput(k, nil)
	compact, err := buildIDToken(k, in)
	if err != nil {
		t.Fatalf("buildIDToken: %v", err)
	}
	claims := decodeJWSPayload(t, compact)

	if claims["iss"] != in.issuer {
		t.Errorf("iss = %v, want %v", claims["iss"], in.issuer)
	}
	if claims["aud"] != in.audience {
		t.Errorf("aud = %v, want %v", claims["aud"], in.audience)
	}
	if claims["nonce"] != in.nonce {
		t.Errorf("nonce = %v, want %v", claims["nonce"], in.nonce)
	}
	wantAtHash := atHashS256(in.accessToken)
	if claims["at_hash"] != wantAtHash {
		t.Errorf("at_hash = %v, want %v", claims["at_hash"], wantAtHash)
	}
	if _, ok := claims["exp"].(float64); !ok {
		t.Errorf("exp is %T, want a JSON number (float64 after decode)", claims["exp"])
	}
	if kidOf(t, compact) != k.Kid() {
		t.Errorf("kid = %q, want the published kid %q", kidOf(t, compact), k.Kid())
	}
}

// TestBuildIDToken_TamperAtHash: at_hash is wrong; iss/aud/nonce/exp and
// the signature are exactly as the baseline.
func TestBuildIDToken_TamperAtHash(t *testing.T) {
	k := testKeySet(t)
	tamper := newTamperSet([]config.TamperTarget{config.TamperAtHash})
	in := baseIDTokenInput(k, tamper)
	compact, err := buildIDToken(k, in)
	if err != nil {
		t.Fatalf("buildIDToken: %v", err)
	}
	claims := decodeJWSPayload(t, compact)

	correct := atHashS256(in.accessToken)
	gotAtHash, _ := claims["at_hash"].(string)
	if gotAtHash == correct {
		t.Fatalf("at_hash = %q, want it to differ from the correct value %q", gotAtHash, correct)
	}
	if len(gotAtHash) != len(correct) {
		t.Errorf("tampered at_hash length = %d, want %d (still base64url-shaped)", len(gotAtHash), len(correct))
	}
	if _, err := base64.RawURLEncoding.DecodeString(gotAtHash); err != nil {
		t.Errorf("tampered at_hash is not valid base64url: %v", err)
	}

	if claims["iss"] != in.issuer {
		t.Errorf("iss = %v, want untouched %v", claims["iss"], in.issuer)
	}
	if claims["aud"] != in.audience {
		t.Errorf("aud = %v, want untouched %v", claims["aud"], in.audience)
	}
	if claims["nonce"] != in.nonce {
		t.Errorf("nonce = %v, want untouched %v", claims["nonce"], in.nonce)
	}
	if kidOf(t, compact) != k.Kid() {
		t.Errorf("kid = %q, want the published kid %q (signature must stay valid)", kidOf(t, compact), k.Kid())
	}
	assertVerifies(t, k, compact)
}

func TestBuildIDToken_TamperIss(t *testing.T) {
	k := testKeySet(t)
	tamper := newTamperSet([]config.TamperTarget{config.TamperIss})
	in := baseIDTokenInput(k, tamper)
	compact, err := buildIDToken(k, in)
	if err != nil {
		t.Fatalf("buildIDToken: %v", err)
	}
	claims := decodeJWSPayload(t, compact)

	gotIss, _ := claims["iss"].(string)
	if gotIss == in.issuer {
		t.Fatalf("iss = %q, want it to differ from %q", gotIss, in.issuer)
	}
	if !strings.HasPrefix(gotIss, "https://") {
		t.Errorf("tampered iss = %q, want it to remain a well-formed URL (https:// prefix)", gotIss)
	}

	if claims["aud"] != in.audience {
		t.Errorf("aud = %v, want untouched %v", claims["aud"], in.audience)
	}
	if claims["nonce"] != in.nonce {
		t.Errorf("nonce = %v, want untouched %v", claims["nonce"], in.nonce)
	}
	if claims["at_hash"] != atHashS256(in.accessToken) {
		t.Errorf("at_hash = %v, want untouched", claims["at_hash"])
	}
	assertVerifies(t, k, compact)
}

func TestBuildIDToken_TamperAud(t *testing.T) {
	k := testKeySet(t)
	tamper := newTamperSet([]config.TamperTarget{config.TamperAud})
	in := baseIDTokenInput(k, tamper)
	compact, err := buildIDToken(k, in)
	if err != nil {
		t.Fatalf("buildIDToken: %v", err)
	}
	claims := decodeJWSPayload(t, compact)

	gotAud, _ := claims["aud"].(string)
	if gotAud == in.audience {
		t.Fatalf("aud = %q, want it to differ from %q", gotAud, in.audience)
	}

	if claims["iss"] != in.issuer {
		t.Errorf("iss = %v, want untouched %v", claims["iss"], in.issuer)
	}
	if claims["nonce"] != in.nonce {
		t.Errorf("nonce = %v, want untouched %v", claims["nonce"], in.nonce)
	}
	if claims["at_hash"] != atHashS256(in.accessToken) {
		t.Errorf("at_hash = %v, want untouched", claims["at_hash"])
	}
	assertVerifies(t, k, compact)
}

func TestBuildIDToken_TamperNonce_WhenLoginHadOne(t *testing.T) {
	k := testKeySet(t)
	tamper := newTamperSet([]config.TamperTarget{config.TamperNonce})
	in := baseIDTokenInput(k, tamper)
	compact, err := buildIDToken(k, in)
	if err != nil {
		t.Fatalf("buildIDToken: %v", err)
	}
	claims := decodeJWSPayload(t, compact)

	gotNonce, _ := claims["nonce"].(string)
	if gotNonce == in.nonce {
		t.Fatalf("nonce = %q, want it to differ from %q", gotNonce, in.nonce)
	}

	if claims["iss"] != in.issuer {
		t.Errorf("iss = %v, want untouched %v", claims["iss"], in.issuer)
	}
	if claims["aud"] != in.audience {
		t.Errorf("aud = %v, want untouched %v", claims["aud"], in.audience)
	}
	if claims["at_hash"] != atHashS256(in.accessToken) {
		t.Errorf("at_hash = %v, want untouched", claims["at_hash"])
	}
	assertVerifies(t, k, compact)
}

// TestBuildIDToken_TamperNonce_WhenLoginHadNone documents and pins the
// decision: tamper: [nonce] has nothing to corrupt when the login sent
// no nonce (e.g. no nonce at /authorize, or a refresh-minted ID token,
// which never carries one -- token.go's issueFromRefresh). It is a
// deliberate no-op, not an error and not a fabricated claim.
func TestBuildIDToken_TamperNonce_WhenLoginHadNone(t *testing.T) {
	k := testKeySet(t)
	tamper := newTamperSet([]config.TamperTarget{config.TamperNonce})
	in := baseIDTokenInput(k, tamper)
	in.nonce = ""
	compact, err := buildIDToken(k, in)
	if err != nil {
		t.Fatalf("buildIDToken: %v", err)
	}
	claims := decodeJWSPayload(t, compact)

	if _, present := claims["nonce"]; present {
		t.Fatalf("nonce claim present (%v) for a login with no nonce; tamper: [nonce] must not fabricate one", claims["nonce"])
	}
	assertVerifies(t, k, compact)
}

// TestBuildIDToken_TamperExp: exp becomes a JSON string (wrong type),
// every other claim -- including a correctly-typed iat -- is untouched,
// and the signature still verifies. This is the check that
// distinguishes tamper: [exp] from id_token_ttl: -5m: the raw JSON
// literal for "exp" must not be a bare number.
func TestBuildIDToken_TamperExp(t *testing.T) {
	k := testKeySet(t)
	tamper := newTamperSet([]config.TamperTarget{config.TamperExp})
	in := baseIDTokenInput(k, tamper)
	compact, err := buildIDToken(k, in)
	if err != nil {
		t.Fatalf("buildIDToken: %v", err)
	}

	parts := strings.Split(compact, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decoding payload: %v", err)
	}
	var rawClaims map[string]json.RawMessage
	if err := json.Unmarshal(raw, &rawClaims); err != nil {
		t.Fatalf("unmarshaling raw claims: %v", err)
	}
	expLiteral := strings.TrimSpace(string(rawClaims["exp"]))
	if !strings.HasPrefix(expLiteral, `"`) {
		t.Fatalf("exp JSON literal = %s, want a quoted string, not a bare number", expLiteral)
	}
	var expString string
	if err := json.Unmarshal(rawClaims["exp"], &expString); err != nil {
		t.Fatalf("exp is not even a valid JSON string: %v", err)
	}
	if expString != "tampered-1700003600" {
		t.Errorf("exp string value = %q, want %q", expString, "tampered-1700003600")
	}

	claims := decodeJWSPayload(t, compact)
	if claims["iss"] != in.issuer {
		t.Errorf("iss = %v, want untouched %v", claims["iss"], in.issuer)
	}
	if claims["aud"] != in.audience {
		t.Errorf("aud = %v, want untouched %v", claims["aud"], in.audience)
	}
	if claims["nonce"] != in.nonce {
		t.Errorf("nonce = %v, want untouched %v", claims["nonce"], in.nonce)
	}
	if claims["at_hash"] != atHashS256(in.accessToken) {
		t.Errorf("at_hash = %v, want untouched", claims["at_hash"])
	}
	if _, ok := claims["iat"].(float64); !ok {
		t.Errorf("iat = %T, want an untouched JSON number", claims["iat"])
	}
	assertVerifies(t, k, compact)
}

// TestBuildIDToken_TamperSignature: the kid is the unpublished one (and
// therefore absent from JWKS), while every claim -- at_hash included, so
// signature-tampering provably does not also break at_hash -- is exactly
// what a non-tampered build would have produced.
func TestBuildIDToken_TamperSignature(t *testing.T) {
	k := testKeySet(t)
	tamper := newTamperSet([]config.TamperTarget{config.TamperSignature})
	in := baseIDTokenInput(k, tamper)
	compact, err := buildIDToken(k, in)
	if err != nil {
		t.Fatalf("buildIDToken: %v", err)
	}

	gotKid := kidOf(t, compact)
	if gotKid != k.UnpublishedKid() {
		t.Fatalf("kid = %q, want the unpublished kid %q", gotKid, k.UnpublishedKid())
	}
	if gotKid == k.Kid() {
		t.Fatalf("kid = %q, must not equal the published kid", gotKid)
	}

	set, err := jwk.Parse(k.JWKS())
	if err != nil {
		t.Fatalf("parsing JWKS: %v", err)
	}
	if _, ok := set.LookupKeyID(gotKid); ok {
		t.Fatalf("kid %q unexpectedly present in the served JWKS", gotKid)
	}
	if _, err := jws.Verify([]byte(compact), jws.WithKeySet(set)); err == nil {
		t.Fatal("jws.Verify against the published JWKS unexpectedly succeeded for a signature-tampered token")
	}

	claims := decodeJWSPayload(t, compact)
	if claims["iss"] != in.issuer {
		t.Errorf("iss = %v, want untouched %v", claims["iss"], in.issuer)
	}
	if claims["aud"] != in.audience {
		t.Errorf("aud = %v, want untouched %v", claims["aud"], in.audience)
	}
	if claims["nonce"] != in.nonce {
		t.Errorf("nonce = %v, want untouched %v", claims["nonce"], in.nonce)
	}
	// The ordering invariant: at_hash must still be computed over the
	// access token as the client will actually receive it, even though
	// that token (in a real login) may itself be signature-tampered too.
	// buildIDToken hashes in.accessToken as given, so this always holds
	// regardless of which key signed the access token.
	if claims["at_hash"] != atHashS256(in.accessToken) {
		t.Errorf("at_hash = %v, want %v (signature tampering must not also break at_hash)", claims["at_hash"], atHashS256(in.accessToken))
	}
}

// TestBuildIDToken_Combination_AudAndAtHash: two tamper values at once,
// each corrupting only its own claim.
func TestBuildIDToken_Combination_AudAndAtHash(t *testing.T) {
	k := testKeySet(t)
	tamper := newTamperSet([]config.TamperTarget{config.TamperAud, config.TamperAtHash})
	in := baseIDTokenInput(k, tamper)
	compact, err := buildIDToken(k, in)
	if err != nil {
		t.Fatalf("buildIDToken: %v", err)
	}
	claims := decodeJWSPayload(t, compact)

	gotAud, _ := claims["aud"].(string)
	if gotAud == in.audience {
		t.Fatalf("aud = %q, want it to differ", gotAud)
	}
	gotAtHash, _ := claims["at_hash"].(string)
	if gotAtHash == atHashS256(in.accessToken) {
		t.Fatalf("at_hash = %q, want it to differ", gotAtHash)
	}

	if claims["iss"] != in.issuer {
		t.Errorf("iss = %v, want untouched %v", claims["iss"], in.issuer)
	}
	if claims["nonce"] != in.nonce {
		t.Errorf("nonce = %v, want untouched %v", claims["nonce"], in.nonce)
	}
	if kidOf(t, compact) != k.Kid() {
		t.Errorf("kid = %q, want the published kid (signature not part of this combination)", kidOf(t, compact))
	}
	assertVerifies(t, k, compact)
}

// --- accessTokenInput: tamper applies only to claims a JWT access token
// actually carries (iss, aud, exp, signature) -- at_hash and nonce have
// no analogue there, per jwt.go's buildAccessToken doc comment.

func TestBuildAccessToken_NoTamper_Baseline(t *testing.T) {
	k := testKeySet(t)
	in := baseAccessTokenInput(nil)
	compact, err := buildAccessToken(k, in)
	if err != nil {
		t.Fatalf("buildAccessToken: %v", err)
	}
	claims := decodeJWSPayload(t, compact)
	if claims["iss"] != in.issuer || claims["aud"] != in.audience {
		t.Fatalf("claims = %+v, want untampered iss/aud", claims)
	}
	if kidOf(t, compact) != k.Kid() {
		t.Errorf("kid = %q, want published kid", kidOf(t, compact))
	}
}

func TestBuildAccessToken_TamperIssAudExp(t *testing.T) {
	k := testKeySet(t)
	tamper := newTamperSet([]config.TamperTarget{config.TamperIss, config.TamperAud, config.TamperExp})
	in := baseAccessTokenInput(tamper)
	compact, err := buildAccessToken(k, in)
	if err != nil {
		t.Fatalf("buildAccessToken: %v", err)
	}
	claims := decodeJWSPayload(t, compact)

	if claims["iss"] == in.issuer {
		t.Errorf("iss unchanged, want it tampered")
	}
	if claims["aud"] == in.audience {
		t.Errorf("aud unchanged, want it tampered")
	}
	if _, ok := claims["exp"].(float64); ok {
		t.Errorf("exp is still a JSON number, want a tampered (string) exp")
	}
	if claims["client_id"] != in.clientID {
		t.Errorf("client_id = %v, want untouched %v", claims["client_id"], in.clientID)
	}
	if claims["scope"] != in.scope {
		t.Errorf("scope = %v, want untouched %v", claims["scope"], in.scope)
	}
	assertVerifies(t, k, compact)
}

func TestBuildAccessToken_TamperSignature(t *testing.T) {
	k := testKeySet(t)
	tamper := newTamperSet([]config.TamperTarget{config.TamperSignature})
	in := baseAccessTokenInput(tamper)
	compact, err := buildAccessToken(k, in)
	if err != nil {
		t.Fatalf("buildAccessToken: %v", err)
	}
	gotKid := kidOf(t, compact)
	if gotKid != k.UnpublishedKid() {
		t.Fatalf("kid = %q, want unpublished kid %q", gotKid, k.UnpublishedKid())
	}
	set, err := jwk.Parse(k.JWKS())
	if err != nil {
		t.Fatalf("parsing JWKS: %v", err)
	}
	if _, ok := set.LookupKeyID(gotKid); ok {
		t.Fatalf("kid %q unexpectedly present in JWKS", gotKid)
	}
}

// assertVerifies confirms compact verifies against k's published JWKS --
// the "everything else stays valid, including the signature" half of the
// tamper contract for every value except tamper: [signature] itself.
func assertVerifies(t *testing.T, k *keys.Set, compact string) {
	t.Helper()
	set, err := jwk.Parse(k.JWKS())
	if err != nil {
		t.Fatalf("parsing JWKS: %v", err)
	}
	if _, err := jws.Verify([]byte(compact), jws.WithKeySet(set)); err != nil {
		t.Fatalf("jws.Verify against the published JWKS: %v (signature must stay valid for this tamper value)", err)
	}
}
