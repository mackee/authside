package oidcop

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/mackee/authside/config"
	"github.com/mackee/authside/internal/keys"
)

// idTokenInput carries everything buildIDToken needs to mint one ID token.
type idTokenInput struct {
	issuer       string
	subject      string
	audience     string // client_id
	nonce        string // empty when the login had none
	nbf          *time.Time
	issuedAt     time.Time
	expiresAt    time.Time // may be before issuedAt: a negative id_token_ttl mints an already-expired token, on purpose
	accessToken  string    // for at_hash
	customClaims map[string]any
	tamper       tamperSet // this target's tamper: values (README "Negative testing"), nil when none configured
}

// buildIDToken assembles and signs an RS256 ID token.
//
// at_hash is always present (README "Tokens"): left half of SHA-256 over
// the access token's ASCII bytes, base64url-encoded without padding --
// go-oidc's IDToken.VerifyAccessToken rejects a token with no at_hash at
// all, so this is not optional even though the first intended consumer
// never calls VerifyAccessToken itself.
//
// tamper (README "Negative testing") corrupts exactly the
// claims/signature its values name, applied after every other claim is
// set to its normal, correct value -- see tamper.go for each corruption
// and jwt_test.go / root package tamper_test.go for the per-value proof
// that everything else stays valid. nonce is only corrupted when the
// login actually sent one: tamper: [nonce] on a target/flow where nonce
// is already absent (no nonce at /authorize, or the refresh grant, which
// never carries one -- see token.go's issueFromRefresh) has nothing to
// corrupt and is a deliberate no-op, since there is no way to "corrupt" a
// claim that is not there without fabricating one a real IdP would never
// have sent in the first place.
func buildIDToken(k *keys.Set, in idTokenInput) (string, error) {
	claims := make(map[string]any, len(in.customClaims)+8)
	for key, v := range in.customClaims {
		claims[key] = v
	}

	// Reserved claims are set after the custom ones so a custom claim can
	// never accidentally (or maliciously, via a test's own config)
	// clobber a protocol-level claim.
	claims["iss"] = in.issuer
	claims["sub"] = in.subject
	claims["aud"] = in.audience
	claims["iat"] = in.issuedAt.Unix()
	claims["exp"] = in.expiresAt.Unix()
	if in.nbf != nil {
		claims["nbf"] = in.nbf.Unix()
	}
	if in.nonce != "" {
		claims["nonce"] = in.nonce
	}
	claims["at_hash"] = atHashS256(in.accessToken)

	if in.tamper.has(config.TamperIss) {
		claims["iss"] = tamperString(in.issuer)
	}
	if in.tamper.has(config.TamperAud) {
		claims["aud"] = tamperString(in.audience)
	}
	if in.tamper.has(config.TamperNonce) && in.nonce != "" {
		claims["nonce"] = tamperString(in.nonce)
	}
	if in.tamper.has(config.TamperAtHash) {
		claims["at_hash"] = tamperAtHash(claims["at_hash"].(string))
	}
	if in.tamper.has(config.TamperExp) {
		claims["exp"] = tamperExpValue(in.expiresAt.Unix())
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("oidcop: marshal id_token claims: %w", err)
	}

	sign := k.Sign
	if in.tamper.has(config.TamperSignature) {
		sign = k.SignUnpublished
	}
	tok, err := sign(payload)
	if err != nil {
		return "", fmt.Errorf("oidcop: sign id_token: %w", err)
	}
	return tok, nil
}

// accessTokenInput carries everything buildAccessToken needs to mint one
// JWT access token.
type accessTokenInput struct {
	issuer    string
	subject   string
	audience  string // client_id
	clientID  string
	scope     string
	issuedAt  time.Time
	expiresAt time.Time // may be before issuedAt, same as idTokenInput.expiresAt
	tamper    tamperSet // this target's tamper: values, nil when none configured
}

// buildAccessToken assembles and signs an RS256 JWT access token
// (access_token: jwt, the default). It is reached only through token.go's
// mintAccessToken, which is where the access_token: jwt|opaque branch
// lives -- an opaque access token never gets here, and consequently
// carries none of the tamper corruptions below; see that function for
// why that is the intended behaviour rather than a gap.
//
// tamper is applied to every claim the access token actually carries:
// iss, aud and exp (signature the same way as the ID token -- see
// buildIDToken's doc comment). at_hash and nonce have no equivalent here
// -- a JWT access token carries neither claim in this package's shape --
// so those two values only ever affect the ID token. That is the
// deliberate scope: tamper applies to every claim a JWT contains,
// consistently, across both tokens.
func buildAccessToken(k *keys.Set, in accessTokenInput) (string, error) {
	claims := map[string]any{
		"iss":       in.issuer,
		"sub":       in.subject,
		"aud":       in.audience,
		"client_id": in.clientID,
		"scope":     in.scope,
		"iat":       in.issuedAt.Unix(),
		"exp":       in.expiresAt.Unix(),
	}

	if in.tamper.has(config.TamperIss) {
		claims["iss"] = tamperString(in.issuer)
	}
	if in.tamper.has(config.TamperAud) {
		claims["aud"] = tamperString(in.audience)
	}
	if in.tamper.has(config.TamperExp) {
		claims["exp"] = tamperExpValue(in.expiresAt.Unix())
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("oidcop: marshal access_token claims: %w", err)
	}

	sign := k.Sign
	if in.tamper.has(config.TamperSignature) {
		sign = k.SignUnpublished
	}
	tok, err := sign(payload)
	if err != nil {
		return "", fmt.Errorf("oidcop: sign access_token: %w", err)
	}
	return tok, nil
}

// atHashS256 computes at_hash for the RS256 case: SHA-256 over the access
// token's ASCII bytes, left half of the digest, base64url with no padding
// (verified against x/oauth2/go-oidc's own IDToken.VerifyAccessToken).
func atHashS256(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	left := sum[:len(sum)/2]
	return base64.RawURLEncoding.EncodeToString(left)
}
