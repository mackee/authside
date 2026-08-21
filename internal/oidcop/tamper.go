package oidcop

import (
	"encoding/base64"
	"strconv"

	"github.com/mackee/authside/config"
)

// tamperSet is the set of config.TamperTarget values one target's
// `tamper:` list requested (README "Negative testing"). A nil tamperSet
// (the common case: no tamper: configured) behaves exactly like an empty
// one -- has() returns false for everything -- so callers never need a
// nil check of their own.
type tamperSet map[config.TamperTarget]bool

// newTamperSet builds a tamperSet from a target's config.Target.Tamper.
// It returns nil for an empty/nil input, which is fine: tamperSet.has on
// a nil map is always false.
func newTamperSet(values []config.TamperTarget) tamperSet {
	if len(values) == 0 {
		return nil
	}
	s := make(tamperSet, len(values))
	for _, v := range values {
		s[v] = true
	}
	return s
}

func (s tamperSet) has(v config.TamperTarget) bool {
	return s[v]
}

// tamperedMarker is appended to a claim value tamper corrupts, so the
// corruption is visible when eyeballing a decoded token (this package's
// own "Loud about being fake" habit, applied to negative testing too),
// while leaving the value a well-formed string of the same kind (a URL
// with an extra path segment is still a URL; a client_id with a suffix is
// still a plausible client_id).
const tamperedMarker = "-tampered"

// tamperString corrupts good by appending tamperedMarker, guaranteeing
// the result differs from good (used for iss, aud and nonce: each stays
// a syntactically ordinary string, just the wrong one).
func tamperString(good string) string {
	return good + tamperedMarker
}

// tamperAtHash corrupts a correctly-computed at_hash into a
// syntactically plausible but wrong one: it decodes the base64url
// (unpadded) value, flips every bit of the first byte, and re-encodes
// with the same alphabet, so the result has identical length and
// charset -- a client checking only "is at_hash present and
// base64url-shaped" would not notice, but the hash comparison in
// go-oidc's VerifyAccessToken fails as a mismatch, not as "claim absent"
// (errNoAtHash), which is the distinction the README's negative-testing
// contract needs: omitting at_hash breaks correct clients (go-oidc's own
// IDToken.VerifyAccessToken treats an absent claim as an error, per
// jwt.go's buildIDToken comment), so tamper must corrupt the value,
// never drop it.
func tamperAtHash(good string) string {
	raw, err := base64.RawURLEncoding.DecodeString(good)
	if err != nil || len(raw) == 0 {
		// atHashS256 always produces a valid, non-empty base64url string,
		// so this is unreachable in practice; fall back to a value that
		// is still wrong but keeps the function total.
		return tamperString(good)
	}
	raw[0] ^= 0xFF
	return base64.RawURLEncoding.EncodeToString(raw)
}

// tamperExpValue re-encodes an exp claim's unix-seconds value as a JSON
// *string* instead of a JSON number: encoding/json quotes any Go string
// value automatically, so setting claims["exp"] to this return value is
// enough to make the marshaled "exp" a string in the token's payload.
//
// The string is deliberately NOT just the digits of the timestamp.
// go-oidc's claims struct (its jsonTime type) decodes exp
// via encoding/json's json.Number, and json.Number -- confirmed
// empirically against coreos/go-oidc/v3@v3.20.0 and the Go 1.26 standard
// library -- silently accepts a *quoted* string that happens to match
// the JSON number-literal grammar exactly (json.Unmarshal(`"1700003600"`,
// &n) succeeds with n == "1700003600": encoding/json's literal decoder
// has a quoted-number fallback for exactly this shape). A bare-digit
// string therefore does NOT reproduce the intended defect: it would
// verify as if exp were a normal number. Prefixing with a non-digit
// marker makes the value fail that same number-literal grammar (the
// literal no longer starts with `-` or a digit), so
// json.Unmarshal(payload, &token) fails outright with "invalid number
// literal" before any expiry (or other claim) check ever runs.
//
// This is deliberately a different defect from id_token_ttl: -5m
// (README "Refresh tokens" / "Scenarios are configuration"), which mints
// a structurally normal, valid-but-past exp through the ordinary code
// path -- a real client rejects that with go-oidc's TokenExpiredError.
// Here the client instead sees "oidc: failed to unmarshal claims: ...",
// never "expired" -- a genuinely different failure a client's error
// handling should also be exercised against, which is exactly why
// internal/keys.Sign takes raw JSON rather than typed claims (this
// corruption could not be expressed as a valid time.Time at all).
func tamperExpValue(unixSeconds int64) string {
	return "tampered-" + strconv.FormatInt(unixSeconds, 10)
}
