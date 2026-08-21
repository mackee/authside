package oidcop

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// codeChallengeMethodS256 is the only code_challenge_method authside
// verifies (README "Supported flows": "S256 only; plain is rejected").
const codeChallengeMethodS256 = "S256"

// checkPKCE verifies the code_verifier presented at /token against the
// code_challenge (and code_challenge_method) recorded at /authorize time
// for this authorization code.
//
// PKCE is verified-when-used, never required:
//
//   - No challenge was recorded and no verifier is presented: fine, this
//     client simply did not use PKCE.
//   - A challenge was recorded but no verifier is presented, or a verifier
//     is presented but no challenge was recorded: invalid_grant -- mixing
//     the two halves is always rejected.
//   - A challenge was recorded with a method other than "S256" (i.e.
//     "plain", or anything else RFC 7636 allows): invalid_grant,
//     regardless of what verifier is presented. authside never verifies
//     "plain".
//   - A challenge was recorded with method "S256": the verifier must hash
//     (SHA-256, base64url, unpadded) to exactly the recorded challenge.
func checkPKCE(codeChallenge, codeChallengeMethod, verifier string) error {
	switch {
	case codeChallenge == "" && verifier == "":
		return nil
	case codeChallenge == "" && verifier != "":
		return errInvalidGrantf("code_verifier was presented at /token but no code_challenge was sent to /authorize for this code")
	case codeChallenge != "" && verifier == "":
		return errInvalidGrantf("code_challenge was sent to /authorize for this code; code_verifier is required at /token")
	}

	if codeChallengeMethod != codeChallengeMethodS256 {
		return errInvalidGrantf("code_challenge_method %q is not supported; authside only verifies S256", codeChallengeMethod)
	}

	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(computed), []byte(codeChallenge)) != 1 {
		return errInvalidGrantf("code_verifier does not match the code_challenge sent to /authorize")
	}
	return nil
}
