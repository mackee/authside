package oidcop

import "testing"

// TestAtHashS256 checks atHashS256 against a hand-computed vector: for
// access token "AT-test-token-1234567890",
//
//	python3 -c "
//	import hashlib, base64
//	token = 'AT-test-token-1234567890'
//	h = hashlib.sha256(token.encode('ascii')).digest()
//	left = h[:16]
//	print(base64.urlsafe_b64encode(left).rstrip(b'=').decode())"
//
// prints Q6WW1_Tj0VQet9_EQFM4Kg -- SHA-256 over the token's ASCII bytes,
// left half (16 of the 32 bytes) of the digest, base64url with no
// padding: the exact algorithm go-oidc's IDToken.VerifyAccessToken uses.
func TestAtHashS256(t *testing.T) {
	const accessToken = "AT-test-token-1234567890"
	const want = "Q6WW1_Tj0VQet9_EQFM4Kg"

	got := atHashS256(accessToken)
	if got != want {
		t.Fatalf("atHashS256(%q) = %q, want %q", accessToken, got, want)
	}
}
