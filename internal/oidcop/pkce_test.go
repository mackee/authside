package oidcop

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/mackee/authside/internal/httpx"
)

func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestCheckPKCE(t *testing.T) {
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := s256(verifier)

	tests := []struct {
		name                string
		codeChallenge       string
		codeChallengeMethod string
		verifier            string
		wantErr             bool
	}{
		{
			name: "no PKCE at all is fine",
		},
		{
			name:                "S256 correct verifier succeeds",
			codeChallenge:       challenge,
			codeChallengeMethod: codeChallengeMethodS256,
			verifier:            verifier,
		},
		{
			name:                "S256 wrong verifier fails",
			codeChallenge:       challenge,
			codeChallengeMethod: codeChallengeMethodS256,
			verifier:            "this-is-not-the-right-verifier-------------",
			wantErr:             true,
		},
		{
			name:                "plain method is rejected outright",
			codeChallenge:       verifier, // plain: challenge == verifier
			codeChallengeMethod: "plain",
			verifier:            verifier,
			wantErr:             true,
		},
		{
			name:                "challenge without verifier is invalid_grant",
			codeChallenge:       challenge,
			codeChallengeMethod: codeChallengeMethodS256,
			verifier:            "",
			wantErr:             true,
		},
		{
			name:          "verifier without challenge is invalid_grant",
			codeChallenge: "",
			verifier:      verifier,
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkPKCE(tt.codeChallenge, tt.codeChallengeMethod, tt.verifier)
			if tt.wantErr && err == nil {
				t.Fatalf("checkPKCE() = nil, want an error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("checkPKCE() = %v, want nil", err)
			}
			if err != nil {
				oerr, ok := err.(*httpx.OIDCError)
				if !ok {
					t.Fatalf("error type = %T, want *httpx.OIDCError", err)
				}
				if oerr.Code != httpx.ErrInvalidGrant {
					t.Fatalf("error code = %q, want invalid_grant", oerr.Code)
				}
			}
		})
	}
}
