package authside_test

// This file is the client-level exit test for the tamper: feature
// (README "Negative testing"): for each of the six tamper: values, a
// *real* coreos/go-oidc/v3 verifier rejects the tampered token, for the
// specific reason the README promises -- and, load-bearing for the
// "exactly one thing corrupts" contract, everything else about the same
// token still checks out (a positive control target with no tamper: set
// at all, plus per-value "skip the one broken check" assertions using
// go-oidc's own Config.Skip* flags, or a manual claim/signature
// inspection where go-oidc has no such flag).
//
// It reuses this package's existing test helpers (noFollowClient,
// setAuthsideSubCookie, driveAuthorize) from authside_test.go -- both
// files are package authside_test, so nothing needs to be exported or
// duplicated.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"golang.org/x/oauth2"

	"github.com/mackee/authside"
	"github.com/mackee/authside/config"
)

const tamperClientID = "app"
const tamperClientSecret = "secret"
const tamperRedirectURI = "http://app.invalid/callback"

// tamperTarget builds one config.Target sharing the same client/user
// across every scenario, differing only in mount/issuer and tamper:
// (mirrors the README's "Scenarios are configuration" YAML-anchor shape,
// expressed in Go since these tests build *authside.Config directly
// rather than parsing YAML).
func tamperTarget(name, mount, baseURL string, tamper []config.TamperTarget) config.Target {
	return config.Target{
		Name:   name,
		Type:   "oidc",
		Issuer: baseURL + mount,
		Mount:  mount,
		Login:  config.LoginAuto,
		Tamper: tamper,
		Clients: []config.Client{
			{ClientID: tamperClientID, ClientSecret: tamperClientSecret, RedirectURIs: []string{tamperRedirectURI}},
		},
		Users: []config.User{
			{Sub: "user-1", Claims: map[string]any{"email": "alice@example.com"}},
		},
	}
}

// tamperLogin drives a full authorization_code login against mount and
// returns the resulting *oidc.Provider (built via ordinary discovery, so
// its notion of "issuer" is the target's *configured* issuer -- the
// correct one, never itself tampered: only the minted token's claims
// are) and the raw token response.
func tamperLogin(t *testing.T, ctx context.Context, baseURL, mount, nonce string) (*oidc.Provider, *oauth2.Token) {
	t.Helper()
	issuer := baseURL + mount

	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		t.Fatalf("oidc.NewProvider(%s): %v", issuer, err)
	}
	oauth2Config := &oauth2.Config{
		ClientID:     tamperClientID,
		ClientSecret: tamperClientSecret,
		RedirectURL:  tamperRedirectURI,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID},
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	setAuthsideSubCookie(t, jar, baseURL, "user-1")
	client := noFollowClient(jar)

	code, _ := driveAuthorize(t, client, issuer, tamperClientID, tamperRedirectURI, "st", nonce)
	tok, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		t.Fatalf("Exchange(%s): %v", issuer, err)
	}
	return provider, tok
}

func rawIDTokenOf(t *testing.T, tok *oauth2.Token) string {
	t.Helper()
	raw, ok := tok.Extra("id_token").(string)
	if !ok || raw == "" {
		t.Fatalf("token response has no id_token")
	}
	return raw
}

// decodeCompactJWTPayload base64url-decodes a compact JWT's payload
// segment into a map, with no signature check -- used only where go-oidc
// itself refuses to parse the token at all (tamper: [exp]) and the "rest
// stays valid" proof has to be done by hand.
func decodeCompactJWTPayload(t *testing.T, compact string) map[string]any {
	t.Helper()
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("compact JWT has %d parts, want 3", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decoding payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("unmarshaling payload %s: %v", raw, err)
	}
	return claims
}

func kidOfCompactJWT(t *testing.T, compact string) string {
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

func fetchJWKS(t *testing.T, jwksURI string) jwk.Set {
	t.Helper()
	resp, err := http.Get(jwksURI)
	if err != nil {
		t.Fatalf("GET %s: %v", jwksURI, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading JWKS body: %v", err)
	}
	set, err := jwk.Parse(body)
	if err != nil {
		t.Fatalf("parsing JWKS: %v", err)
	}
	return set
}

// TestM8_Tamper is the single server hosting one target per tamper
// scenario plus a positive control, exactly the "targets are independent
// by construction" model README "Scenarios are configuration" describes.
func TestM8_Tamper(t *testing.T) {
	srv := httptest.NewUnstartedServer(nil)
	baseURL := "http://" + srv.Listener.Addr().String()

	cfg := &authside.Config{
		Targets: []config.Target{
			tamperTarget("plain", "/plain", baseURL, nil),
			tamperTarget("t-at-hash", "/t-at-hash", baseURL, []config.TamperTarget{config.TamperAtHash}),
			tamperTarget("t-iss", "/t-iss", baseURL, []config.TamperTarget{config.TamperIss}),
			tamperTarget("t-aud", "/t-aud", baseURL, []config.TamperTarget{config.TamperAud}),
			tamperTarget("t-nonce", "/t-nonce", baseURL, []config.TamperTarget{config.TamperNonce}),
			tamperTarget("t-exp", "/t-exp", baseURL, []config.TamperTarget{config.TamperExp}),
			tamperTarget("t-signature", "/t-signature", baseURL, []config.TamperTarget{config.TamperSignature}),
			tamperTarget("t-combo", "/t-combo", baseURL, []config.TamperTarget{config.TamperAud, config.TamperAtHash}),
		},
	}
	handler, err := authside.New(cfg)
	if err != nil {
		t.Fatalf("authside.New: %v", err)
	}
	srv.Config.Handler = handler
	srv.Start()
	defer srv.Close()

	ctx := context.Background()

	// --- Positive control: the same shape, no tamper: at all. Without
	// this, none of the failures below prove anything (they could just
	// as well be a bug that breaks every token).
	t.Run("PositiveControl_NoTamper", func(t *testing.T) {
		provider, tok := tamperLogin(t, ctx, baseURL, "/plain", "the-nonce-value")
		raw := rawIDTokenOf(t, tok)
		verifier := provider.Verifier(&oidc.Config{ClientID: tamperClientID})
		idTok, err := verifier.Verify(ctx, raw)
		if err != nil {
			t.Fatalf("Verify() on an untampered token = %v, want success", err)
		}
		if idTok.Nonce != "the-nonce-value" {
			t.Fatalf("nonce = %q, want %q", idTok.Nonce, "the-nonce-value")
		}
		if err := idTok.VerifyAccessToken(tok.AccessToken); err != nil {
			t.Fatalf("VerifyAccessToken() on an untampered token = %v, want success", err)
		}
	})

	// --- at_hash: Verify() (which does not check at_hash) still
	// succeeds; VerifyAccessToken() fails with the *mismatch* error, not
	// "claim absent" -- the isolation the README's negative-testing
	// contract needs (omitting at_hash breaks correct clients; tamper
	// must corrupt the value, never drop it).
	t.Run("AtHash", func(t *testing.T) {
		provider, tok := tamperLogin(t, ctx, baseURL, "/t-at-hash", "the-nonce-value")
		raw := rawIDTokenOf(t, tok)
		verifier := provider.Verifier(&oidc.Config{ClientID: tamperClientID})
		idTok, err := verifier.Verify(ctx, raw)
		if err != nil {
			t.Fatalf("Verify() = %v, want success (Verify does not check at_hash)", err)
		}
		if idTok.Nonce != "the-nonce-value" {
			t.Errorf("nonce = %q, want untouched %q", idTok.Nonce, "the-nonce-value")
		}
		err = idTok.VerifyAccessToken(tok.AccessToken)
		if err == nil {
			t.Fatal("VerifyAccessToken() succeeded, want an at_hash mismatch")
		}
		const wantMsg = "access token hash does not match value in ID token"
		if err.Error() != wantMsg {
			t.Fatalf("VerifyAccessToken() error = %q, want %q (must be a mismatch, not \"claim absent\")", err.Error(), wantMsg)
		}
	})

	// --- iss: Verify() fails with the "different provider" error;
	// SkipIssuerCheck alone makes it succeed, proving nothing else is
	// broken.
	t.Run("Iss", func(t *testing.T) {
		provider, tok := tamperLogin(t, ctx, baseURL, "/t-iss", "the-nonce-value")
		raw := rawIDTokenOf(t, tok)

		_, err := provider.Verifier(&oidc.Config{ClientID: tamperClientID}).Verify(ctx, raw)
		if err == nil {
			t.Fatal("Verify() succeeded, want an issuer mismatch")
		}
		if !strings.Contains(err.Error(), "issued by a different provider") {
			t.Fatalf("Verify() error = %v, want it to mention \"issued by a different provider\"", err)
		}

		idTok, err := provider.Verifier(&oidc.Config{ClientID: tamperClientID, SkipIssuerCheck: true}).Verify(ctx, raw)
		if err != nil {
			t.Fatalf("Verify() with SkipIssuerCheck = %v, want success (only iss is broken)", err)
		}
		if err := idTok.VerifyAccessToken(tok.AccessToken); err != nil {
			t.Fatalf("VerifyAccessToken() = %v, want success", err)
		}
	})

	// --- aud: Verify() fails with the "expected audience" error;
	// SkipClientIDCheck alone makes it succeed.
	t.Run("Aud", func(t *testing.T) {
		provider, tok := tamperLogin(t, ctx, baseURL, "/t-aud", "the-nonce-value")
		raw := rawIDTokenOf(t, tok)

		_, err := provider.Verifier(&oidc.Config{ClientID: tamperClientID}).Verify(ctx, raw)
		if err == nil {
			t.Fatal("Verify() succeeded, want an audience mismatch")
		}
		if !strings.Contains(err.Error(), "expected audience") {
			t.Fatalf("Verify() error = %v, want it to mention \"expected audience\"", err)
		}

		idTok, err := provider.Verifier(&oidc.Config{ClientID: tamperClientID, SkipClientIDCheck: true}).Verify(ctx, raw)
		if err != nil {
			t.Fatalf("Verify() with SkipClientIDCheck = %v, want success (only aud is broken)", err)
		}
		if err := idTok.VerifyAccessToken(tok.AccessToken); err != nil {
			t.Fatalf("VerifyAccessToken() = %v, want success", err)
		}
	})

	// --- nonce: go-oidc's own Verify() never checks nonce (that is left
	// to the caller, e.g. tanukirpc/auth/oidc), so the client-level
	// assertion here is exactly that comparison: the verified token's
	// Nonce must differ from what was sent, and nothing else about the
	// token is affected.
	t.Run("Nonce", func(t *testing.T) {
		const sentNonce = "the-nonce-value"
		provider, tok := tamperLogin(t, ctx, baseURL, "/t-nonce", sentNonce)
		raw := rawIDTokenOf(t, tok)
		idTok, err := provider.Verifier(&oidc.Config{ClientID: tamperClientID}).Verify(ctx, raw)
		if err != nil {
			t.Fatalf("Verify() = %v, want success (go-oidc does not validate nonce itself)", err)
		}
		if idTok.Nonce == sentNonce {
			t.Fatalf("nonce = %q, want it to differ from the nonce sent to /authorize (%q)", idTok.Nonce, sentNonce)
		}
		if err := idTok.VerifyAccessToken(tok.AccessToken); err != nil {
			t.Fatalf("VerifyAccessToken() = %v, want success (only nonce is broken)", err)
		}
	})

	// --- exp: this must be a genuinely different failure from
	// id_token_ttl: -5m. A structurally wrong exp (a JSON string, not a
	// number) makes go-oidc fail to unmarshal the claims at all, before
	// any expiry check runs -- so the error must NOT say "expired".
	t.Run("Exp", func(t *testing.T) {
		provider, tok := tamperLogin(t, ctx, baseURL, "/t-exp", "the-nonce-value")
		raw := rawIDTokenOf(t, tok)

		_, err := provider.Verifier(&oidc.Config{ClientID: tamperClientID}).Verify(ctx, raw)
		if err == nil {
			t.Fatal("Verify() succeeded, want a claims-unmarshal failure")
		}
		if !strings.Contains(err.Error(), "failed to unmarshal claims") {
			t.Fatalf("Verify() error = %v, want it to mention \"failed to unmarshal claims\"", err)
		}
		if strings.Contains(err.Error(), "expired") {
			t.Fatalf("Verify() error = %v, must NOT say \"expired\" -- that is id_token_ttl: -5m's failure, a different defect", err)
		}

		// "Rest stays valid" has to be checked by hand here: go-oidc
		// refuses to even parse the claims, so there is no Skip* flag
		// for this one. Confirm every other claim is exactly correct
		// and the signature verifies, by decoding and checking the JWKS
		// directly.
		claims := decodeCompactJWTPayload(t, raw)
		if claims["iss"] != baseURL+"/t-exp" {
			t.Errorf("iss = %v, want untouched %q", claims["iss"], baseURL+"/t-exp")
		}
		if claims["aud"] != tamperClientID {
			t.Errorf("aud = %v, want untouched %q", claims["aud"], tamperClientID)
		}
		if claims["nonce"] != "the-nonce-value" {
			t.Errorf("nonce = %v, want untouched", claims["nonce"])
		}
		if _, ok := claims["at_hash"].(string); !ok {
			t.Errorf("at_hash = %v, want an untouched string", claims["at_hash"])
		}
		expVal, ok := claims["exp"].(string)
		if !ok {
			t.Fatalf("exp = %T, want a JSON string (the corruption itself)", claims["exp"])
		}
		if expVal == "" {
			t.Errorf("exp string is empty")
		}

		set := fetchJWKS(t, baseURL+"/t-exp/jwks")
		if _, err := jws.Verify([]byte(raw), jws.WithKeySet(set)); err != nil {
			t.Fatalf("jws.Verify against the served JWKS = %v, want success (signature must stay valid for tamper: [exp])", err)
		}
	})

	// --- signature: unknown kid. Verify() fails, and the kid used is
	// absent from the JWKS this target itself serves -- the unknown-kid/
	// key-rotation scenario README "Keys" calls out.
	t.Run("Signature", func(t *testing.T) {
		provider, tok := tamperLogin(t, ctx, baseURL, "/t-signature", "the-nonce-value")
		raw := rawIDTokenOf(t, tok)

		_, err := provider.Verifier(&oidc.Config{ClientID: tamperClientID}).Verify(ctx, raw)
		if err == nil {
			t.Fatal("Verify() succeeded, want an unknown-kid failure")
		}

		kid := kidOfCompactJWT(t, raw)
		set := fetchJWKS(t, baseURL+"/t-signature/jwks")
		if _, ok := set.LookupKeyID(kid); ok {
			t.Fatalf("kid %q from the tampered token is present in the served JWKS, want it absent", kid)
		}

		// The rest of the claims are still exactly correct -- decode
		// without verifying (there is no valid signature to verify
		// against the published JWKS by design) and check them by hand.
		claims := decodeCompactJWTPayload(t, raw)
		if claims["iss"] != baseURL+"/t-signature" {
			t.Errorf("iss = %v, want untouched", claims["iss"])
		}
		if claims["aud"] != tamperClientID {
			t.Errorf("aud = %v, want untouched", claims["aud"])
		}
		if claims["nonce"] != "the-nonce-value" {
			t.Errorf("nonce = %v, want untouched", claims["nonce"])
		}
	})

	// --- Combination: [aud, at_hash] together. Skipping only the
	// client-ID check must make Verify() succeed (proving iss/exp/
	// signature/nonce are all still fine), while VerifyAccessToken still
	// fails (proving at_hash is still broken too) -- two things broken,
	// nothing else.
	t.Run("Combination_AudAndAtHash", func(t *testing.T) {
		provider, tok := tamperLogin(t, ctx, baseURL, "/t-combo", "the-nonce-value")
		raw := rawIDTokenOf(t, tok)

		idTok, err := provider.Verifier(&oidc.Config{ClientID: tamperClientID, SkipClientIDCheck: true}).Verify(ctx, raw)
		if err != nil {
			t.Fatalf("Verify() with SkipClientIDCheck = %v, want success", err)
		}
		if len(idTok.Audience) == 0 || idTok.Audience[0] == tamperClientID {
			t.Fatalf("Audience = %v, want it tampered (differ from %q)", idTok.Audience, tamperClientID)
		}
		if idTok.Nonce != "the-nonce-value" {
			t.Errorf("nonce = %q, want untouched", idTok.Nonce)
		}
		if err := idTok.VerifyAccessToken(tok.AccessToken); err == nil {
			t.Fatal("VerifyAccessToken() succeeded, want at_hash still broken")
		}
	})

	// --- Refresh grant: the ID token minted by grant_type=refresh_token
	// carries the same tamper corruption as the one minted by the
	// authorization_code grant, since both flow through the same
	// buildIDToken/buildAccessToken (token.go). A client that re-verifies
	// after a refresh is exercised exactly the same way.
	t.Run("RefreshGrantIsTamperedToo", func(t *testing.T) {
		provider, tok := tamperLogin(t, ctx, baseURL, "/t-at-hash", "the-nonce-value")
		if tok.RefreshToken == "" {
			t.Fatalf("no refresh_token in the initial token response")
		}

		form := url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {tok.RefreshToken},
			"client_id":     {tamperClientID},
			"client_secret": {tamperClientSecret},
		}
		resp, err := http.PostForm(baseURL+"/t-at-hash/token", form)
		if err != nil {
			t.Fatalf("POST /token (refresh_token): %v", err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("reading refresh response: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("refresh status = %d, want 200 (body: %s)", resp.StatusCode, body)
		}
		var refreshed struct {
			AccessToken string `json:"access_token"`
			IDToken     string `json:"id_token"`
		}
		if err := json.Unmarshal(body, &refreshed); err != nil {
			t.Fatalf("decoding refresh response: %v", err)
		}
		if refreshed.IDToken == "" || refreshed.AccessToken == "" {
			t.Fatalf("refresh response missing id_token/access_token: %s", body)
		}

		idTok, err := provider.Verifier(&oidc.Config{ClientID: tamperClientID}).Verify(ctx, refreshed.IDToken)
		if err != nil {
			t.Fatalf("Verify() on the refreshed ID token = %v, want success (only at_hash is broken)", err)
		}
		if err := idTok.VerifyAccessToken(refreshed.AccessToken); err == nil {
			t.Fatal("VerifyAccessToken() on the refreshed ID token succeeded, want at_hash still tampered after refresh")
		}
	})
}
