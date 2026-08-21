package authside_test

// This file is the exit test for a configured signing key (key_pem /
// key_file). The property it buys, and the only reason to configure one,
// is that a token minted by one process verifies against a *different*
// process's JWKS -- which a generated key can never do, because it exists
// only for the life of the process that made it.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/mackee/authside"
	"github.com/mackee/authside/config"
)

// writeSigningKey generates a PKCS#8 RSA key and writes it where a config
// can point at it. Generated rather than checked in: a committed private
// key trips secret scanners and can be blocked by push protection.
func writeSigningKey(t *testing.T) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatalf("marshalling the key: %v", err)
	}
	path := filepath.Join(t.TempDir(), "signing-key.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("writing the key: %v", err)
	}
	return path
}

func TestKey_TokenFromOneProcessVerifiesAgainstAnothersJWKS(t *testing.T) {
	const (
		mount        = "/oidc"
		clientID     = "local-app"
		clientSecret = "local-secret"
		redirectURI  = "http://app.invalid/callback"
	)

	keyPath := writeSigningKey(t)

	// Two independent authside instances on the same config, standing in
	// for "the sidecar" and "authside token" -- or simply for the same
	// sidecar before and after a restart.
	newInstance := func() *httptest.Server {
		srv := httptest.NewUnstartedServer(nil)
		baseURL := "http://" + srv.Listener.Addr().String()
		cfg := oneTarget("oidc", baseURL, mount, clientID, clientSecret, redirectURI, nil)
		cfg.Targets[0].KeyFile = keyPath
		h, err := authside.New(cfg)
		if err != nil {
			t.Fatalf("authside.New: %v", err)
		}
		srv.Config.Handler = h
		srv.Start()
		t.Cleanup(srv.Close)
		return srv
	}

	minter := newInstance()
	verifierSide := newInstance()

	// The two agree on the JWKS byte-for-byte, because the kid is an RFC
	// 7638 thumbprint of the key material and the key is the same file.
	minterJWKS := fetchJWKSBytes(t, minter.URL+mount+"/jwks")
	verifierJWKS := fetchJWKSBytes(t, verifierSide.URL+mount+"/jwks")
	if string(minterJWKS) != string(verifierJWKS) {
		t.Fatalf("two instances on one key file served different JWKS:\n %s\n %s", minterJWKS, verifierJWKS)
	}

	// Log in against the first instance.
	minterBase := "http://" + minter.Listener.Addr().String()
	minterIssuer := minterBase + mount
	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, minterIssuer)
	if err != nil {
		t.Fatalf("NewProvider (minter): %v", err)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	setAuthsideSubCookie(t, jar, minterBase, "user-1")
	code, _ := driveAuthorize(t, noFollowClient(jar), minterIssuer, clientID, redirectURI, "st", "nonce-key")
	tok, err := (&oauth2.Config{
		ClientID: clientID, ClientSecret: clientSecret, RedirectURL: redirectURI,
		Endpoint: provider.Endpoint(), Scopes: []string{oidc.ScopeOpenID},
	}).Exchange(ctx, code)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		t.Fatal("no id_token in the token response")
	}

	// The payoff: verify that token using the OTHER instance's JWKS.
	// SkipIssuerCheck because the two instances necessarily listen on
	// different ports, so their issuers differ -- the signature is what
	// is under test here, and the issuer is checked in every other
	// acceptance test in this package.
	otherKeySet := oidc.NewRemoteKeySet(ctx, verifierSide.URL+mount+"/jwks")
	crossVerifier := oidc.NewVerifier(minterIssuer, otherKeySet, &oidc.Config{
		ClientID:        clientID,
		SkipIssuerCheck: true,
	})
	verified, err := crossVerifier.Verify(ctx, rawIDToken)
	if err != nil {
		t.Fatalf("verifying against another instance's JWKS: %v", err)
	}
	if verified.Subject != "user-1" {
		t.Fatalf("sub = %q, want user-1", verified.Subject)
	}
}

// TestKey_WithoutAConfiguredKeyCrossProcessVerificationFails is the
// contrast: the same test without key_file must fail, or the test above
// proves nothing.
func TestKey_WithoutAConfiguredKeyCrossProcessVerificationFails(t *testing.T) {
	const (
		mount        = "/oidc"
		clientID     = "local-app"
		clientSecret = "local-secret"
		redirectURI  = "http://app.invalid/callback"
	)

	newInstance := func() *httptest.Server {
		srv := httptest.NewUnstartedServer(nil)
		baseURL := "http://" + srv.Listener.Addr().String()
		h, err := authside.New(oneTarget("oidc", baseURL, mount, clientID, clientSecret, redirectURI, nil))
		if err != nil {
			t.Fatalf("authside.New: %v", err)
		}
		srv.Config.Handler = h
		srv.Start()
		t.Cleanup(srv.Close)
		return srv
	}

	minter := newInstance()
	other := newInstance()

	if string(fetchJWKSBytes(t, minter.URL+mount+"/jwks")) == string(fetchJWKSBytes(t, other.URL+mount+"/jwks")) {
		t.Fatal("two keyless instances served the same JWKS; they are supposed to generate independent keys")
	}
}

// TestKey_InlinePEMWorksToo covers key_pem, for a config with nowhere to
// put a file (AUTHSIDE_CONFIG_INLINE, for instance).
func TestKey_InlinePEMWorksToo(t *testing.T) {
	const (
		mount        = "/oidc"
		clientID     = "local-app"
		clientSecret = "local-secret"
		redirectURI  = "http://app.invalid/callback"
	)

	keyPath := writeSigningKey(t)
	pemBytes, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("reading the key: %v", err)
	}

	jwksFor := func(mutate func(*config.Target)) string {
		srv := httptest.NewUnstartedServer(nil)
		baseURL := "http://" + srv.Listener.Addr().String()
		cfg := oneTarget("oidc", baseURL, mount, clientID, clientSecret, redirectURI, nil)
		mutate(&cfg.Targets[0])
		h, err := authside.New(cfg)
		if err != nil {
			t.Fatalf("authside.New: %v", err)
		}
		srv.Config.Handler = h
		srv.Start()
		t.Cleanup(srv.Close)
		return string(fetchJWKSBytes(t, srv.URL+mount+"/jwks"))
	}

	inline := jwksFor(func(tg *config.Target) { tg.KeyPEM = string(pemBytes) })
	fromFile := jwksFor(func(tg *config.Target) { tg.KeyFile = keyPath })
	if inline != fromFile {
		t.Fatalf("key_pem and key_file on the same key served different JWKS:\n %s\n %s", inline, fromFile)
	}
}

// fetchJWKSBytes returns the JWKS document as served, unparsed: these
// tests compare two instances' documents byte-for-byte, which a parsed
// jwk.Set (tamper_test.go's fetchJWKS) cannot express.
func fetchJWKSBytes(t *testing.T, url string) []byte {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status = %d, want 200", url, resp.StatusCode)
	}
	var raw json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		t.Fatalf("decoding JWKS: %v", err)
	}
	return raw
}
