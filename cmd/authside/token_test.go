package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/lestrrat-go/jwx/v3/jwk"

	"github.com/mackee/authside/config"
)

// tokenTestConfig is the config every case here mints against: one
// target, one client, one user with claims worth asserting on.
const tokenTestConfig = `
targets:
  - name: oidc
    type: oidc
    issuer: http://authside.test/oidc
    mount: /oidc
    clients:
      - client_id: local-app
        client_secret: local-secret
        redirect_uris: [http://localhost:8080/auth/callback]
    users:
      - sub: user-1
        claims:
          email: alice@example.com
          name: Alice
`

func writeTokenTestConfig(t *testing.T, doc string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "authside.yaml")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	return path
}

// mintedOutput is the shape runToken prints, decoded.
type mintedOutput struct {
	IDToken     string          `json:"id_token"`
	AccessToken string          `json:"access_token"`
	ExpiresIn   int64           `json:"expires_in"`
	JWKS        json.RawMessage `json:"jwks"`
}

// runTokenOK runs the subcommand, requires success, and returns the
// decoded stdout plus the raw stderr.
func runTokenOK(t *testing.T, args ...string) (mintedOutput, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if err := runToken(args, &stdout, &stderr); err != nil {
		t.Fatalf("runToken(%v) = %v, want nil (stderr: %s)", args, err, stderr.String())
	}
	var out mintedOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("stdout is not one JSON object: %v (stdout: %s)", err, stdout.String())
	}
	return out, stderr.String()
}

// TestRunToken_MintsTokensVerifiableWithTheirOwnJWKS is this
// subcommand's exit test, and the reason --jwks exists at all.
//
// With no key configured on the target, the signing key is generated for
// this invocation alone, so the token verifies against no running
// authside -- the only key set that matches it is the one printed
// alongside it. This test is the proof that pairing actually works: it verifies the id_token with
// go-oidc, the real consumer, against a StaticKeySet built from the
// printed JWKS and nothing else. No server is involved anywhere.
func TestRunToken_MintsTokensVerifiableWithTheirOwnJWKS(t *testing.T) {
	cfg := writeTokenTestConfig(t, tokenTestConfig)

	out, _ := runTokenOK(t, "--config", cfg, "--client", "local-app", "--user", "user-1", "--jwks")

	if out.IDToken == "" || out.AccessToken == "" {
		t.Fatalf("missing tokens in %+v", out)
	}
	if len(out.JWKS) == 0 {
		t.Fatal("--jwks was passed but the output carries no jwks")
	}

	verifier := oidc.NewVerifier(
		"http://authside.test/oidc",
		&oidc.StaticKeySet{PublicKeys: publicKeysFromJWKS(t, out.JWKS)},
		&oidc.Config{ClientID: "local-app"},
	)
	idToken, err := verifier.Verify(context.Background(), out.IDToken)
	if err != nil {
		t.Fatalf("verifying the minted id_token against its own JWKS: %v", err)
	}
	if idToken.Subject != "user-1" {
		t.Fatalf("sub = %q, want user-1", idToken.Subject)
	}

	var claims struct {
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := idToken.Claims(&claims); err != nil {
		t.Fatalf("Claims: %v", err)
	}
	if claims.Email != "alice@example.com" || claims.Name != "Alice" {
		t.Fatalf("claims = %+v, want the configured user's claims", claims)
	}

	// at_hash covers the access token here exactly as it does after a
	// real login: a headless mint is not a second, weaker code path.
	if err := idToken.VerifyAccessToken(out.AccessToken); err != nil {
		t.Fatalf("VerifyAccessToken on a headlessly minted pair: %v", err)
	}
}

// publicKeysFromJWKS turns the printed JWKS into the crypto.PublicKey
// slice go-oidc's StaticKeySet wants.
func publicKeysFromJWKS(t *testing.T, raw []byte) []crypto.PublicKey {
	t.Helper()
	set, err := jwk.Parse(raw)
	if err != nil {
		t.Fatalf("parsing the printed JWKS: %v (jwks: %s)", err, raw)
	}
	if set.Len() == 0 {
		t.Fatalf("the printed JWKS has no keys: %s", raw)
	}
	keys := make([]crypto.PublicKey, 0, set.Len())
	for i := 0; i < set.Len(); i++ {
		key, ok := set.Key(i)
		if !ok {
			t.Fatalf("JWKS key %d is not readable", i)
		}
		var pub rsa.PublicKey
		if err := jwk.Export(key, &pub); err != nil {
			t.Fatalf("exporting JWKS key %d: %v", i, err)
		}
		keys = append(keys, &pub)
	}
	return keys
}

// TestRunToken_StdoutIsJSONOnlyAndTheKeyCaveatGoesToStderr: the command
// is meant to be piped into jq, so a note that belonged on stdout would
// break every such use -- while a caveat that appeared nowhere would let
// a user ship tokens no verifier accepts without ever being told why.
func TestRunToken_StdoutIsJSONOnlyAndTheKeyCaveatGoesToStderr(t *testing.T) {
	cfg := writeTokenTestConfig(t, tokenTestConfig)

	var stdout, stderr bytes.Buffer
	if err := runToken([]string{"--config", cfg, "--client", "local-app", "--user", "user-1"}, &stdout, &stderr); err != nil {
		t.Fatalf("runToken: %v (stderr: %s)", err, stderr.String())
	}

	// Exactly one JSON object and nothing else: decoding to the end of
	// the stream must find no second value.
	dec := json.NewDecoder(&stdout)
	var first mintedOutput
	if err := dec.Decode(&first); err != nil {
		t.Fatalf("decoding stdout: %v", err)
	}
	if dec.More() {
		t.Fatal("stdout carries more than one JSON value")
	}

	// Without --jwks the key set is omitted entirely rather than emitted
	// empty.
	if first.JWKS != nil {
		t.Fatalf("jwks present without --jwks: %s", first.JWKS)
	}

	if !strings.Contains(stderr.String(), "configures no signing key") {
		t.Fatalf("stderr does not carry the ephemeral-key caveat: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "--jwks") {
		t.Fatalf("stderr does not point at --jwks as the way out: %s", stderr.String())
	}
}

// TestRunToken_NoEphemeralKeyNoteWhenTheTargetSuppliesAKey: with
// key_file set, the caveat would be false -- the same key signs in every
// process, so these tokens do verify against a running authside. A
// warning that does not apply is worse than none.
func TestRunToken_NoEphemeralKeyNoteWhenTheTargetSuppliesAKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "signing-key.pem")
	if err := os.WriteFile(keyPath, []byte(testSigningKeyPEM(t)), 0o600); err != nil {
		t.Fatalf("writing the key: %v", err)
	}
	cfg := writeTokenTestConfig(t, tokenTestConfig+"    key_file: "+keyPath+"\n")

	var stdout, stderr bytes.Buffer
	if err := runToken([]string{"--config", cfg, "--client", "local-app", "--user", "user-1"}, &stdout, &stderr); err != nil {
		t.Fatalf("runToken: %v (stderr: %s)", err, stderr.String())
	}
	if strings.Contains(stderr.String(), "configures no signing key") {
		t.Fatalf("the ephemeral-key caveat was printed for a target that supplies a key: %s", stderr.String())
	}
	if stdout.Len() == 0 {
		t.Fatal("no tokens minted")
	}
}

// testSigningKeyPEM generates a PKCS#8 RSA key at test time. Not a
// checked-in fixture: a committed private key trips secret scanners and
// can be blocked by push protection outright.
func testSigningKeyPEM(t *testing.T) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatalf("marshalling the key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// TestRunToken_NoNonceAndNoRefreshToken pins the two omissions Mint
// documents: there was no authentication request to carry a nonce, and a
// refresh token would be a handle into state that dies with the process.
func TestRunToken_NoNonceAndNoRefreshToken(t *testing.T) {
	cfg := writeTokenTestConfig(t, tokenTestConfig)

	var stdout, stderr bytes.Buffer
	if err := runToken([]string{"--config", cfg, "--client", "local-app", "--user", "user-1"}, &stdout, &stderr); err != nil {
		t.Fatalf("runToken: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &raw); err != nil {
		t.Fatalf("decoding stdout: %v", err)
	}
	if _, present := raw["refresh_token"]; present {
		t.Fatalf("output carries a refresh_token: %v", raw)
	}

	var out mintedOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("decoding stdout: %v", err)
	}
	claims := jwtClaims(t, out.IDToken)
	if _, present := claims["nonce"]; present {
		t.Fatalf("id_token carries a nonce claim: %v", claims)
	}
	if claims["sub"] != "user-1" {
		t.Fatalf("id_token sub = %v, want user-1", claims["sub"])
	}
}

// TestRunToken_RejectsWhatItCannotMint: every one of these is a mistake a
// user makes at the shell, so each must fail with an error naming the
// thing that was wrong rather than minting something surprising.
func TestRunToken_RejectsWhatItCannotMint(t *testing.T) {
	cfg := writeTokenTestConfig(t, tokenTestConfig)
	twoTargets := writeTokenTestConfig(t, tokenTestConfig+`
  - name: second
    type: oidc
    issuer: http://authside.test/second
    mount: /second
    clients:
      - client_id: local-app
        client_secret: local-secret
        redirect_uris: [http://localhost:8080/auth/callback]
    users:
      - sub: user-1
`)

	for name, tc := range map[string]struct {
		args    []string
		wantMsg string
	}{
		"no client": {
			args:    []string{"--config", cfg, "--user", "user-1"},
			wantMsg: "--client is required",
		},
		"no user": {
			args:    []string{"--config", cfg, "--client", "local-app"},
			wantMsg: "--user is required",
		},
		"no config": {
			args:    []string{"--client", "local-app", "--user", "user-1"},
			wantMsg: "no config provided",
		},
		"unknown client": {
			args:    []string{"--config", cfg, "--client", "nope", "--user", "user-1"},
			wantMsg: `no client "nope"`,
		},
		"unknown user": {
			args:    []string{"--config", cfg, "--client", "local-app", "--user", "nobody"},
			wantMsg: `no user "nobody"`,
		},
		"unknown target": {
			args:    []string{"--config", cfg, "--target", "nope", "--client", "local-app", "--user", "user-1"},
			wantMsg: `no target named "nope"`,
		},
		"ambiguous target": {
			args:    []string{"--config", twoTargets, "--client", "local-app", "--user", "user-1"},
			wantMsg: "--target is required",
		},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			err := runToken(tc.args, &stdout, &stderr)
			if err == nil {
				t.Fatalf("runToken(%v) = nil, want an error (stdout: %s)", tc.args, stdout.String())
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("error = %q, want it to mention %q", err.Error(), tc.wantMsg)
			}
			if stdout.Len() != 0 {
				t.Fatalf("a failed mint wrote to stdout: %s", stdout.String())
			}
		})
	}
}

// TestRunToken_SingleTargetNeedsNoTargetFlag: --target is only required
// where it is actually ambiguous, since one target is the common case.
func TestRunToken_SingleTargetNeedsNoTargetFlag(t *testing.T) {
	cfg := writeTokenTestConfig(t, tokenTestConfig)
	out, _ := runTokenOK(t, "--config", cfg, "--client", "local-app", "--user", "user-1")
	if out.IDToken == "" {
		t.Fatal("no id_token minted without --target on a single-target config")
	}
}

// TestDispatch_OnlyTheBareWordTokenIsASubcommand is the regression guard
// for every existing deployment: the Dockerfile's CMD and the compose
// example pass flags with no subcommand, and must keep reaching the
// server. run() fails on an unreadable config, which is enough to show
// which path was taken -- reaching runToken instead would fail on the
// missing --client first.
func TestDispatch_OnlyTheBareWordTokenIsASubcommand(t *testing.T) {
	err := dispatch(context.Background(), []string{"--config", filepath.Join(t.TempDir(), "missing.yaml")}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("dispatch with only flags = nil, want the server path's config error")
	}
	if !strings.Contains(err.Error(), "loading config") {
		t.Fatalf("error = %q, want the server path's %q error", err.Error(), "loading config")
	}

	cfg := writeTokenTestConfig(t, tokenTestConfig)
	var stdout bytes.Buffer
	if err := dispatch(context.Background(), []string{"token", "--config", cfg, "--client", "local-app", "--user", "user-1"}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatalf("dispatch to the token subcommand: %v", err)
	}
	if !strings.Contains(stdout.String(), "id_token") {
		t.Fatalf("token subcommand produced no id_token: %s", stdout.String())
	}
}

// jwtClaims decodes a compact JWS payload without verifying it.
func jwtClaims(t *testing.T, compact string) map[string]any {
	t.Helper()
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("not a three-part JWT: %s", compact)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decoding JWT payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("unmarshalling JWT payload: %v", err)
	}
	return claims
}

// TestVersionFlag_NeedsNoConfigAndPrintsOneLineOnStdout: `--version` is
// the one invocation that must work in a bare container with nothing
// mounted, so it has to answer before the config check and before the
// banner. stdout carries the version alone, because a script reads it.
func TestVersionFlag_NeedsNoConfigAndPrintsOneLineOnStdout(t *testing.T) {
	t.Setenv(config.InlineConfigEnvVar, "")

	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"--version"}, &stdout, &stderr); err != nil {
		t.Fatalf("run(--version) = %v, want nil (stderr: %s)", err, stderr.String())
	}

	got := strings.TrimSpace(stdout.String())
	if got == "" {
		t.Fatal("--version printed nothing on stdout")
	}
	if strings.Contains(got, "\n") {
		t.Fatalf("--version printed %q, want a single bare line", stdout.String())
	}
	if got != resolveVersion() {
		t.Fatalf("--version printed %q, want %q", got, resolveVersion())
	}
	// No banner, no warnings: nothing but the version happened.
	if stderr.Len() != 0 {
		t.Fatalf("--version wrote to stderr: %s", stderr.String())
	}
}

// TestResolveVersion_PrefersTheInjectedValue pins the precedence in
// resolveVersion: an ldflags-injected version wins, and "dev" (or empty)
// falls through to whatever Go recorded -- which in a test binary is
// "(devel)", i.e. nothing useful, so it lands back on "dev".
func TestResolveVersion_PrefersTheInjectedValue(t *testing.T) {
	original := version
	t.Cleanup(func() { version = original })

	version = "v9.9.9"
	if got := resolveVersion(); got != "v9.9.9" {
		t.Fatalf("resolveVersion() with an injected version = %q, want v9.9.9", got)
	}

	for _, uninjected := range []string{"dev", ""} {
		version = uninjected
		if got := resolveVersion(); got != "dev" {
			t.Fatalf("resolveVersion() with version=%q = %q, want dev (a test binary's module version is \"(devel)\")", uninjected, got)
		}
	}
}
