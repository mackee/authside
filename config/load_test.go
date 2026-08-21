package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validMinimalDoc = `
targets:
  - name: oidc
    type: oidc
    issuer: http://authside:5556/oidc
    clients:
      - client_id: local-app
        client_secret: local-secret
        redirect_uris: [http://localhost:8080/auth/callback]
    users:
      - sub: user-1
`

func TestLoad_FromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "authside.yaml")
	if err := os.WriteFile(path, []byte(validMinimalDoc), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Targets) != 1 || cfg.Targets[0].Name != "oidc" {
		t.Fatalf("cfg = %+v", cfg)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err == nil {
		t.Fatalf("expected an error for a missing file")
	}
}

func TestLoadReader(t *testing.T) {
	cfg, err := LoadReader(strings.NewReader(validMinimalDoc))
	if err != nil {
		t.Fatalf("LoadReader: %v", err)
	}
	if len(cfg.Targets) != 1 {
		t.Fatalf("cfg = %+v", cfg)
	}
}

func TestLoadBytes_UnknownFieldRejected(t *testing.T) {
	const doc = `
targets:
  - name: oidc
    type: oidc
    issur: http://authside:5556/oidc   # typo: issur, not issuer
    clients:
      - client_id: local-app
        client_secret: local-secret
        redirect_uris: [http://localhost:8080/auth/callback]
    users:
      - sub: user-1
`
	_, err := LoadBytes([]byte(doc))
	if err == nil {
		t.Fatalf("expected an error for an unknown field (typo), got nil")
	}
	if !strings.Contains(err.Error(), "issur") {
		t.Fatalf("error should name the offending field: %v", err)
	}
}

func TestLoadBytes_UnknownFieldRejected_TopLevel(t *testing.T) {
	const doc = `
listne: 0.0.0.0:5556   # typo: listne, not listen
targets:
  - name: oidc
    type: oidc
    issuer: http://authside:5556/oidc
    clients:
      - client_id: local-app
        client_secret: local-secret
        redirect_uris: [http://localhost:8080/auth/callback]
    users:
      - sub: user-1
`
	_, err := LoadBytes([]byte(doc))
	if err == nil {
		t.Fatalf("expected an error for an unknown top-level field, got nil")
	}
}

func TestResolve_InlineEnvTakesPrecedenceOverPath(t *testing.T) {
	t.Setenv(InlineConfigEnvVar, validMinimalDoc)

	// path points at a file that does not exist -- Resolve must not even
	// try to read it, because the inline env var is set and non-empty.
	cfg, err := Resolve(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(cfg.Targets) != 1 || cfg.Targets[0].Name != "oidc" {
		t.Fatalf("cfg = %+v", cfg)
	}
}

func TestResolve_FallsBackToPathWhenInlineUnset(t *testing.T) {
	// t.Setenv followed by os.Unsetenv, rather than a bare os.Unsetenv,
	// so the harness restores whatever value (if any) was present
	// before this test ran -- a bare Unsetenv would leak that change
	// into every test that runs after this one in the same process.
	t.Setenv(InlineConfigEnvVar, "placeholder")
	os.Unsetenv(InlineConfigEnvVar)

	dir := t.TempDir()
	path := filepath.Join(dir, "authside.yaml")
	if err := os.WriteFile(path, []byte(validMinimalDoc), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg, err := Resolve(path)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(cfg.Targets) != 1 {
		t.Fatalf("cfg = %+v", cfg)
	}
}

func TestResolve_FallsBackToPathWhenInlineEmpty(t *testing.T) {
	// Set-but-empty must behave like unset, not like "use an empty
	// document" -- an empty env var is what a compose file has when the
	// variable is declared but not substituted.
	t.Setenv(InlineConfigEnvVar, "")

	dir := t.TempDir()
	path := filepath.Join(dir, "authside.yaml")
	if err := os.WriteFile(path, []byte(validMinimalDoc), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg, err := Resolve(path)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(cfg.Targets) != 1 {
		t.Fatalf("cfg = %+v", cfg)
	}
}

func TestLoadBytes_InvalidConfigStillFails(t *testing.T) {
	const doc = `
targets: []
`
	_, err := LoadBytes([]byte(doc))
	if err == nil {
		t.Fatalf("expected a validation error for an empty targets list")
	}
}
