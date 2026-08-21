package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mackee/authside"
	"github.com/mackee/authside/config"
)

// --- resolveListenAddr: table-driven -------------------------------------

func TestResolveListenAddr(t *testing.T) {
	tests := []struct {
		name          string
		listen        string
		allowExternal bool
		wantAddr      string
		wantWarning   bool
		wantErr       bool
	}{
		{
			name:          "0.0.0.0 without flag forces loopback and warns",
			listen:        "0.0.0.0:5556",
			allowExternal: false,
			wantAddr:      "127.0.0.1:5556",
			wantWarning:   true,
		},
		{
			name:          "0.0.0.0 with flag binds as configured and warns",
			listen:        "0.0.0.0:5556",
			allowExternal: true,
			wantAddr:      "0.0.0.0:5556",
			wantWarning:   true,
		},
		{
			name:          "bare port without flag forces loopback and warns",
			listen:        ":5556",
			allowExternal: false,
			wantAddr:      "127.0.0.1:5556",
			wantWarning:   true,
		},
		{
			name:          "bare port with flag binds as configured and warns",
			listen:        ":5556",
			allowExternal: true,
			wantAddr:      ":5556",
			wantWarning:   true,
		},
		{
			name:          "127.0.0.1 without flag: already loopback, no warning",
			listen:        "127.0.0.1:5556",
			allowExternal: false,
			wantAddr:      "127.0.0.1:5556",
			wantWarning:   false,
		},
		{
			name:          "127.0.0.1 with flag: still loopback, no warning",
			listen:        "127.0.0.1:5556",
			allowExternal: true,
			wantAddr:      "127.0.0.1:5556",
			wantWarning:   false,
		},
		{
			name:          "localhost without flag: loopback, no warning",
			listen:        "localhost:5556",
			allowExternal: false,
			wantAddr:      "localhost:5556",
			wantWarning:   false,
		},
		{
			name:          "IPv6 wildcard without flag forces loopback and warns",
			listen:        "[::]:5556",
			allowExternal: false,
			wantAddr:      "127.0.0.1:5556",
			wantWarning:   true,
		},
		{
			name:          "IPv6 wildcard with flag binds as configured and warns",
			listen:        "[::]:5556",
			allowExternal: true,
			wantAddr:      "[::]:5556",
			wantWarning:   true,
		},
		{
			name:          "IPv6 loopback without flag: no warning",
			listen:        "[::1]:5556",
			allowExternal: false,
			wantAddr:      "[::1]:5556",
			wantWarning:   false,
		},
		{
			name:          "IPv6 loopback with flag: no warning",
			listen:        "[::1]:5556",
			allowExternal: true,
			wantAddr:      "[::1]:5556",
			wantWarning:   false,
		},
		{
			name:          "empty listen: default port on loopback, flag irrelevant",
			listen:        "",
			allowExternal: false,
			wantAddr:      "127.0.0.1:5556",
			wantWarning:   false,
		},
		{
			name:          "empty listen with flag: still default port on loopback",
			listen:        "",
			allowExternal: true,
			wantAddr:      "127.0.0.1:5556",
			wantWarning:   false,
		},
		{
			name:    "malformed listen value is an error",
			listen:  "no-port",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, warning, err := resolveListenAddr(tt.listen, tt.allowExternal)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("resolveListenAddr(%q, %v) = %q, %q, nil; want error", tt.listen, tt.allowExternal, addr, warning)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveListenAddr(%q, %v) unexpected error: %v", tt.listen, tt.allowExternal, err)
			}
			if addr != tt.wantAddr {
				t.Errorf("addr = %q, want %q", addr, tt.wantAddr)
			}
			gotWarning := warning != ""
			if gotWarning != tt.wantWarning {
				t.Errorf("warning present = %v (%q), want %v", gotWarning, warning, tt.wantWarning)
			}
		})
	}
}

// --- serve: end-to-end-ish start/serve/shutdown --------------------------

const minimalValidConfig = `
listen: 127.0.0.1:0
targets:
  - name: oidc
    type: oidc
    issuer: http://127.0.0.1/oidc
    login: auto
    default_user: user-1
    clients:
      - client_id: local-app
        client_secret: local-secret
        redirect_uris: [http://localhost:8080/auth/callback]
    users:
      - sub: user-1
        claims:
          email: alice@example.com
`

func TestServeStartsServesAndShutsDownCleanly(t *testing.T) {
	cfg, err := config.LoadBytes([]byte(minimalValidConfig))
	if err != nil {
		t.Fatalf("config.LoadBytes: %v", err)
	}

	handler, err := authside.New(cfg)
	if err != nil {
		t.Fatalf("authside.New: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	readyCh := make(chan net.Addr, 1)
	errCh := make(chan error, 1)

	go func() {
		errCh <- serve(ctx, logger, "127.0.0.1:0", handler, func(a net.Addr) {
			readyCh <- a
		})
	}()

	var addr net.Addr
	select {
	case addr = <-readyCh:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not become ready in time")
	}

	resp, err := http.Get("http://" + addr.String() + "/oidc/jwks")
	if err != nil {
		t.Fatalf("GET /oidc/jwks: %v", err)
	}
	resp.Body.Close()

	if got := resp.Header.Get("X-Authside"); got != "fake-idp" {
		t.Errorf("X-Authside header = %q, want %q", got, "fake-idp")
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("serve returned error after shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not shut down in time")
	}
}

// --- run: config warnings reach the log output ---------------------------

func TestRun_WarningsReachLogOutput(t *testing.T) {
	t.Setenv(config.InlineConfigEnvVar, "")

	dir := t.TempDir()
	path := filepath.Join(dir, "authside.yaml")
	// login: auto with no default_user triggers config.Validate's warning
	// (README "Login modes": auto has no implicit fallback subject). It
	// is the only warning this config produces, and the only one the
	// config package emits at all now that key_seed is gone -- if a
	// second warning is ever added, this test does not need to change.
	const doc = `
listen: 127.0.0.1:0
targets:
  - name: oidc
    type: oidc
    issuer: http://127.0.0.1/oidc
    login: auto
    clients:
      - client_id: local-app
        client_secret: local-secret
        redirect_uris: [http://localhost:8080/auth/callback]
    users:
      - sub: user-1
`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}

	var buf bytes.Buffer
	// Already-canceled context: run() does its startup sequence (banner,
	// load, warnings, bind, build handler) and then serve() sees ctx
	// already Done and shuts down immediately -- deterministic, no sleeps.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := run(ctx, []string{"--config", path}, io.Discard, &buf); err != nil {
		t.Fatalf("run: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "login: auto has no default_user") {
		t.Errorf("log output missing login:auto warning; got:\n%s", out)
	}
}

func TestRun_NoConfigProvided(t *testing.T) {
	t.Setenv(config.InlineConfigEnvVar, "")

	var buf bytes.Buffer
	err := run(context.Background(), nil, io.Discard, &buf)
	if err == nil {
		t.Fatal("run: expected an error when neither --config nor AUTHSIDE_CONFIG_INLINE is set")
	}
	if !strings.Contains(err.Error(), "--config") || !strings.Contains(err.Error(), config.InlineConfigEnvVar) {
		t.Errorf("error should name both mechanisms, got: %v", err)
	}
}

func TestRun_InlineConfigEnvVarTakesPrecedence(t *testing.T) {
	t.Setenv(config.InlineConfigEnvVar, minimalValidConfig)

	var buf bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// A bogus --config path must be ignored, since the inline env var is
	// set (config.Resolve's precedence).
	if err := run(ctx, []string{"--config", "/does/not/exist.yaml", "--allow-external"}, io.Discard, &buf); err != nil {
		t.Fatalf("run: %v", err)
	}
}
