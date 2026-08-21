package oidcop

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mackee/authside/config"
)

func encodePayload(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshalling payload: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func TestDecodeInjectedIdentity_FlatObject(t *testing.T) {
	raw := encodePayload(t, map[string]any{
		"sub":   "u-1",
		"email": "u-1@example.com",
		"hd":    "example.com",
	})

	id, err := decodeInjectedIdentity(raw)
	if err != nil {
		t.Fatalf("decodeInjectedIdentity: %v", err)
	}
	if id.sub != "u-1" {
		t.Fatalf("sub = %q, want %q", id.sub, "u-1")
	}
	// sub is the subject, not a claim: carrying it in the claim map too
	// would be a value buildIDToken always overwrites.
	if _, ok := id.claims["sub"]; ok {
		t.Fatalf("claims still carry sub: %v", id.claims)
	}
	if id.claims["email"] != "u-1@example.com" || id.claims["hd"] != "example.com" {
		t.Fatalf("claims = %v", id.claims)
	}
}

// Node's Buffer.toString('base64url') emits no padding; other encoders do.
// Both decode, so a caller does not have to know which one authside wants.
func TestDecodeInjectedIdentity_PaddedBase64(t *testing.T) {
	b, err := json.Marshal(map[string]any{"sub": "u-1", "email": "a@b.example"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	padded := base64.URLEncoding.EncodeToString(b)
	if !strings.HasSuffix(padded, "=") {
		t.Skip("payload happens to need no padding; nothing to assert here")
	}
	if _, err := decodeInjectedIdentity(padded); err != nil {
		t.Fatalf("padded base64url rejected: %v", err)
	}
}

// A "${...}" in an injected value is a literal: injected claims are
// already specific to the one login carrying them, so a request can never
// introduce a template (or a template syntax error).
func TestDecodeInjectedIdentity_ValuesAreLiterals(t *testing.T) {
	raw := encodePayload(t, map[string]any{"sub": "u-1", "email": "${subject}@example.com"})
	id, err := decodeInjectedIdentity(raw)
	if err != nil {
		t.Fatalf("decodeInjectedIdentity: %v", err)
	}
	if got := id.claims["email"]; got != "${subject}@example.com" {
		t.Fatalf("email = %v, want the literal template text back", got)
	}
}

func TestDecodeInjectedIdentity_NumbersStayExact(t *testing.T) {
	id, err := decodeInjectedIdentity(base64.RawURLEncoding.EncodeToString(
		[]byte(`{"sub":"u-1","seat":10000000000000001}`)))
	if err != nil {
		t.Fatalf("decodeInjectedIdentity: %v", err)
	}
	num, ok := id.claims["seat"].(json.Number)
	if !ok {
		t.Fatalf("seat has type %T, want json.Number", id.claims["seat"])
	}
	if num.String() != "10000000000000001" {
		t.Fatalf("seat = %s, want the digits back unrounded", num)
	}
}

func TestDecodeInjectedIdentity_Rejects(t *testing.T) {
	for _, tc := range []struct {
		name, raw, want string
	}{
		{"not base64", "!!!not base64!!!", "base64url decode"},
		{"not json", base64.RawURLEncoding.EncodeToString([]byte("not json")), "json decode"},
		{"json null", base64.RawURLEncoding.EncodeToString([]byte("null")), "JSON null"},
		{"array", base64.RawURLEncoding.EncodeToString([]byte(`["sub"]`)), "json decode"},
		{"no sub", base64.RawURLEncoding.EncodeToString([]byte(`{"email":"a@b.example"}`)), `no "sub"`},
		{"empty sub", base64.RawURLEncoding.EncodeToString([]byte(`{"sub":""}`)), "must not be empty"},
		{"numeric sub", base64.RawURLEncoding.EncodeToString([]byte(`{"sub":42}`)), "want a string"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decodeInjectedIdentity(tc.raw)
			if err == nil {
				t.Fatalf("expected an error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want substring %q", err, tc.want)
			}
		})
	}
}

// The ignore-without-opt-in path says so once per target, not per
// request: every target in one process shares one origin, so a cookie
// set for a sibling target reaches this one on every single request.
func TestWarnIgnoredInjection_OncePerTarget(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	target, err := buildTarget(&config.Target{
		Name:   "oidc",
		Type:   "oidc",
		Issuer: "http://authside.invalid/oidc",
		Mount:  "/oidc",
		Login:  config.LoginAuto,
		Users:  []config.User{{Sub: "user-1"}},
		// accept_injected_claims deliberately not set.
	}, logger)
	if err != nil {
		t.Fatalf("buildTarget: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://authside.invalid/oidc/authorize", nil)
	req.AddCookie(&http.Cookie{Name: authsideClaimsCookie, Value: "anything"})

	for range 3 {
		_, ok, oerr := injectedIdentityFrom(req, target)
		if ok || oerr != nil {
			t.Fatalf("injectedIdentityFrom() = (_, %v, %v), want the cookie ignored", ok, oerr)
		}
	}

	if got := strings.Count(buf.String(), authsideClaimsCookie); got != 1 {
		t.Fatalf("warned %d times across 3 requests, want exactly 1; log = %s", got, buf.String())
	}
}
