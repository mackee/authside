package oidcop

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mackee/authside/internal/httpx"
)

func TestRedirectURIRegistered(t *testing.T) {
	registered := []string{"https://app.example/cb", "https://app.example/cb2"}

	tests := []struct {
		uri  string
		want bool
	}{
		{"https://app.example/cb", true},
		{"https://app.example/cb2", true},
		// Exact match is deliberate strictness (README "Strict about the
		// protocol"): a trailing slash, a different path, or an extra
		// query parameter must all be rejected, not fuzzily accepted.
		{"https://app.example/cb/", false},
		{"https://app.example/cb?x=1", false},
		{"https://app.example/CB", false},
		{"https://evil.example/cb", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := redirectURIRegistered(registered, tt.uri); got != tt.want {
			t.Errorf("redirectURIRegistered(_, %q) = %v, want %v", tt.uri, got, tt.want)
		}
	}
}

func TestSubjectForAuto(t *testing.T) {
	t.Run("cookie wins", func(t *testing.T) {
		target := &Target{name: "oidc", defaultUser: "user-default"}
		req := httptest.NewRequest(http.MethodGet, "/authorize", nil)
		req.AddCookie(&http.Cookie{Name: authsideSubCookie, Value: "user-cookie"})

		got, err := subjectForAuto(req, target)
		if err != nil {
			t.Fatalf("subjectForAuto() error = %v", err)
		}
		if got != "user-cookie" {
			t.Fatalf("subject = %q, want user-cookie", got)
		}
	})

	t.Run("falls back to default_user without a cookie", func(t *testing.T) {
		target := &Target{name: "oidc", defaultUser: "user-default"}
		req := httptest.NewRequest(http.MethodGet, "/authorize", nil)

		got, err := subjectForAuto(req, target)
		if err != nil {
			t.Fatalf("subjectForAuto() error = %v", err)
		}
		if got != "user-default" {
			t.Fatalf("subject = %q, want user-default", got)
		}
	})

	t.Run("neither cookie nor default_user is an error", func(t *testing.T) {
		target := &Target{name: "oidc"}
		req := httptest.NewRequest(http.MethodGet, "/authorize", nil)

		_, err := subjectForAuto(req, target)
		if err == nil {
			t.Fatalf("subjectForAuto() = nil error, want login_required")
		}
		if err.Code != httpx.ErrLoginRequired {
			t.Fatalf("error code = %q, want login_required", err.Code)
		}
		// README: "Make the error message say exactly how to fix it (set
		// the cookie or configure default_user)."
		if !strings.Contains(err.Description, authsideSubCookie) || !strings.Contains(err.Description, "default_user") {
			t.Fatalf("description = %q, want it to mention both %q and default_user", err.Description, authsideSubCookie)
		}
	})
}
