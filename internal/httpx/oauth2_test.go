package httpx_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mackee/authside/internal/httpx"
	"github.com/mackee/tanukirpc"
	"golang.org/x/oauth2"
)

// --- 8: a real client-library check. golang.org/x/oauth2 drives a token
// endpoint built on this package's codec and ErrorHooker: a successful
// exchange must work end to end, and an error response must be parsed into
// a *oauth2.RetrieveError with ErrorCode == "invalid_grant".
//
// This also doubles as the regression test for unknown-form-key tolerance:
// golang.org/x/oauth2 always attempts client_secret_basic (client_id and
// client_secret in the Authorization header) first, and only on a failed
// attempt retries with client_secret_post (client_id and client_secret
// moved into the POST body). formRequest below declares only grant_type
// and code -- if the form codec were still strict about unknown keys, the
// client_secret_post retry in TestOAuth2Exchange_ErrorParsedAsRetrieveError
// would itself fail to decode (masking the intended invalid_grant behind a
// decode error), so that test only passes if unknown keys are genuinely
// ignored, not merely worked around in the test.

const oauth2TestGrantCode = "good-code"

func newOAuth2TestRouter(t *testing.T, fail bool) *tanukirpc.Router[reg] {
	t.Helper()
	router := httpx.NewRouter(reg{})
	router.Post("/token", tanukirpc.NewHandler(func(ctx tanukirpc.Context[reg], req formRequest) (*tokenResponse, error) {
		if fail {
			return nil, httpx.InvalidGrant("the authorization code is invalid or expired")
		}
		if req.GrantType != "authorization_code" || req.Code != oauth2TestGrantCode {
			return nil, httpx.InvalidGrant("unexpected request")
		}
		return &tokenResponse{AccessToken: "real-access-token", TokenType: "Bearer"}, nil
	}))
	return router
}

func TestOAuth2Exchange_Success(t *testing.T) {
	router := newOAuth2TestRouter(t, false)
	srv := httptest.NewServer(router)
	defer srv.Close()

	cfg := &oauth2.Config{
		ClientID:     "client-1",
		ClientSecret: "secret-1",
		Endpoint: oauth2.Endpoint{
			TokenURL: srv.URL + "/token",
		},
	}

	tok, err := cfg.Exchange(context.Background(), oauth2TestGrantCode)
	if err != nil {
		t.Fatalf("Exchange failed: %v", err)
	}
	if tok.AccessToken != "real-access-token" {
		t.Fatalf("AccessToken = %q, want real-access-token", tok.AccessToken)
	}
	if tok.TokenType != "Bearer" {
		t.Fatalf("TokenType = %q, want Bearer", tok.TokenType)
	}
}

func TestOAuth2Exchange_ErrorParsedAsRetrieveError(t *testing.T) {
	router := newOAuth2TestRouter(t, true)
	srv := httptest.NewServer(router)
	defer srv.Close()

	cfg := &oauth2.Config{
		ClientID:     "client-1",
		ClientSecret: "secret-1",
		Endpoint: oauth2.Endpoint{
			TokenURL: srv.URL + "/token",
		},
	}

	_, err := cfg.Exchange(context.Background(), "any-code")
	if err == nil {
		t.Fatal("expected an error")
	}

	retrieveErr, ok := err.(*oauth2.RetrieveError)
	if !ok {
		t.Fatalf("error is %T, want *oauth2.RetrieveError: %v", err, err)
	}
	if retrieveErr.ErrorCode != "invalid_grant" {
		t.Fatalf("ErrorCode = %q, want invalid_grant", retrieveErr.ErrorCode)
	}
	if retrieveErr.Response.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", retrieveErr.Response.StatusCode)
	}
}
