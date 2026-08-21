package oidcop

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/mackee/authside/config"
)

func postRevoke(t *testing.T, revocationURL string, form url.Values) *http.Response {
	t.Helper()
	resp, err := http.PostForm(revocationURL, form)
	if err != nil {
		t.Fatalf("POST /revocation: %v", err)
	}
	return resp
}

// TestRevocation_RefreshToken_RevokesWholeFamily is Part 4's core case:
// revoking a refresh token kills its whole family, exactly as reuse
// detection does (Part 3) -- the sibling access token and any later
// refresh with the same family all stop working.
func TestRevocation_RefreshToken_RevokesWholeFamily(t *testing.T) {
	tgt := testTarget()
	tgt.DefaultUser = "user-1"
	srv := newTestServer(t, tgt)

	code := codeFromAuthorize(t, srv, refreshTestClientID, refreshTestRedirectURI)
	tok := exchangeCodeRaw(t, srv.URL+"/token", code)

	resp := postRevoke(t, srv.URL+"/revocation", url.Values{
		"token":           {tok.RefreshToken},
		"token_type_hint": {"refresh_token"},
		"client_id":       {refreshTestClientID},
		"client_secret":   {refreshTestClientSecret},
	})
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /revocation status = %d, want 200 (RFC 7009 §2.2) (body: %s)", resp.StatusCode, body)
	}

	// The refresh token itself is now dead.
	postTokenExpectError(t, srv.URL+"/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tok.RefreshToken},
		"client_id":     {refreshTestClientID},
		"client_secret": {refreshTestClientSecret},
	}, http.StatusBadRequest, "invalid_grant")

	// The access token minted alongside it at exchange is dead too (its
	// family was revoked).
	if status := userinfoStatus(t, srv.URL+"/userinfo", tok.AccessToken); status != http.StatusUnauthorized {
		t.Fatalf("/userinfo after revoking the refresh token: status = %d, want 401", status)
	}
}

// TestRevocation_AccessToken_DoesNotRevokeRefreshTokenFamily is Part 4's
// documented choice: revoking an access token invalidates only that
// access token, and deliberately does not cascade into the refresh
// token/family (RFC 7009 §2.1's cascade is a MAY, not a MUST) -- see
// revocation.go's revocationHandler doc comment for the reasoning.
func TestRevocation_AccessToken_DoesNotRevokeRefreshTokenFamily(t *testing.T) {
	tgt := testTarget()
	tgt.DefaultUser = "user-1"
	srv := newTestServer(t, tgt)

	code := codeFromAuthorize(t, srv, refreshTestClientID, refreshTestRedirectURI)
	tok := exchangeCodeRaw(t, srv.URL+"/token", code)

	resp := postRevoke(t, srv.URL+"/revocation", url.Values{
		"token":           {tok.AccessToken},
		"token_type_hint": {"access_token"},
		"client_id":       {refreshTestClientID},
		"client_secret":   {refreshTestClientSecret},
	})
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /revocation status = %d, want 200 (body: %s)", resp.StatusCode, body)
	}

	// The access token is dead.
	if status := userinfoStatus(t, srv.URL+"/userinfo", tok.AccessToken); status != http.StatusUnauthorized {
		t.Fatalf("/userinfo after revoking the access token: status = %d, want 401", status)
	}

	// But the refresh token from the very same exchange must still work.
	refreshed, refreshResp := refreshRaw(t, srv.URL+"/token", tok.RefreshToken, refreshTestClientID, refreshTestClientSecret)
	if refreshResp.StatusCode != http.StatusOK {
		t.Fatalf("refresh after revoking only the access token: status = %d, want 200 (access-token revocation must not cascade into the refresh token)", refreshResp.StatusCode)
	}
	if refreshed.AccessToken == "" {
		t.Fatalf("refresh succeeded but returned no access_token")
	}
}

// TestRevocation_UnknownToken_Returns200 is RFC 7009 §2.2's core rule:
// an unrecognised token must not be distinguishable, at the wire, from a
// token that really was just revoked.
func TestRevocation_UnknownToken_Returns200(t *testing.T) {
	tgt := testTarget()
	srv := newTestServer(t, tgt)

	resp := postRevoke(t, srv.URL+"/revocation", url.Values{
		"token":         {"this-token-was-never-issued"},
		"client_id":     {refreshTestClientID},
		"client_secret": {refreshTestClientSecret},
	})
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 for an unknown token (RFC 7009 §2.2) (body: %s)", resp.StatusCode, body)
	}
}

// TestRevocation_TokenBelongingToAnotherClient_Returns200NoRevocation
// confirms the ownership check does not leak whether a token exists for
// a different client: it looks, at the wire, exactly like "unknown
// token" (200, no visible effect), while the real owner's token stays
// alive.
func TestRevocation_TokenBelongingToAnotherClient_Returns200NoRevocation(t *testing.T) {
	tgt := testTarget()
	tgt.DefaultUser = "user-1"
	tgt.Clients = append(tgt.Clients, config.Client{
		ClientID:     "client-2",
		ClientSecret: "secret-2",
		RedirectURIs: []string{"https://other.example/cb"},
	})
	srv := newTestServer(t, tgt)

	code := codeFromAuthorize(t, srv, refreshTestClientID, refreshTestRedirectURI)
	tok := exchangeCodeRaw(t, srv.URL+"/token", code)

	// client-2 tries to revoke client-1's refresh token.
	resp := postRevoke(t, srv.URL+"/revocation", url.Values{
		"token":         {tok.RefreshToken},
		"client_id":     {"client-2"},
		"client_secret": {"secret-2"},
	})
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", resp.StatusCode, body)
	}

	// The real owner's refresh token must still work.
	if _, refreshResp := refreshRaw(t, srv.URL+"/token", tok.RefreshToken, refreshTestClientID, refreshTestClientSecret); refreshResp.StatusCode != http.StatusOK {
		t.Fatalf("refresh by the rightful owner after another client's revocation attempt: status = %d, want 200 (the token must NOT actually have been revoked)", refreshResp.StatusCode)
	}
}

// TestRevocation_ClientSecretBasic confirms /revocation accepts
// client_secret_basic, not just client_secret_post -- Part 4 requires
// "the same two methods" as /token.
func TestRevocation_ClientSecretBasic(t *testing.T) {
	tgt := testTarget()
	tgt.DefaultUser = "user-1"
	srv := newTestServer(t, tgt)

	code := codeFromAuthorize(t, srv, refreshTestClientID, refreshTestRedirectURI)
	tok := exchangeCodeRaw(t, srv.URL+"/token", code)

	form := url.Values{"token": {tok.RefreshToken}}
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/revocation", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(refreshTestClientID+":"+refreshTestClientSecret)))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /revocation (client_secret_basic): %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", resp.StatusCode, body)
	}

	// It must have actually revoked: the refresh token is now dead.
	postTokenExpectError(t, srv.URL+"/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tok.RefreshToken},
		"client_id":     {refreshTestClientID},
		"client_secret": {refreshTestClientSecret},
	}, http.StatusBadRequest, "invalid_grant")
}

func TestRevocation_ClientAuthFailure_Returns401(t *testing.T) {
	tgt := testTarget()
	srv := newTestServer(t, tgt)

	resp := postRevoke(t, srv.URL+"/revocation", url.Values{
		"token":         {"whatever"},
		"client_id":     {refreshTestClientID},
		"client_secret": {"wrong-secret"},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for a failed client authentication", resp.StatusCode)
	}
}

func TestRevocation_MissingToken_Returns400InvalidRequest(t *testing.T) {
	tgt := testTarget()
	srv := newTestServer(t, tgt)

	resp := postRevoke(t, srv.URL+"/revocation", url.Values{
		"client_id":     {refreshTestClientID},
		"client_secret": {refreshTestClientSecret},
	})
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a missing token (body: %s)", resp.StatusCode, body)
	}
}

// TestRevocation_ConfiguredError is README "Negative testing" > errors:
// {revocation: ...}.
func TestRevocation_ConfiguredError(t *testing.T) {
	tgt := testTarget()
	tgt.Errors = map[string]config.ErrorSpec{"revocation": "invalid_request"}
	srv := newTestServer(t, tgt)

	resp := postRevoke(t, srv.URL+"/revocation", url.Values{
		"token":         {"whatever"},
		"client_id":     {refreshTestClientID},
		"client_secret": {refreshTestClientSecret},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (errors: {revocation: invalid_request})", resp.StatusCode)
	}
}
