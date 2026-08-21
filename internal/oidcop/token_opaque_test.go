package oidcop

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mackee/authside/config"
)

// This file covers access_token: opaque. The implementation is one
// branch -- token.go's mintAccessToken -- precisely because /userinfo
// resolves an access token by lookup in the session store rather than by
// parsing it (sessions.go). These tests are here to prove that claim
// rather than assume it: every access-token behaviour the jwt format has
// (userinfo, revocation, family revocation, negative TTL, refresh) must
// hold identically for opaque.

// opaqueTarget is testTarget() switched to access_token: opaque, with a
// default_user so login: auto can issue without a cookie.
//
// testTarget()'s TTLs default to 0, which mints a token that expires the
// instant it is issued -- fine for tests that never present one, useless
// here, where /userinfo accepting the token is the whole assertion. Every
// case in this file therefore gets a real TTL, and the one that wants an
// expired token (TestOpaque_NegativeAccessTokenTTLIsBornExpired) sets a
// negative one explicitly rather than relying on the zero value, so that
// what it is testing is visible at the call site.
func opaqueTarget() *config.Target {
	tgt := testTarget()
	tgt.AccessToken = config.AccessTokenOpaque
	tgt.DefaultUser = "user-1"
	realTTL := config.Duration(time.Hour)
	tgt.IDTokenTTL = &realTTL
	tgt.AccessTokenTTL = &realTTL
	return tgt
}

// userinfoClaims is userinfoStatus (token_refresh_test.go) plus the
// decoded body, which the opaque cases need: proving /userinfo answers
// correctly for a token that carries no claims of its own is the whole
// point, and a bare status code cannot show that.
func userinfoClaims(t *testing.T, userinfoURL, token string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, userinfoURL, nil)
	if err != nil {
		t.Fatalf("building /userinfo request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /userinfo: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decoding /userinfo body: %v (body: %s)", err, body)
	}
	return resp.StatusCode, out
}

// assertOpaque fails unless token looks like an opaque handle rather than
// a JWT. A JWT is three base64url segments separated by dots, so the
// absence of any dot is what makes an opaque token unparseable as one --
// which is the whole point of the format: an application that quietly
// decodes its access token instead of just presenting it must break
// here, visibly, rather than in production against the real provider.
func assertOpaque(t *testing.T, token string) {
	t.Helper()
	if token == "" {
		t.Fatal("access token is empty")
	}
	if strings.Contains(token, ".") {
		t.Fatalf("access token %q contains a dot, so it is JWT-shaped; want an opaque handle", token)
	}
}

// TestOpaque_UserinfoResolvesAnOpaqueAccessToken is the core case: the
// token carries no claims at all, so /userinfo answering correctly proves
// the answer came from the session store rather than from the token.
func TestOpaque_UserinfoResolvesAnOpaqueAccessToken(t *testing.T) {
	srv := newTestServer(t, opaqueTarget())

	code := codeFromAuthorize(t, srv, refreshTestClientID, refreshTestRedirectURI)
	tok := exchangeCodeRaw(t, srv.URL+"/token", code)
	assertOpaque(t, tok.AccessToken)

	status, info := userinfoClaims(t, srv.URL+"/userinfo", tok.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("/userinfo status = %d, want 200", status)
	}
	if info["sub"] != "user-1" {
		t.Fatalf("/userinfo sub = %v, want user-1", info["sub"])
	}
	if info["email"] != "alice@example.com" {
		t.Fatalf("/userinfo email = %v, want the claims the token was issued for", info["email"])
	}
}

// TestOpaque_EveryExchangeMintsADistinctToken guards against the failure
// where mintAccessToken returns something derived from the target rather
// than freshly random: two logins sharing one access token would make
// revoking either revoke both.
func TestOpaque_EveryExchangeMintsADistinctToken(t *testing.T) {
	srv := newTestServer(t, opaqueTarget())

	first := exchangeCodeRaw(t, srv.URL+"/token", codeFromAuthorize(t, srv, refreshTestClientID, refreshTestRedirectURI))
	second := exchangeCodeRaw(t, srv.URL+"/token", codeFromAuthorize(t, srv, refreshTestClientID, refreshTestRedirectURI))

	assertOpaque(t, first.AccessToken)
	assertOpaque(t, second.AccessToken)
	if first.AccessToken == second.AccessToken {
		t.Fatalf("two exchanges returned the same access token %q, want distinct random tokens", first.AccessToken)
	}
}

// TestOpaque_RefreshGrantAlsoMintsOpaque: the format is a property of the
// target, not of the grant that happened to mint the token, so
// issueFromRefresh must honour it too (both grants route through the same
// mintAccessToken -- this proves neither path was missed).
func TestOpaque_RefreshGrantAlsoMintsOpaque(t *testing.T) {
	srv := newTestServer(t, opaqueTarget())

	code := codeFromAuthorize(t, srv, refreshTestClientID, refreshTestRedirectURI)
	tok := exchangeCodeRaw(t, srv.URL+"/token", code)

	refreshed, resp := refreshRaw(t, srv.URL+"/token", tok.RefreshToken, refreshTestClientID, refreshTestClientSecret)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh status = %d, want 200", resp.StatusCode)
	}
	assertOpaque(t, refreshed.AccessToken)
	if refreshed.AccessToken == tok.AccessToken {
		t.Fatalf("refresh returned the same access token, want a fresh one")
	}

	if status, info := userinfoClaims(t, srv.URL+"/userinfo", refreshed.AccessToken); status != http.StatusOK || info["sub"] != "user-1" {
		t.Fatalf("/userinfo with the refreshed opaque token = %d %v, want 200 and sub=user-1", status, info)
	}
}

// TestOpaque_NegativeAccessTokenTTLIsBornExpired: expiry lives on the
// session record, not in the token, so a negative access_token_ttl must
// work for opaque exactly as it does for jwt (README "Scenarios are
// configuration").
func TestOpaque_NegativeAccessTokenTTLIsBornExpired(t *testing.T) {
	tgt := opaqueTarget()
	negative := config.Duration(-5 * time.Minute)
	tgt.AccessTokenTTL = &negative
	srv := newTestServer(t, tgt)

	code := codeFromAuthorize(t, srv, refreshTestClientID, refreshTestRedirectURI)
	tok := exchangeCodeRaw(t, srv.URL+"/token", code)
	assertOpaque(t, tok.AccessToken)

	if status := userinfoStatus(t, srv.URL+"/userinfo", tok.AccessToken); status != http.StatusUnauthorized {
		t.Fatalf("/userinfo status = %d, want 401 for an already-expired opaque access token", status)
	}
}

// TestOpaque_RevocationRevokesAnOpaqueAccessToken: POST /revocation
// resolves the token through the same store, so revoking an opaque access
// token must take effect at /userinfo immediately.
func TestOpaque_RevocationRevokesAnOpaqueAccessToken(t *testing.T) {
	srv := newTestServer(t, opaqueTarget())

	code := codeFromAuthorize(t, srv, refreshTestClientID, refreshTestRedirectURI)
	tok := exchangeCodeRaw(t, srv.URL+"/token", code)

	if status := userinfoStatus(t, srv.URL+"/userinfo", tok.AccessToken); status != http.StatusOK {
		t.Fatalf("/userinfo before revocation = %d, want 200", status)
	}

	resp, err := http.PostForm(srv.URL+"/revocation", url.Values{
		"token":         {tok.AccessToken},
		"client_id":     {refreshTestClientID},
		"client_secret": {refreshTestClientSecret},
	})
	if err != nil {
		t.Fatalf("POST /revocation: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /revocation status = %d, want 200", resp.StatusCode)
	}

	if status := userinfoStatus(t, srv.URL+"/userinfo", tok.AccessToken); status != http.StatusUnauthorized {
		t.Fatalf("/userinfo after revocation = %d, want 401", status)
	}
}

// TestOpaque_FamilyRevocationKillsTrackedOpaqueAccessTokens: replaying a
// retired refresh token revokes the whole family, including every access
// token minted along it. The family bookkeeping never looks inside an
// access token, so this should be free -- prove it rather than assume it.
func TestOpaque_FamilyRevocationKillsTrackedOpaqueAccessTokens(t *testing.T) {
	srv := newTestServer(t, opaqueTarget())

	code := codeFromAuthorize(t, srv, refreshTestClientID, refreshTestRedirectURI)
	first := exchangeCodeRaw(t, srv.URL+"/token", code)
	second, resp := refreshRaw(t, srv.URL+"/token", first.RefreshToken, refreshTestClientID, refreshTestClientSecret)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first refresh status = %d, want 200", resp.StatusCode)
	}

	// Replay the now-retired refresh token: reuse detection revokes the
	// family.
	postTokenExpectError(t, srv.URL+"/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {first.RefreshToken},
		"client_id":     {refreshTestClientID},
		"client_secret": {refreshTestClientSecret},
	}, http.StatusBadRequest, "invalid_grant")

	for name, token := range map[string]string{
		"the original opaque access token":  first.AccessToken,
		"the refreshed opaque access token": second.AccessToken,
	} {
		if status := userinfoStatus(t, srv.URL+"/userinfo", token); status != http.StatusUnauthorized {
			t.Fatalf("/userinfo with %s after family revocation = %d, want 401", name, status)
		}
	}
}

// TestOpaque_TamperLeavesTheIDTokenTamperedAndTheAccessTokenOpaque pins
// the scope decision in mintAccessToken's doc comment: tamper values that
// name access-token claims have nothing to act on when the access token
// carries no claims, and that must not turn into either an error or a
// silently un-tampered ID token.
func TestOpaque_TamperLeavesTheIDTokenTamperedAndTheAccessTokenOpaque(t *testing.T) {
	tgt := opaqueTarget()
	tgt.Tamper = []config.TamperTarget{config.TamperIss}
	srv := newTestServer(t, tgt)

	code := codeFromAuthorize(t, srv, refreshTestClientID, refreshTestRedirectURI)
	tok := exchangeCodeRaw(t, srv.URL+"/token", code)

	// The access token is still an ordinary opaque handle, and still
	// resolves: there is no iss claim on it to corrupt.
	assertOpaque(t, tok.AccessToken)
	if status := userinfoStatus(t, srv.URL+"/userinfo", tok.AccessToken); status != http.StatusOK {
		t.Fatalf("/userinfo = %d, want 200: tamper: [iss] has nothing to corrupt on an opaque access token", status)
	}

	// The ID token from the same exchange is tampered as configured.
	if iss := decodeJWSPayload(t, tok.IDToken)["iss"]; iss == tgt.Issuer {
		t.Fatalf("id_token iss = %v, want it corrupted by tamper: [iss]", iss)
	}
}
