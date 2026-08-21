package oidcop

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/mackee/authside/config"
)

// rawTokenResponse mirrors POST /token's JSON body, for tests that drive
// the wire directly with net/http rather than through x/oauth2.
type rawTokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

// postTokenExpectError POSTs form to tokenURL and asserts a response
// carrying wantStatus and wantErrorCode.
func postTokenExpectError(t *testing.T, tokenURL string, form url.Values, wantStatus int, wantErrorCode string) {
	t.Helper()
	resp, err := http.PostForm(tokenURL, form)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != wantStatus {
		t.Fatalf("status = %d, want %d (body: %s)", resp.StatusCode, wantStatus, body)
	}
	var out struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decoding error response: %v (body: %s)", err, body)
	}
	if out.Error != wantErrorCode {
		t.Fatalf("error = %q, want %q (body: %s)", out.Error, wantErrorCode, body)
	}
}

const (
	refreshTestClientID     = "client-1"
	refreshTestClientSecret = "secret-1"
	refreshTestRedirectURI  = "https://app.example/cb"
)

func exchangeCodeRaw(t *testing.T, tokenURL, code string) rawTokenResponse {
	t.Helper()
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {refreshTestRedirectURI},
		"client_id":     {refreshTestClientID},
		"client_secret": {refreshTestClientSecret},
	}
	resp, err := http.PostForm(tokenURL, form)
	if err != nil {
		t.Fatalf("POST /token (exchange): %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("exchange status = %d, want 200 (body: %s)", resp.StatusCode, body)
	}
	var out rawTokenResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decoding exchange response: %v (body: %s)", err, body)
	}
	return out
}

// refreshRaw POSTs grant_type=refresh_token and returns the decoded
// response (zero value on non-200) plus the raw *http.Response for the
// caller to inspect status on.
func refreshRaw(t *testing.T, tokenURL, refreshToken, clientID, clientSecret string) (rawTokenResponse, *http.Response) {
	t.Helper()
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	resp, err := http.PostForm(tokenURL, form)
	if err != nil {
		t.Fatalf("POST /token (refresh): %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return rawTokenResponse{}, resp
	}
	var out rawTokenResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decoding refresh response: %v (body: %s)", err, body)
	}
	return out, resp
}

// concurrentRefreshAttempt is refreshRaw's goroutine-safe twin: it never
// touches a *testing.T, since t.Fatalf (which refreshRaw and its callees
// use on a decode failure) must only ever be called from the goroutine
// running the test itself -- see
// TestToken_RefreshGrant_ConcurrentReplaySameToken_OverHTTP, which calls
// this from many goroutines at once.
func concurrentRefreshAttempt(tokenURL, refreshToken, clientID, clientSecret string) (status int, out rawTokenResponse, err error) {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	resp, err := http.PostForm(tokenURL, form)
	if err != nil {
		return 0, rawTokenResponse{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, rawTokenResponse{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, rawTokenResponse{}, nil
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return resp.StatusCode, rawTokenResponse{}, err
	}
	return resp.StatusCode, out, nil
}

func userinfoStatus(t *testing.T, userinfoURL, accessToken string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, userinfoURL, nil)
	if err != nil {
		t.Fatalf("building /userinfo request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /userinfo: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func TestToken_AuthorizationCode_IssuesRefreshToken(t *testing.T) {
	tgt := testTarget()
	tgt.DefaultUser = "user-1"
	srv := newTestServer(t, tgt)

	code := codeFromAuthorize(t, srv, refreshTestClientID, refreshTestRedirectURI)
	tok := exchangeCodeRaw(t, srv.URL+"/token", code)

	if tok.RefreshToken == "" {
		t.Fatalf("token response has no refresh_token (offline_access gating decision: refresh tokens are issued unconditionally)")
	}
	if tok.AccessToken == "" || tok.IDToken == "" {
		t.Fatalf("token response missing access_token/id_token")
	}
}

// TestToken_RefreshGrant_ViaXOAuth2_RotatesAndReturnsVerifiableIDToken
// drives a real golang.org/x/oauth2 TokenSource through one rotation, and
// re-verifies the refreshed id_token with coreos/go-oidc -- the two
// libraries the root acceptance tests use, exercised the same way here so
// the refresh grant is proven against a real client, not just raw HTTP.
//
// Discovery's issuer must byte-match the URL passed to oidc.NewProvider,
// so (like discovery_test.go's TestDiscovery_SimpleMode_Unchanged) this
// builds the target against a not-yet-started httptest.Server, whose
// address is known before Start.
func TestToken_RefreshGrant_ViaXOAuth2_RotatesAndReturnsVerifiableIDToken(t *testing.T) {
	srv := httptest.NewUnstartedServer(nil)
	baseURL := "http://" + srv.Listener.Addr().String()

	tgt := testTarget()
	tgt.DefaultUser = "user-1"
	tgt.Issuer = baseURL
	tgt.Mount = ""
	// testTarget()'s IDTokenTTL/AccessTokenTTL default to 0 (expires the
	// instant it is issued -- convenient for tests that never actually
	// verify exp), which would make go-oidc's real Verify() reject even
	// the very first id_token as expired. This test needs both to
	// actually verify, so give them a real TTL.
	realTTL := config.Duration(time.Hour)
	tgt.IDTokenTTL = &realTTL
	tgt.AccessTokenTTL = &realTTL

	handler, err := New(tgt, nil, nil)
	if err != nil {
		t.Fatalf("New() = %v", err)
	}
	srv.Config.Handler = handler
	srv.Start()
	defer srv.Close()

	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, baseURL)
	if err != nil {
		t.Fatalf("oidc.NewProvider: %v", err)
	}

	oauth2Config := &oauth2.Config{
		ClientID:     refreshTestClientID,
		ClientSecret: refreshTestClientSecret,
		RedirectURL:  refreshTestRedirectURI,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID},
	}

	code := codeFromAuthorize(t, srv, refreshTestClientID, refreshTestRedirectURI)
	tok, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if tok.RefreshToken == "" {
		t.Fatalf("Exchange result has no RefreshToken")
	}
	firstRefreshToken := tok.RefreshToken

	// Force a refresh by handing TokenSource an already-expired token
	// alongside the real refresh token.
	expired := &oauth2.Token{
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		Expiry:       time.Now().Add(-time.Hour),
	}

	src := oauth2Config.TokenSource(ctx, expired)
	refreshed, err := src.Token()
	if err != nil {
		t.Fatalf("TokenSource.Token() (refresh): %v", err)
	}
	if refreshed.AccessToken == "" {
		t.Fatalf("refreshed token has no access_token")
	}
	if refreshed.RefreshToken == "" || refreshed.RefreshToken == firstRefreshToken {
		t.Fatalf("refreshed RefreshToken = %q (same as original %q), want a NEW refresh token -- README's argument for rotate-by-default is that x/oauth2 hands back a new one the app must persist", refreshed.RefreshToken, firstRefreshToken)
	}

	rawIDToken, ok := refreshed.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		t.Fatalf("refreshed token response has no id_token -- a client that re-verifies after refresh has nothing to verify")
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: refreshTestClientID})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		t.Fatalf("Verify(refreshed id_token): %v", err)
	}
	if idToken.Subject != "user-1" {
		t.Fatalf("refreshed id_token subject = %q, want user-1", idToken.Subject)
	}
}

func TestToken_RefreshGrant_WrongClientRejected(t *testing.T) {
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

	_, resp := refreshRaw(t, srv.URL+"/token", tok.RefreshToken, "client-2", "secret-2")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("refresh with a different client's credentials: status = %d, want 400", resp.StatusCode)
	}

	// The rightful owner must still be able to refresh afterwards.
	if _, resp2 := refreshRaw(t, srv.URL+"/token", tok.RefreshToken, refreshTestClientID, refreshTestClientSecret); resp2.StatusCode != http.StatusOK {
		t.Fatalf("refresh by the rightful client after a wrong-client attempt: status = %d, want 200", resp2.StatusCode)
	}
}

// TestToken_RefreshGrant_FullReuseDetectionSequence is Part 3's exit
// test: exchange -> refresh (A retired, B issued) -> refresh with B works
// -> replay A -> invalid_grant, and then the whole family (including B's
// own successor and the access tokens minted along the chain) is dead,
// confirmed by both a further /token refresh attempt and a /userinfo
// call with the chain's access tokens.
func TestToken_RefreshGrant_FullReuseDetectionSequence(t *testing.T) {
	tgt := testTarget()
	tgt.DefaultUser = "user-1"
	srv := newTestServer(t, tgt)
	tokenURL := srv.URL + "/token"

	code := codeFromAuthorize(t, srv, refreshTestClientID, refreshTestRedirectURI)
	exchanged := exchangeCodeRaw(t, tokenURL, code)
	tokenA := exchanged.RefreshToken
	accessTokenFromExchange := exchanged.AccessToken

	refreshedWithA, respA := refreshRaw(t, tokenURL, tokenA, refreshTestClientID, refreshTestClientSecret)
	if respA.StatusCode != http.StatusOK {
		t.Fatalf("refresh(A) status = %d, want 200", respA.StatusCode)
	}
	tokenB := refreshedWithA.RefreshToken
	if tokenB == "" || tokenB == tokenA {
		t.Fatalf("refresh(A) did not rotate: got refresh_token %q", tokenB)
	}

	refreshedWithB, respB := refreshRaw(t, tokenURL, tokenB, refreshTestClientID, refreshTestClientSecret)
	if respB.StatusCode != http.StatusOK {
		t.Fatalf("refresh(B) status = %d, want 200 (\"refresh with B works\")", respB.StatusCode)
	}
	tokenC := refreshedWithB.RefreshToken
	accessTokenFromB := refreshedWithB.AccessToken

	// Replay the already-retired A: reuse detected.
	postTokenExpectError(t, tokenURL, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tokenA},
		"client_id":     {refreshTestClientID},
		"client_secret": {refreshTestClientSecret},
	}, http.StatusBadRequest, "invalid_grant")

	// The whole family is now dead: C (never itself retired) must also
	// fail -- the real proof this is family-wide, not per-token.
	postTokenExpectError(t, tokenURL, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tokenC},
		"client_id":     {refreshTestClientID},
		"client_secret": {refreshTestClientSecret},
	}, http.StatusBadRequest, "invalid_grant")

	// Every access token minted along the chain is dead at /userinfo.
	accessTokens := map[string]string{
		"from exchange":   accessTokenFromExchange,
		"from refresh(B)": accessTokenFromB,
	}
	for name, at := range accessTokens {
		if status := userinfoStatus(t, srv.URL+"/userinfo", at); status != http.StatusUnauthorized {
			t.Errorf("/userinfo with access token %s: status = %d, want 401 (token must be dead after family revocation)", name, status)
		}
	}
}

func TestToken_RefreshGrant_StaticMode_NoRotationNoReuseDetection(t *testing.T) {
	tgt := testTarget()
	tgt.DefaultUser = "user-1"
	tgt.RefreshToken = config.RefreshStatic
	srv := newTestServer(t, tgt)
	tokenURL := srv.URL + "/token"

	code := codeFromAuthorize(t, srv, refreshTestClientID, refreshTestRedirectURI)
	exchanged := exchangeCodeRaw(t, tokenURL, code)
	token := exchanged.RefreshToken
	if token == "" {
		t.Fatalf("static mode: no refresh_token issued at exchange")
	}

	for i := 0; i < 3; i++ {
		refreshed, resp := refreshRaw(t, tokenURL, token, refreshTestClientID, refreshTestClientSecret)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("static mode refresh #%d: status = %d, want 200 (repeated use must not trip reuse detection)", i, resp.StatusCode)
		}
		if refreshed.RefreshToken != token {
			t.Fatalf("static mode refresh #%d: refresh_token = %q, want the SAME token %q (static must not rotate)", i, refreshed.RefreshToken, token)
		}
	}
}

// TestToken_RefreshGrant_ConcurrentReplaySameToken_OverHTTP is the
// HTTP-level twin of TestRefreshStore_ConcurrentReplaySameToken: N real
// concurrent POST /token requests, all presenting the very same
// not-yet-retired refresh token, against a real *httptest.Server. Exactly
// one must get a 200 (a fresh access/refresh token pair); every other one
// must get invalid_grant. The winner's own freshly-minted access token
// must then be dead at /userinfo, and its own freshly-minted refresh
// token must be dead at /token too -- proving the family-revocation race
// window (refreshStore.refresh returns -> token.go mints access/id
// tokens -> trackAccessToken registers them) is closed end to end, not
// just at the store level.
//
// Run with -race.
func TestToken_RefreshGrant_ConcurrentReplaySameToken_OverHTTP(t *testing.T) {
	tgt := testTarget()
	tgt.DefaultUser = "user-1"
	srv := newTestServer(t, tgt)
	tokenURL := srv.URL + "/token"

	code := codeFromAuthorize(t, srv, refreshTestClientID, refreshTestRedirectURI)
	exchanged := exchangeCodeRaw(t, tokenURL, code)
	token := exchanged.RefreshToken

	const n = 15
	var (
		mu                sync.Mutex
		wg                sync.WaitGroup
		succeeded, failed int
		winner            rawTokenResponse
	)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			// concurrentRefreshAttempt (not refreshRaw) is used here
			// deliberately: t.Fatalf is only safe to call from the
			// goroutine running the test itself, never from a spawned
			// goroutine, so this helper reports failures through its
			// return values instead.
			status, resp, err := concurrentRefreshAttempt(tokenURL, token, refreshTestClientID, refreshTestClientSecret)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				t.Errorf("POST /token (concurrent refresh): %v", err)
				failed++
				return
			}
			if status != http.StatusOK {
				failed++
				return
			}
			succeeded++
			winner = resp
		}()
	}
	wg.Wait()

	if succeeded != 1 {
		t.Fatalf("succeeded = %d, want exactly 1 (concurrent replays of the same token, rest must be invalid_grant)", succeeded)
	}
	if failed != n-1 {
		t.Fatalf("failed = %d, want %d", failed, n-1)
	}

	if status := userinfoStatus(t, srv.URL+"/userinfo", winner.AccessToken); status != http.StatusUnauthorized {
		t.Fatalf("/userinfo with the concurrent-refresh winner's access token: status = %d, want 401 (the family was revoked by the losing replays)", status)
	}
	if _, resp := refreshRaw(t, tokenURL, winner.RefreshToken, refreshTestClientID, refreshTestClientSecret); resp.StatusCode == http.StatusOK {
		t.Fatalf("refresh with the concurrent-refresh winner's own new refresh token succeeded, want invalid_grant (family revoked)")
	}
}
