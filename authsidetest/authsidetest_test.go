package authsidetest_test

// This file is authsidetest's own exit test: it drives the package
// exactly the way an application's test suite would -- coreos/go-oidc for
// discovery and ID token verification, golang.org/x/oauth2 (with PKCE)
// for the authorization-code exchange -- against authsidetest.NewOIDC,
// with no shortcut into authside's or authsidetest's internals. The
// helpers below (noFollowClient, driveAuthorize) intentionally mirror
// authside_test.go's identically-named ones at the repo root: this
// package is the thing that is supposed to make those helpers
// unnecessary for a library caller, so reusing the same shape here is
// the point, not an oversight.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/mackee/authside"
	"github.com/mackee/authside/authsidetest"
)

// noFollowClient stops client from following the redirect /authorize
// issues, so the test can inspect the Location header (the authorization
// code and state) directly instead of the client trying to actually dial
// the -- generally non-existent -- redirect_uri.
func noFollowClient(client *http.Client) *http.Client {
	out := *client
	out.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &out
}

// driveAuthorize builds an authorization request (with PKCE) from
// oauth2Config, sends it through client, and returns the code and state
// from /authorize's redirect back to redirect_uri. verifier is the PKCE
// code_verifier to pass to Exchange afterward.
func driveAuthorize(t *testing.T, client *http.Client, oauth2Config *oauth2.Config, state, nonce string) (code, gotState, verifier string) {
	t.Helper()

	verifier = oauth2.GenerateVerifier()
	authURL := oauth2Config.AuthCodeURL(state,
		oauth2.S256ChallengeOption(verifier),
		oauth2.SetAuthURLParam("nonce", nonce),
	)

	resp, err := noFollowClient(client).Get(authURL)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("GET /authorize status = %d, want 302", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parsing Location: %v", err)
	}
	if errCode := loc.Query().Get("error"); errCode != "" {
		t.Fatalf("authorize redirected with error=%s (%s)", errCode, loc.Query().Get("error_description"))
	}
	return loc.Query().Get("code"), loc.Query().Get("state"), verifier
}

// oauth2ConfigFor builds the golang.org/x/oauth2 config a real application
// would use against as, via vanilla OIDC discovery.
func oauth2ConfigFor(t *testing.T, ctx context.Context, as *authsidetest.OIDC) (*oauth2.Config, *oidc.Provider) {
	t.Helper()

	provider, err := oidc.NewProvider(ctx, as.Issuer())
	if err != nil {
		t.Fatalf("oidc.NewProvider: %v", err)
	}
	return &oauth2.Config{
		ClientID:     as.ClientID(),
		ClientSecret: as.ClientSecret(),
		RedirectURL:  as.RedirectURI(),
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID},
	}, provider
}

// loginTokensAs drives a complete authorization-code-with-PKCE login as
// sub against as and returns the raw token pair, plus the oauth2 config
// and provider it used. It is split out of loginAs for the tests that
// need the access/refresh token strings themselves rather than the
// verified ID token.
func loginTokensAs(t *testing.T, as *authsidetest.OIDC, sub string) (*oauth2.Token, *oauth2.Config, *oidc.Provider) {
	t.Helper()
	ctx := context.Background()

	oauth2Config, provider := oauth2ConfigFor(t, ctx, as)
	client := as.ClientAs(sub)

	code, gotState, verifier := driveAuthorize(t, client, oauth2Config, "the-state-"+sub, "the-nonce-"+sub)
	if code == "" {
		t.Fatalf("no code in the /authorize redirect for sub %q", sub)
	}
	if want := "the-state-" + sub; gotState != want {
		t.Fatalf("state = %q, want %q", gotState, want)
	}

	tok, err := oauth2Config.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	return tok, oauth2Config, provider
}

// loginAs drives a complete authorization-code-with-PKCE login as sub
// against as, and returns the verified ID token's claims. It is the
// building block every test below composes.
func loginAs(t *testing.T, as *authsidetest.OIDC, sub string) *oidc.IDToken {
	t.Helper()
	ctx := context.Background()

	tok, _, provider := loginTokensAs(t, as, sub)

	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		t.Fatalf("no id_token in the token response")
	}

	verifierV := provider.Verifier(&oidc.Config{ClientID: as.ClientID(), Now: as.Now})
	idToken, err := verifierV.Verify(ctx, rawIDToken)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	return idToken
}

// TestClientAs_CookieDecidesTheSubjectNotDefaultUser is the regression
// this whole package exists to prevent: NewOIDC's target has a
// default_user (see NewOIDC's doc comment on "DefaultUser is a
// convenience"), so a test that forgot to wire ClientAs's argument
// through to the authside_sub cookie would still see a login succeed --
// just silently as the wrong user. Logging in as two different users and
// asserting each one's sub matches the ClientAs argument that produced it
// is what catches that: if ClientAs ignored sub entirely, both logins
// would come back as the same (default_user) subject and this test would
// fail on the second assertion.
func TestClientAs_CookieDecidesTheSubjectNotDefaultUser(t *testing.T) {
	as := authsidetest.NewOIDC(t,
		authsidetest.WithUsers(
			authsidetest.User{Sub: "user-1", Claims: map[string]any{"email": "user-1@example.com"}},
			authsidetest.User{Sub: "user-2", Claims: map[string]any{"email": "user-2@example.com"}},
		),
	)

	idToken1 := loginAs(t, as, "user-1")
	if idToken1.Subject != "user-1" {
		t.Fatalf("sub = %q, want user-1", idToken1.Subject)
	}

	idToken2 := loginAs(t, as, "user-2")
	if idToken2.Subject != "user-2" {
		t.Fatalf("sub = %q, want user-2 -- got default_user instead of ClientAs's argument?", idToken2.Subject)
	}
}

// TestTimeControl_AdvancePastTTLExpiresAnAlreadyIssuedToken is the reason
// Now/Advance/SetTime exist: a test must be able to pin "now", mint a
// token, and later move time forward far enough that the *same,
// unchanged* token is rejected as expired -- without sleeping for real
// and without restarting the process. This also checks that Now() itself
// reports exactly what the minted token's iat carries, which would catch
// a regression where the clock passed to WithClock diverged from the one
// Now()/Advance/SetTime operate on (two different clocks would make every
// assertion here fail, not just the second one).
func TestTimeControl_AdvancePastTTLExpiresAnAlreadyIssuedToken(t *testing.T) {
	start := time.Date(2031, 3, 4, 5, 6, 7, 0, time.UTC)
	as := authsidetest.NewOIDC(t, authsidetest.WithStartTime(start))

	if got := as.Now(); !got.Equal(start) {
		t.Fatalf("Now() before any Advance = %v, want the configured start time %v", got, start)
	}

	ctx := context.Background()
	oauth2Config, provider := oauth2ConfigFor(t, ctx, as)
	client := as.ClientAs("user-1")

	code, _, verifier := driveAuthorize(t, client, oauth2Config, "st", "no")
	if code == "" {
		t.Fatalf("no code in the /authorize redirect")
	}
	tok, err := oauth2Config.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		t.Fatalf("no id_token in the token response")
	}

	// Pin the verifier's own notion of "now" to as.Now, exactly as a
	// caller is expected to (see authside_options_test.go's identical
	// pattern at the repo root): only then does moving as's clock also
	// move the verifier's judgment of validity.
	verifierV := provider.Verifier(&oidc.Config{ClientID: as.ClientID(), Now: as.Now})

	idToken, err := verifierV.Verify(ctx, rawIDToken)
	if err != nil {
		t.Fatalf("Verify (before Advance) = %v, want a valid token", err)
	}
	if !idToken.IssuedAt.Equal(start) {
		t.Fatalf("id_token iat = %v, want %v (Now() at issuance)", idToken.IssuedAt, start)
	}

	ttl := idToken.Expiry.Sub(idToken.IssuedAt)
	as.Advance(ttl + time.Minute)
	if got := as.Now(); !got.Equal(start.Add(ttl + time.Minute)) {
		t.Fatalf("Now() after Advance = %v, want %v", got, start.Add(ttl+time.Minute))
	}

	if _, err := verifierV.Verify(ctx, rawIDToken); err == nil {
		t.Fatalf("Verify (after Advance past expiry) succeeded, want an expiry error")
	} else if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("Verify (after Advance past expiry) error = %v, want it to mention expiry", err)
	}
}

// TestRequestLog_CapturesAuthorizeAndTokenTimestampedByTheTestClock
// checks that RequestLog is wired to the same buffer authside.New writes
// to, and that every record is timestamped from the injected test clock
// rather than wall-clock time -- if WithClock and WithRequestLog were
// wired to two different clocks (or WithRequestLog were never passed to
// authside.New at all), the timestamp assertion below would fail even if
// RequestLog's line count looked fine.
func TestRequestLog_CapturesAuthorizeAndTokenTimestampedByTheTestClock(t *testing.T) {
	fixed := time.Date(2032, 7, 8, 9, 10, 11, 0, time.UTC)
	as := authsidetest.NewOIDC(t, authsidetest.WithStartTime(fixed))

	ctx := context.Background()
	oauth2Config, _ := oauth2ConfigFor(t, ctx, as)
	client := as.ClientAs("user-1")

	code, _, verifier := driveAuthorize(t, client, oauth2Config, "st", "no")
	if code == "" {
		t.Fatalf("no code in the /authorize redirect")
	}
	if _, err := oauth2Config.Exchange(ctx, code, oauth2.VerifierOption(verifier)); err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	lines := as.RequestLog()
	if len(lines) == 0 {
		t.Fatalf("RequestLog() is empty, want at least one captured line")
	}

	type record struct {
		Method string    `json:"method"`
		Path   string    `json:"path"`
		Time   time.Time `json:"time"`
	}

	var sawAuthorize, sawToken bool
	for _, line := range lines {
		var rec record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("decoding request log line %q: %v", line, err)
		}
		if !rec.Time.Equal(fixed) {
			t.Fatalf("record %+v time = %v, want %v (the injected test clock's time, not wall time)", rec, rec.Time, fixed)
		}
		switch {
		case rec.Method == http.MethodGet && strings.HasSuffix(rec.Path, "/authorize"):
			sawAuthorize = true
		case rec.Method == http.MethodPost && strings.HasSuffix(rec.Path, "/token"):
			sawToken = true
		}
	}
	if !sawAuthorize {
		t.Fatalf("no GET .../authorize record found; lines = %v", lines)
	}
	if !sawToken {
		t.Fatalf("no POST .../token record found; lines = %v", lines)
	}
}

// TestNewOIDC_DefaultsCompleteALoginAsUser1 is the "NewOIDC(t) alone
// works" contract from the package/NewOIDC doc comments: no options at
// all must still be enough to discover, authorize and exchange a token,
// logging in as the built-in default user "user-1" purely through
// default_user's fallback (no authside_sub cookie set at all -- a plain
// client, not one from ClientAs).
func TestNewOIDC_DefaultsCompleteALoginAsUser1(t *testing.T) {
	as := authsidetest.NewOIDC(t)

	if got, want := as.ClientID(), "local-app"; got != want {
		t.Fatalf("ClientID() = %q, want %q", got, want)
	}
	if got, want := as.ClientSecret(), "local-secret"; got != want {
		t.Fatalf("ClientSecret() = %q, want %q", got, want)
	}
	if got, want := as.RedirectURI(), "http://127.0.0.1/callback"; got != want {
		t.Fatalf("RedirectURI() = %q, want %q", got, want)
	}

	ctx := context.Background()
	oauth2Config, provider := oauth2ConfigFor(t, ctx, as)

	// Deliberately a plain *http.Client with no jar at all -- no
	// authside_sub cookie, so this only succeeds via default_user's
	// fallback (see NewOIDC's "DefaultUser is a convenience" doc
	// comment).
	code, _, verifier := driveAuthorize(t, &http.Client{}, oauth2Config, "st", "no")
	if code == "" {
		t.Fatalf("no code in the /authorize redirect")
	}

	tok, err := oauth2Config.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		t.Fatalf("no id_token in the token response")
	}

	verifierV := provider.Verifier(&oidc.Config{ClientID: as.ClientID(), Now: as.Now})
	idToken, err := verifierV.Verify(ctx, rawIDToken)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if idToken.Subject != "user-1" {
		t.Fatalf("sub = %q, want the default user-1", idToken.Subject)
	}

	var claims struct {
		Email string `json:"email"`
	}
	if err := idToken.Claims(&claims); err != nil {
		t.Fatalf("Claims: %v", err)
	}
	if claims.Email != "user-1@example.com" {
		t.Fatalf("email claim = %q, want user-1@example.com", claims.Email)
	}
}

// userinfoStatus GETs /userinfo with accessToken as a bearer credential
// and returns the status. 200 means the token is still live; 401 means
// authside no longer recognises it.
func userinfoStatus(t *testing.T, as *authsidetest.OIDC, accessToken string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, as.Issuer()+"/userinfo", nil)
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

// revokeFromTheTest POSTs RFC 7009 /revocation as the client, using the
// credentials authsidetest already exposes. This is the whole mechanism
// behind the test below: no authsidetest API is involved beyond
// Issuer()/ClientID()/ClientSecret().
func revokeFromTheTest(t *testing.T, as *authsidetest.OIDC, token string) {
	t.Helper()
	resp, err := http.PostForm(as.Issuer()+"/revocation", url.Values{
		"token":         {token},
		"client_id":     {as.ClientID()},
		"client_secret": {as.ClientSecret()},
	})
	if err != nil {
		t.Fatalf("POST /revocation: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /revocation status = %d, want 200", resp.StatusCode)
	}
}

// TestRevocation_ATestCanEndASessionWithoutTheApplication is the
// "revoking a token from outside the application" scenario -- an operator
// killing a session at the IdP while the application is still holding its
// tokens -- and it needs no authsidetest API for it at all. The test is
// already allowed to be an OAuth client: it has the client credentials,
// so it can call RFC 7009 /revocation exactly as the application could.
//
// This is worth an explicit test because the capability is invisible
// otherwise. authsidetest's surface is Now/Advance/SetTime/RequestLog and
// nothing about revocation, so the natural reading is that revocation
// from outside is missing -- README's roadmap said so for a while. It is
// not; it just lives in the protocol rather than in this package.
//
// Revoking the *refresh* token is the right lever for "the session is
// over": it takes the whole token family with it, so the access token
// stops working at /userinfo immediately and the application's next
// silent refresh fails too, which is the pair of symptoms a real
// revocation produces. (Revoking only the access token deliberately does
// not cascade -- see internal/oidcop/revocation.go.)
func TestRevocation_ATestCanEndASessionWithoutTheApplication(t *testing.T) {
	as := authsidetest.NewOIDC(t, authsidetest.WithUsers(
		authsidetest.User{Sub: "user-1", Claims: map[string]any{"email": "alice@example.com"}},
	))

	tok, oauth2Config, _ := loginTokensAs(t, as, "user-1")
	if tok.RefreshToken == "" {
		t.Fatal("no refresh_token to revoke")
	}
	if got := userinfoStatus(t, as, tok.AccessToken); got != http.StatusOK {
		t.Fatalf("/userinfo before revocation = %d, want 200", got)
	}

	revokeFromTheTest(t, as, tok.RefreshToken)

	if got := userinfoStatus(t, as, tok.AccessToken); got != http.StatusUnauthorized {
		t.Fatalf("/userinfo after revocation = %d, want 401", got)
	}

	// And what the application actually notices: its next refresh fails
	// with invalid_grant rather than quietly succeeding. Expiry is forced
	// into the past so x/oauth2 attempts the refresh instead of handing
	// back the cached, still-unexpired access token.
	expired := *tok
	expired.Expiry = as.Now().Add(-time.Hour)
	_, err := oauth2Config.TokenSource(context.Background(), &expired).Token()
	if err == nil {
		t.Fatal("refresh after revocation succeeded, want invalid_grant")
	}
	if !strings.Contains(err.Error(), "invalid_grant") {
		t.Fatalf("refresh error = %q, want it to mention invalid_grant", err.Error())
	}
}

// ClientAsIdentity is the in-process counterpart of the authside_claims
// cookie: an identity the config never listed, driven through the same
// login: auto flow ClientAs uses.
func TestClientAsIdentity(t *testing.T) {
	op := authsidetest.NewOIDC(t,
		authsidetest.WithConfig(func(cfg *authside.Config) {
			cfg.Targets[0].AcceptInjectedClaims = true
		}),
	)

	client := op.ClientAsIdentity(map[string]any{
		"sub":   "invented-user",
		"email": "invented@example.com",
	})
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	u, err := url.Parse(op.Issuer() + "/authorize")
	if err != nil {
		t.Fatalf("parsing authorize URL: %v", err)
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", op.ClientID())
	q.Set("redirect_uri", op.RedirectURI())
	q.Set("scope", "openid")
	q.Set("state", "s-1")
	u.RawQuery = q.Encode()

	resp, err := client.Get(u.String())
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("/authorize status = %d, want 302", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parsing Location: %v", err)
	}
	if loc.Query().Get("code") == "" {
		t.Fatalf("no code in %q", loc)
	}

	// The request log records the invented subject, which is the cheap
	// proof that the cookie -- not default_user -- decided this login.
	log := op.RequestLog()
	var found bool
	for _, line := range log {
		if strings.Contains(line, `"sub":"invented-user"`) {
			found = true
		}
	}
	if !found {
		t.Fatalf("no request logged for the injected subject; log = %v", log)
	}
}
