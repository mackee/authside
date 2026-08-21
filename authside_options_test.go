package authside_test

// This file is the exit test for the three injection seams options.go
// opens on authside.New (WithClock, WithLogger via internal/oidcop's own
// options_test.go, WithRequestLog): an in-process Go test must be able to
// control time and capture the request log without going through
// cmd/authside or any file on disk at all.
//
// Both tests below reuse the helpers already defined in authside_test.go
// (oneTarget, noFollowClient, setAuthsideSubCookie, driveAuthorize)
// rather than redeclaring them -- see that file's doc comment for what
// each does.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/mackee/authside"
	"github.com/mackee/authside/config"
	"github.com/mackee/authside/internal/clock"
	"github.com/mackee/authside/internal/reqlog"
)

// TestOptions_WithClockDeterminesTokenTimes is the whole reason this
// task's seam exists: an in-process test must be able to pin "now" to a
// value it chooses, mint a token, and later move time forward to observe
// the token expire -- with no sleeping, no dependence on the real wall
// clock's current value, and no special-cased "test mode" in the
// production code path (New(cfg, WithClock(...)) is the same New every
// other caller uses).
//
// fixed is deliberately far from whatever the real wall clock reads when
// this test runs: if authside.New silently ignored WithClock and fell
// back to clock.System{}, the iat assertion below would fail loudly
// instead of coincidentally passing.
func TestOptions_WithClockDeterminesTokenTimes(t *testing.T) {
	const (
		mount        = "/oidc-clock"
		clientID     = "local-app"
		clientSecret = "local-secret"
		redirectURI  = "http://app.invalid/callback"
	)

	fixed := time.Date(2030, 6, 15, 9, 30, 0, 0, time.UTC)
	testClock := clock.NewTest(fixed)

	ttl := config.Duration(10 * time.Minute)
	srv := httptest.NewUnstartedServer(nil)
	baseURL := "http://" + srv.Listener.Addr().String()

	cfg := oneTarget("oidc-clock", baseURL, mount, clientID, clientSecret, redirectURI, &ttl)
	handler, err := authside.New(cfg, authside.WithClock(testClock))
	if err != nil {
		t.Fatalf("authside.New: %v", err)
	}
	srv.Config.Handler = handler
	srv.Start()
	defer srv.Close()

	issuer := baseURL + mount
	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		t.Fatalf("oidc.NewProvider: %v", err)
	}
	oauth2Config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURI,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID},
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	setAuthsideSubCookie(t, jar, baseURL, "user-1")
	client := noFollowClient(jar)

	code, _ := driveAuthorize(t, client, issuer, clientID, redirectURI, "st", "no")
	if code == "" {
		t.Fatalf("no code in the /authorize redirect")
	}
	tok, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		t.Fatalf("no id_token in the token response")
	}

	// The verifier's own notion of "now" is pinned to the same *Test
	// clock the handler was built with, via oidc.Config.Now -- not to
	// the real wall clock. That is what lets Advance, below, move the
	// verifier's judgment of the token's validity without any real time
	// passing.
	verifier := provider.Verifier(&oidc.Config{ClientID: clientID, Now: testClock.Now})

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		t.Fatalf("Verify (before Advance) = %v, want a valid token", err)
	}
	if !idToken.IssuedAt.Equal(fixed) {
		t.Fatalf("id_token iat = %v, want %v (the injected test clock's time)", idToken.IssuedAt, fixed)
	}
	if gotTTL := idToken.Expiry.Sub(idToken.IssuedAt); gotTTL != ttl.Std() {
		t.Fatalf("id_token exp-iat = %v, want the configured id_token_ttl %v", gotTTL, ttl.Std())
	}

	// Move the test clock past the token's expiry and confirm the same
	// token -- unchanged, already issued -- is now rejected. This is the
	// capability the whole change exists for: an in-process test moving
	// time forward without restarting the process or sleeping for real.
	testClock.Advance(ttl.Std() + time.Minute)
	if _, err := verifier.Verify(ctx, rawIDToken); err == nil {
		t.Fatalf("Verify (after Advance past expiry) succeeded, want an expiry error")
	} else if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("Verify (after Advance past expiry) error = %v, want it to mention expiry", err)
	}
}

// TestOptions_WithRequestLogCapturesTheLogTimestampedByTheInjectedClock
// covers WithRequestLog together with the clock-coupling design note on
// New: the request-log Recorder authside.New builds must write to the
// io.Writer WithRequestLog supplies (not os.Stdout), and it must
// timestamp every record with the *same* clock WithClock supplies to the
// targets -- not the wall clock. A test that only checked "the buffer is
// non-empty" would miss a regression where the recorder's clock silently
// stayed on clock.System{} while the targets' own clock was overridden;
// picking a fixed time far from the real wall clock and asserting on it
// exactly is what catches that.
//
// The buffer is read only after the whole login flow has completed and
// the handler has returned every response, so there is no concurrent
// access to guard: reqlog.Recorder itself serializes writes under its own
// mutex, and this test never reads buf while a request could still be
// in flight.
func TestOptions_WithRequestLogCapturesTheLogTimestampedByTheInjectedClock(t *testing.T) {
	const (
		mount        = "/oidc-reqlog"
		clientID     = "local-app"
		clientSecret = "local-secret"
		redirectURI  = "http://app.invalid/callback"
	)

	fixed := time.Date(2031, 11, 2, 3, 4, 5, 0, time.UTC)
	testClock := clock.NewTest(fixed)
	var buf bytes.Buffer

	srv := httptest.NewUnstartedServer(nil)
	baseURL := "http://" + srv.Listener.Addr().String()

	cfg := oneTarget("oidc-reqlog", baseURL, mount, clientID, clientSecret, redirectURI, nil)
	handler, err := authside.New(cfg, authside.WithClock(testClock), authside.WithRequestLog(&buf))
	if err != nil {
		t.Fatalf("authside.New: %v", err)
	}
	srv.Config.Handler = handler
	srv.Start()
	defer srv.Close()

	issuer := baseURL + mount
	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		t.Fatalf("oidc.NewProvider: %v", err)
	}
	oauth2Config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURI,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID},
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	setAuthsideSubCookie(t, jar, baseURL, "user-1")
	client := noFollowClient(jar)

	code, _ := driveAuthorize(t, client, issuer, clientID, redirectURI, "st", "no")
	if code == "" {
		t.Fatalf("no code in the /authorize redirect")
	}
	if _, err := oauth2Config.Exchange(ctx, code); err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	if buf.Len() == 0 {
		t.Fatalf("request log buffer is empty, want at least one JSON line")
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	var records []reqlog.Record
	for _, line := range lines {
		if line == "" {
			continue
		}
		var rec reqlog.Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("decoding request log line %q: %v", line, err)
		}
		records = append(records, rec)
	}

	var sawTokenRequest bool
	for _, rec := range records {
		if rec.Method != "POST" || rec.Path != mount+"/token" {
			continue
		}
		sawTokenRequest = true

		// The point of this test: rec.Time comes from the clock passed
		// to WithClock, not from wall-clock time.Now(). If the recorder
		// had kept using clock.System{} internally, this would fail
		// (fixed is nowhere near the real current time), regardless of
		// how many lines were captured.
		if got := rec.Time.AsTime(); !got.Equal(fixed) {
			t.Fatalf("token request record time = %v, want %v (the injected test clock's time, not wall time)", got, fixed)
		}
	}
	if !sawTokenRequest {
		t.Fatalf("no POST %s record found in the captured log; records = %+v", mount+"/token", records)
	}
}
