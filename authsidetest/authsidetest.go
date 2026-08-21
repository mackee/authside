package authsidetest

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/mackee/authside"
	"github.com/mackee/authside/config"
	"github.com/mackee/authside/internal/clock"
)

// defaultTargetName and defaultMount are the target name and mount point
// NewOIDC always uses. There is no WithMount option: a caller that needs
// several independently-mounted targets in one process is exercising
// authside.New directly (see README "Several providers in one process"),
// not the single-target convenience this package provides.
const (
	defaultTargetName = "oidc"
	defaultMount      = "/oidc"
)

// defaultClientID, defaultClientSecret and defaultRedirectURI are the
// client NewOIDC registers when WithClient/WithRedirectURIs is never
// given, matching the client in the README's "As a docker compose
// sidecar" quick start so the two examples stay consistent.
const (
	defaultClientID     = "local-app"
	defaultClientSecret = "local-secret"
	defaultRedirectURI  = "http://127.0.0.1/callback"
)

// defaultUserSub and defaultUserEmail are the single user NewOIDC
// registers when WithUsers is never given.
const (
	defaultUserSub   = "user-1"
	defaultUserEmail = "user-1@example.com"
)

// User is one identity NewOIDC's target can issue tokens for. It mirrors
// config.User (Sub, Claims), rather than aliasing it, so that a caller
// depending only on authsidetest never needs to import the config package
// just to build a User value.
type User struct {
	Sub    string
	Claims map[string]any
}

// LoginMode selects /authorize's behaviour. It is an alias for
// config.LoginMode (not a distinct type) so a LoginMode value produced by
// this package can be passed anywhere a config.LoginMode is expected, and
// vice versa, with no conversion.
type LoginMode = config.LoginMode

// The three login modes /authorize supports. See config.LoginMode's own
// constants for what each one does.
const (
	LoginAuto   = config.LoginAuto
	LoginPicker = config.LoginPicker
	LoginForm   = config.LoginForm
)

// settings is what every Option mutates. NewOIDC seeds it with the
// defaults documented on it, applies every Option in order, then builds a
// *authside.Config from the result.
type settings struct {
	clientID     string
	clientSecret string
	redirectURIs []string
	login        LoginMode
	users        []User
	startTime    time.Time
	configFns    []func(*authside.Config)
}

// Option configures the target NewOIDC builds. See WithUsers, WithLogin,
// WithClient, WithRedirectURIs, WithStartTime and WithConfig.
type Option func(*settings)

// WithUsers sets the pool of identities the target can issue tokens for,
// replacing whatever a previous WithUsers call set (later calls win — as
// with every Option here, options are applied in the order given to
// NewOIDC). The first user in users becomes the target's default_user
// (see NewOIDC's doc comment on DefaultUser), so put the identity you want
// a cookie-less client to log in as first.
//
// Omitting WithUsers entirely leaves NewOIDC's single built-in user in
// place (see NewOIDC).
func WithUsers(users ...User) Option {
	return func(s *settings) {
		s.users = users
	}
}

// WithLogin selects /authorize's behaviour. Omitting it leaves the target
// on LoginAuto, the mode ClientAs is built around (see ClientAs and
// internal/oidcop/authorize.go's authsideSubCookie doc comment) — LoginAuto
// is NewOIDC's default specifically because it is the login mode that
// needs no browser-facing UI and no click/submit for a Go test to drive.
func WithLogin(mode LoginMode) Option {
	return func(s *settings) {
		s.login = mode
	}
}

// WithClient replaces NewOIDC's default client registration wholesale:
// client_id, client_secret and every redirect URI. Use WithRedirectURIs
// instead if only the redirect URIs need to change and the default
// client_id/client_secret are otherwise fine.
//
// redirectURIs must not be empty — NewOIDC has nothing to default
// RedirectURI() to if it is, and fails construction outright rather than
// silently keeping a stale redirect URI.
func WithClient(clientID, clientSecret string, redirectURIs ...string) Option {
	return func(s *settings) {
		s.clientID = clientID
		s.clientSecret = clientSecret
		s.redirectURIs = redirectURIs
	}
}

// WithRedirectURIs is sugar for changing only the redirect URIs on
// NewOIDC's single client, leaving client_id/client_secret at whatever
// they otherwise are (NewOIDC's defaults, or a prior WithClient's values —
// whichever Option ran last, per NewOIDC's left-to-right application
// order). See the package doc comment for why this, not WithClient, is
// almost always the Option a test driving a real application under test
// needs: that application's own callback address is usually the only
// thing that needs to change.
func WithRedirectURIs(uris ...string) Option {
	return func(s *settings) {
		s.redirectURIs = uris
	}
}

// WithStartTime sets the test clock's initial instant — what Now() (and
// every token this target mints) reports before any Advance/SetTime call.
// Omitting it leaves the clock starting at time.Now().Truncate(time.Second)
// (see NewOIDC's doc comment for why truncated).
func WithStartTime(t time.Time) Option {
	return func(s *settings) {
		s.startTime = t
	}
}

// WithConfig is the escape hatch: fn receives the *authside.Config NewOIDC
// is about to build its handler from, after every other Option
// (WithUsers, WithLogin, WithClient/WithRedirectURIs, WithStartTime) has
// already been applied to it, so fn can see and override their combined
// result. It exists for the parts of config.Target this package has no
// dedicated Option for — Discovery, AccessToken, RefreshToken, Errors,
// Tamper, NBFSkew, AcceptAnyUsername, AcceptInjectedClaims and so on —
// not as a replacement for the Options above.
//
// Multiple WithConfig calls run in the order given, each seeing the
// previous one's edits.
//
// Beware fn overwriting Target.Mount or Target.Issuer: URL() and Issuer()
// are computed from what NewOIDC itself set them to, not re-read from cfg
// after fn runs, so changing either here desyncs Issuer() from the mount
// the live server actually serves. Change Mount/Issuer only if you also
// stop relying on (*OIDC).Issuer() and drive the resulting URL by hand.
func WithConfig(fn func(*authside.Config)) Option {
	return func(s *settings) {
		s.configFns = append(s.configFns, fn)
	}
}

// OIDC is a live, in-process authside OIDC target, torn down with the
// test that created it. Build one with NewOIDC.
type OIDC struct {
	tb testing.TB

	srv   *httptest.Server
	mount string

	clientID     string
	clientSecret string
	redirectURI  string

	clock *clock.Test
	buf   *syncBuffer
}

// NewOIDC starts a live, in-process authside OIDC target on a random
// loopback port and returns a handle to it, torn down automatically via
// tb.Cleanup when the test (or benchmark, or any other testing.TB) ends.
// Construction failures (an invalid combination of Options, or an
// authside.New error) fail tb immediately via tb.Fatalf rather than
// returning an error, since there is nothing a caller could usefully do
// with a nil *OIDC.
//
// # Defaults
//
// NewOIDC(tb) with no options at all is a complete, working target:
//
//   - One target, named "oidc", mounted at "/oidc".
//   - One client: client_id "local-app", client_secret "local-secret",
//     redirect_uris ["http://127.0.0.1/callback"] — the same values the
//     README's compose quick start uses, so the two examples agree.
//   - login: auto (see WithLogin) — the mode ClientAs exists to drive.
//   - One user, sub "user-1", claims {"email": "user-1@example.com"},
//     if WithUsers is never given.
//   - The test clock starts at time.Now().Truncate(time.Second). It is
//     truncated to the second because every token this target mints
//     carries iat/exp at second granularity (the JWT numeric-date
//     convention); leaving Now() sub-second would make a caller's
//     assertion like idToken.IssuedAt.Equal(o.Now()) fail on whichever
//     second boundary the wall clock happened to straddle, for no reason
//     visible in the test itself.
//
// # DefaultUser is a convenience, not a suggestion to skip cookies
//
// The target's default_user is set to the first configured user's Sub
// (WithUsers' first argument, or "user-1" if WithUsers is never given).
// That means a plain http.Client with no authside_sub cookie at all still
// completes a login — as that default user, via login: auto's own
// fallback (see internal/oidcop/authorize.go's subjectForAuto). This
// exists so NewOIDC(tb) alone, with no further wiring, is enough to drive
// a login end to end.
//
// It is also a real, if narrow, trap: a test that means to assert "a
// request with no authside_sub cookie is rejected" will instead observe a
// successful login as the default user, unless it overrides default_user
// away (WithConfig, since there is no dedicated Option for it — this is
// deliberately the one target field ClientAs's whole design leans on, so
// giving it its own Option would only invite skipping ClientAs by
// accident). ClientAs itself is unaffected either way: it always sets an
// explicit cookie, so it never depends on this fallback.
func NewOIDC(tb testing.TB, opts ...Option) *OIDC {
	tb.Helper()

	s := &settings{
		clientID:     defaultClientID,
		clientSecret: defaultClientSecret,
		redirectURIs: []string{defaultRedirectURI},
		login:        LoginAuto,
	}
	for _, opt := range opts {
		opt(s)
	}

	if len(s.redirectURIs) == 0 {
		tb.Fatalf("authsidetest: NewOIDC: no redirect URIs configured (WithClient/WithRedirectURIs was given zero URIs)")
		return nil
	}
	if len(s.users) == 0 {
		s.users = []User{{Sub: defaultUserSub, Claims: map[string]any{"email": defaultUserEmail}}}
	}
	if s.startTime.IsZero() {
		s.startTime = time.Now().Truncate(time.Second)
	}

	testClock := clock.NewTest(s.startTime)
	buf := &syncBuffer{}

	// The issuer chicken-and-egg: authside.New needs the issuer before
	// it can build a handler, and httptest.NewServer needs a handler
	// before it can allocate a port. httptest.NewUnstartedServer already
	// owns a live net.Listener before Start is ever called, so its
	// address is known early enough to build the config from — this is
	// the same construction the acceptance tests in this repo use (see
	// authside_test.go).
	srv := httptest.NewUnstartedServer(nil)
	baseURL := "http://" + srv.Listener.Addr().String()

	users := make([]config.User, len(s.users))
	for i, u := range s.users {
		users[i] = config.User{Sub: u.Sub, Claims: u.Claims}
	}

	cfg := &authside.Config{
		Targets: []config.Target{
			{
				Name:        defaultTargetName,
				Type:        "oidc",
				Issuer:      baseURL + defaultMount,
				Mount:       defaultMount,
				Login:       s.login,
				DefaultUser: users[0].Sub,
				Clients: []config.Client{
					{
						ClientID:     s.clientID,
						ClientSecret: s.clientSecret,
						RedirectURIs: s.redirectURIs,
					},
				},
				Users: users,
			},
		},
	}
	for _, fn := range s.configFns {
		fn(cfg)
	}

	handler, err := authside.New(cfg, authside.WithClock(testClock), authside.WithRequestLog(buf))
	if err != nil {
		tb.Fatalf("authsidetest: NewOIDC: authside.New: %v", err)
		return nil
	}

	srv.Config.Handler = handler
	srv.Start()
	tb.Cleanup(srv.Close)

	return &OIDC{
		tb:           tb,
		srv:          srv,
		mount:        defaultMount,
		clientID:     s.clientID,
		clientSecret: s.clientSecret,
		redirectURI:  s.redirectURIs[0],
		clock:        testClock,
		buf:          buf,
	}
}

// URL returns the server's base address, e.g. "http://127.0.0.1:54321"
// (no mount suffix). It is live for as long as the owning test has not
// ended.
func (o *OIDC) URL() string {
	return o.srv.URL
}

// Issuer returns URL() with the target's mount appended, e.g.
// "http://127.0.0.1:54321/oidc". It is computed from the live server on
// every call, not cached from before Start — genuinely the address a
// discovery client fetches right now, not a string that merely looked
// right when NewOIDC ran. In NewOIDC's default (simple-mode) config this
// is also the exact value of the target's issuer, so a vanilla
// oidc.NewProvider(ctx, as.Issuer()) works with no extra wiring — see the
// README's "As a docker compose sidecar" quick start for the same
// property in the sidecar form.
func (o *OIDC) Issuer() string {
	return o.URL() + o.mount
}

// ClientID returns the client_id NewOIDC registered (NewOIDC's default,
// or whatever WithClient last set).
func (o *OIDC) ClientID() string {
	return o.clientID
}

// ClientSecret returns the client_secret NewOIDC registered (NewOIDC's
// default, or whatever WithClient last set).
func (o *OIDC) ClientSecret() string {
	return o.clientSecret
}

// RedirectURI returns the first redirect URI NewOIDC registered for its
// client (NewOIDC's default, or the first URI WithClient/WithRedirectURIs
// last set).
func (o *OIDC) RedirectURI() string {
	return o.redirectURI
}

// Handler returns the http.Handler the live server is dispatching to —
// the same value authside.New returned inside NewOIDC. Most callers want
// Issuer()/URL() instead; Handler exists for a test that wants to mount
// this target's handler somewhere other than the httptest.Server NewOIDC
// already started (e.g. behind its own middleware in a hand-rolled
// httptest.NewServer(...) of its own).
func (o *OIDC) Handler() http.Handler {
	return o.srv.Config.Handler
}

// ClientAs returns an *http.Client whose cookie jar carries an
// authside_sub cookie set to sub, on this server's own origin. Under
// login: auto (NewOIDC's default — see WithLogin), that cookie is exactly
// what internal/oidcop/authorize.go's subjectForAuto reads to decide who
// is logging in (its own doc comment names "a Go test via its http.Client's
// cookie jar" as the intended source) — so driving GET {Issuer()}/authorize
// with the returned client logs in as sub, regardless of the target's
// default_user.
//
// The returned client sets no CheckRedirect of its own: it follows
// redirects exactly as a zero-value http.Client would (matching a real
// browser navigating through a login flow to an application's callback).
// A test that wants to inspect authside's redirect to redirect_uri
// directly, instead of letting the client follow it — the way this
// repository's own acceptance tests do — should set CheckRedirect on the
// returned client itself; ClientAs does not decide that for its caller.
//
// Only login: auto reads this cookie. login: picker and login: form
// choose a subject a different way (a click or a form submission) and
// ignore it entirely — ClientAs is not useful against a target configured
// with either of those modes.
func (o *OIDC) ClientAs(sub string) *http.Client {
	o.tb.Helper()

	jar, err := cookiejar.New(nil)
	if err != nil {
		// cookiejar.New's only documented error path is a non-nil
		// Options.PublicSuffixList misbehaving; nil Options (passed
		// below) never triggers it. Fatalf here rather than a panic so
		// a future change to this call still fails the test, not the
		// process, if that ever stops being true.
		o.tb.Fatalf("authsidetest: ClientAs: cookiejar.New: %v", err)
		return nil
	}

	origin, err := url.Parse(o.URL())
	if err != nil {
		o.tb.Fatalf("authsidetest: ClientAs: parsing %q: %v", o.URL(), err)
		return nil
	}
	jar.SetCookies(origin, []*http.Cookie{{Name: "authside_sub", Value: sub, Path: "/"}})

	return &http.Client{Jar: jar}
}

// ClientAsIdentity returns an *http.Client whose cookie jar carries an
// authside_claims cookie holding identity, on this server's own origin.
// Where ClientAs names a subject the config already lists, this supplies
// the whole identity — identity["sub"] is the subject and every other key
// is a claim — so a test can log in as someone the config never mentioned,
// with the claims the application under test actually reads.
//
// identity must carry a non-empty string "sub"; anything else is a test
// bug and fails the test here rather than at /authorize.
//
// The target must have AcceptInjectedClaims set (there is no dedicated
// Option — use WithConfig) and be running login: auto, which is NewOIDC's
// default. Everything ClientAs documents about redirect following applies
// here unchanged.
func (o *OIDC) ClientAsIdentity(identity map[string]any) *http.Client {
	o.tb.Helper()

	sub, _ := identity["sub"].(string)
	if sub == "" {
		o.tb.Fatalf("authsidetest: ClientAsIdentity: identity needs a non-empty string %q, got %#v", "sub", identity["sub"])
		return nil
	}
	payload, err := json.Marshal(identity)
	if err != nil {
		o.tb.Fatalf("authsidetest: ClientAsIdentity: marshalling identity: %v", err)
		return nil
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		o.tb.Fatalf("authsidetest: ClientAsIdentity: cookiejar.New: %v", err)
		return nil
	}
	origin, err := url.Parse(o.URL())
	if err != nil {
		o.tb.Fatalf("authsidetest: ClientAsIdentity: parsing %q: %v", o.URL(), err)
		return nil
	}
	jar.SetCookies(origin, []*http.Cookie{{
		Name:  "authside_claims",
		Value: base64.RawURLEncoding.EncodeToString(payload),
		Path:  "/",
	}})

	return &http.Client{Jar: jar}
}

// Now returns the test clock's current time — the iat/nbf every token
// minted right now would carry.
func (o *OIDC) Now() time.Time {
	return o.clock.Now()
}

// Advance moves the test clock forward (or backward, for a negative d) by
// d, without sleeping and without affecting a token already minted: a
// token's exp was computed once, from Now() at the moment it was issued,
// so moving Now() past it is what makes a verifier start rejecting that
// same token as expired.
func (o *OIDC) Advance(d time.Duration) {
	o.clock.Advance(d)
}

// SetTime pins the test clock's current time to t.
func (o *OIDC) SetTime(t time.Time) {
	o.clock.Set(t)
}

// RequestLog returns a snapshot of the request log's captured JSON lines,
// one string per line, in the order they were written. Each line decodes
// as a reqlog.Record (internal/reqlog); a caller outside this module
// without access to that type can still assert on the raw JSON via
// encoding/json into its own struct, or with a substring/regexp check.
//
// The snapshot is taken at call time: lines written after RequestLog
// returns are not included, and mutating the returned slice does not
// affect a later call.
func (o *OIDC) RequestLog() []string {
	return o.buf.lines()
}
