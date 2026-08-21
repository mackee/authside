package oidcop

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/mackee/authside/config"
	"github.com/mackee/authside/internal/clock"
	"github.com/mackee/authside/internal/keys"
	"github.com/mackee/authside/internal/reqlog"
	"github.com/mackee/authside/internal/tmpl"
)

// Target is one OIDC target's runtime state: its resolved configuration,
// signing keys, clock, and the in-memory authorization-code and
// access-token-session stores every login populates.
//
// A *Target is safe for concurrent use.
type Target struct {
	name  string
	mount string

	issuerRaw  string
	issuerTmpl *tmpl.Template

	advertiseInternal string
	advertiseBrowser  string

	login             config.LoginMode
	discovery         config.DiscoveryMode
	defaultUser       string
	acceptAnyUsername bool

	// acceptInjectedClaims lets login: auto take the whole identity from
	// the authside_claims cookie (see inject.go). ignoredInjectionOnce
	// makes the "cookie present but this target did not opt in" notice
	// fire once for the life of the target rather than on every request
	// -- one authside process serves every target from one origin, so a
	// cookie meant for another target rides along to this one and the
	// notice would otherwise be per-request noise.
	acceptInjectedClaims bool
	ignoredInjectionOnce sync.Once

	clients map[string]config.Client
	users   map[string]preparedUser

	// errors maps an endpoint name (README "Negative testing" > errors:)
	// to the canned failure configuredError builds from it. nil/empty
	// means the target has no errors: configured and every endpoint
	// behaves normally.
	errors map[string]config.ErrorSpec

	// userOrder preserves the configured order of Users (the map above
	// loses it). login: picker needs a stable, deterministic listing --
	// map iteration order is not that -- so New populates this
	// alongside users, from the same loop.
	userOrder []string

	idTokenTTL     time.Duration
	accessTokenTTL time.Duration
	nbfSkew        time.Duration

	// accessToken is the format POST /token hands back (README
	// "Tokens"), read only by mintAccessToken in token.go. The empty
	// string -- a config.Target built by hand rather than through
	// config.ApplyDefaults -- behaves as config.AccessTokenJWT, the
	// documented default, since only the exact string "opaque" opts out;
	// same treatment newRefreshStore gives an empty refresh_token mode.
	accessToken config.AccessTokenType

	// perIssuer holds one route per rendered issuer, for discovery:
	// per_issuer, and is empty for every other discovery mode. Populated
	// at construction (enumeratePerIssuerRoutes) so a collision or an
	// unservable issuer is a startup failure rather than a surprise on
	// the first fetch; router.go registers one handler per entry.
	perIssuer []perIssuerRoute

	// tamper is this target's tamper: values (README "Negative testing"),
	// nil when the target has none configured. buildIDToken and
	// buildAccessToken (jwt.go) are the only readers.
	tamper tamperSet

	keys   *keys.Set
	clock  clock.Clock
	logger *slog.Logger

	codes         *codeStore
	sessions      *sessionStore
	refreshTokens *refreshStore

	mu sync.Mutex // guards nothing yet beyond codes/sessions, which have their own locks; reserved for future per-target state
}

// New builds the runtime Target for one config.Target and returns the
// http.Handler serving it, with every route registered relative to the
// target's own root (i.e. "/authorize", not "/{mount}/authorize" -- the
// caller, authside.New, is responsible for mounting this handler under
// the target's configured mount).
//
// Every configuration this package accepts is implemented, so New never
// refuses a mode outright. It does fail at construction rather than
// serving something broken: discovery: per_issuer is rejected here when
// its rendered issuers cannot be served -- an issuer whose path is
// outside the target's mount, or two issuers colliding on one route --
// see discovery_periss.go. access_token: opaque is a single branch in
// token.go's mintAccessToken, which is the whole of the difference,
// because /userinfo resolves an access token by lookup in t.sessions
// rather than by parsing it (sessions.go). grant_type=refresh_token,
// refresh_token: rotate/static and POST /revocation, GET /end_session
// are all implemented; see refresh.go, token.go's issueFromRefresh,
// revocation.go and endsession.go. Login modes (auto/picker/form) are
// all implemented; see authorize.go and router.go's conditional
// registration of POST /authorize. errors: is implemented; see errors.go's
// configuredError and every handler's use of it. tamper is implemented;
// see tamper.go's tamperSet and buildIDToken/buildAccessToken's use of it
// (jwt.go), applied uniformly to both the authorization_code and
// refresh_token grants because both call the same build functions
// (token.go).
//
// recorder is the shared *reqlog.Recorder every target's requests are
// logged through (README "Request log"): one process-wide recorder, not
// one per target, so the JSON lines from every target interleave on the
// same stream with their own "target" field distinguishing them (see
// authside.go, the only caller that constructs one for real). A nil
// recorder (every test in this package that does not care about the log)
// falls back to one that discards its output, so Middleware always has a
// non-nil *Recorder to call into.
//
// opts is New's injection seam beyond config.Target itself -- currently
// only WithClock (see options.go). It is variadic, not a positional
// parameter, specifically so that every existing call site (authside.go,
// and every test in this package that calls New(t, logger, recorder) with
// no fourth argument) keeps compiling unchanged: the zero-Option call
// resolves to exactly the pre-Option defaults via resolveOptions. opts is
// threaded through to buildTarget unchanged, and the same resolved clock
// is what the nil-recorder fallback below uses -- WithClock affects the
// nil-recorder Recorder's timestamps exactly as it affects the Target's
// own iat/exp/nbf, since authside.New's real call site pairs one clock
// across both (see authside.go's New for why that coupling matters).
func New(t *config.Target, logger *slog.Logger, recorder *reqlog.Recorder, opts ...Option) (http.Handler, error) {
	o := resolveOptions(opts)

	if recorder == nil {
		recorder = reqlog.New(io.Discard, o.clock)
	}

	target, err := buildTarget(t, logger, opts...)
	if err != nil {
		return nil, err
	}

	return newRouter(target, recorder), nil
}

// buildTarget does everything New does except deciding on a recorder and
// wrapping the result in a router: it validates and resolves one
// config.Target into its runtime *Target. Split out from New so tests in
// this package can build a *Target directly (e.g. to install a custom
// tanukirpc.AccessLogger for asserting on tanukirpc's own error/success
// classification) without reimplementing this construction logic.
//
// opts is variadic for the same reason as New's: every existing caller
// (New itself, and authorize_notanerror_test.go's buildTarget(cfgTarget,
// nil) with no third argument) keeps compiling unchanged, and the
// zero-Option case resolves to clock.System{} via resolveOptions -- see
// options.go.
func buildTarget(t *config.Target, logger *slog.Logger, opts ...Option) (*Target, error) {
	if logger == nil {
		logger = slog.Default()
	}
	o := resolveOptions(opts)

	issuerTmpl, err := tmpl.Parse(t.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidcop: target %q: issuer: %w", t.Name, err)
	}

	clients := make(map[string]config.Client, len(t.Clients))
	for _, c := range t.Clients {
		clients[c.ClientID] = c
	}

	users := make(map[string]preparedUser, len(t.Users))
	userOrder := make([]string, 0, len(t.Users))
	for _, u := range t.Users {
		pu, err := prepareUser(t.Name, u)
		if err != nil {
			return nil, fmt.Errorf("oidcop: %w", err)
		}
		if _, dup := users[u.Sub]; !dup {
			userOrder = append(userOrder, u.Sub)
		}
		users[u.Sub] = pu
	}

	// Dry-run every user's claim templates and this target's issuer
	// template together, so a "${claims.x}" that this user's config
	// simply does not have fails now, at authside.New, instead of the
	// first time a client logs in as them (mirrors internal/tmpl's own
	// parse-time-vs-resolve-time-error design, applied one level up).
	for sub, pu := range users {
		resolved, err := pu.resolveClaims(dryRunClientID)
		if err != nil {
			return nil, fmt.Errorf("oidcop: target %q: user %q: %w", t.Name, sub, err)
		}
		if _, err := issuerTmpl.Resolve(tmpl.Login{Subject: sub, ClientID: dryRunClientID, Claims: resolved}); err != nil {
			return nil, fmt.Errorf("oidcop: target %q: user %q: issuer: %w", t.Name, sub, err)
		}
	}

	// A target with no key_pem/key_file gets a freshly generated key,
	// which is the default: the zero Spec means "generate". Supplying one
	// is what makes this target's JWKS survive a restart and match
	// another process running the same config -- see internal/keys.
	keySet, err := keys.New(keys.Spec{PEM: t.KeyPEM, File: t.KeyFile}, logger)
	if err != nil {
		return nil, fmt.Errorf("oidcop: target %q: %w", t.Name, err)
	}

	target := &Target{
		name:              t.Name,
		mount:             t.Mount,
		issuerRaw:         t.Issuer,
		issuerTmpl:        issuerTmpl,
		advertiseInternal: t.Advertise.Internal,
		advertiseBrowser:  t.Advertise.Browser,
		login:             t.Login,
		discovery:         t.Discovery,
		defaultUser:       t.DefaultUser,
		acceptAnyUsername: t.AcceptAnyUsername,

		acceptInjectedClaims: t.AcceptInjectedClaims,
		clients:              clients,
		users:                users,
		userOrder:            userOrder,
		errors:               t.Errors,
		idTokenTTL:           stdDuration(t.IDTokenTTL),
		accessTokenTTL:       stdDuration(t.AccessTokenTTL),
		nbfSkew:              stdDuration(t.NBFSkew),
		accessToken:          t.AccessToken,
		tamper:               newTamperSet(t.Tamper),
		keys:                 keySet,
		clock:                o.clock,
		logger:               logger,
		codes:                newCodeStore(),
		sessions:             newSessionStore(),
		refreshTokens:        newRefreshStore(t.RefreshToken),
	}

	if t.Discovery == config.DiscoverPerIssuer {
		routes, err := enumeratePerIssuerRoutes(t, issuerTmpl, users, userOrder)
		if err != nil {
			return nil, err
		}
		target.perIssuer = routes
	}

	return target, nil
}

// stdDuration reads a *config.Duration as a plain time.Duration, treating
// a nil pointer (a field config.ApplyDefaults did not get a chance to
// fill -- config.Target built by hand rather than via config.Load/New)
// as zero rather than panicking on the nil dereference a bare d.Std()
// would produce.
func stdDuration(d *config.Duration) time.Duration {
	if d == nil {
		return 0
	}
	return d.Std()
}

// dryRunClientID is the placeholder client_id used to validate a target's
// claim and issuer templates at construction time, before any real client
// has logged in. It is chosen to be obviously not a real client_id if it
// ever leaked into an error message.
const dryRunClientID = "authside-construction-time-check"

// lookupUser resolves subject to a preparedUser. When the target has
// accept_any_username set and subject names no configured user, it
// returns a synthetic user with no claims -- exactly the "unconfigured
// subject becomes sub with no claims" rule from README's "Login modes".
// ok is false when subject is unknown and accept_any_username is not set.
func (t *Target) lookupUser(subject string) (preparedUser, bool) {
	if u, ok := t.users[subject]; ok {
		return u, true
	}
	if t.acceptAnyUsername {
		return preparedUser{sub: subject, raw: map[string]any{}, claims: map[string]claimTemplate{}}, true
	}
	return preparedUser{}, false
}

// warnIgnoredInjection reports, once per target, that a request carried
// an authside_claims cookie this target is not configured to read. It is
// a warning rather than an error for the reason injectedIdentityFrom
// documents (one shared origin across every target), and once rather
// than per-request so that a cookie set for a sibling target does not
// bury the log.
//
// It goes through the target's own logger, so authside.WithLogger
// redirects or silences it like every other line this package writes.
func (t *Target) warnIgnoredInjection() {
	t.ignoredInjectionOnce.Do(func() {
		t.logger.Warn("ignoring "+authsideClaimsCookie+" cookie: this target does not have accept_injected_claims set",
			slog.String("target", t.name))
	})
}

// orderedUsers returns every configured user, in the order they appear in
// the config -- the listing login: picker shows. accept_any_username has
// no bearing here: it lets a POST name a subject the config never listed,
// but there is nothing to list for a user that does not exist yet.
func (t *Target) orderedUsers() []preparedUser {
	out := make([]preparedUser, 0, len(t.userOrder))
	for _, sub := range t.userOrder {
		out = append(out, t.users[sub])
	}
	return out
}
