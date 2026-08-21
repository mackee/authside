# authside

`authside` is an authentication sidecar for **local development and test environments**.
It stands in for the identity provider your application talks to in production, so that
`docker compose up` (or `go test`) is all you need to exercise a real login flow.

The first supported target is **OpenID Connect**. Other targets (SAML, forward-auth
headers, plain OAuth 2.0) are planned — see [Roadmap](#roadmap).

> [!WARNING]
> **Never run `authside` in production, or on any host reachable from the internet.**
> It authenticates nobody: it issues whatever token its config tells it to, for whoever
> asks. Anything that trusts it is unauthenticated, however real the tokens look. It binds
> to loopback unless you pass `--allow-external`, which containers need.

> [!NOTE]
> **Status: it runs, and nobody has used it in anger yet.** The OIDC target works
> end to end — a vanilla `coreos/go-oidc` client completes discovery, authorization,
> the token exchange, ID token verification and `/userinfo` against it, and the
> [Quick start](#quick-start) below is exercised by a test. Every configuration option it
> documents is implemented. The configuration format may still change.

## Why

Testing an application that delegates authentication to an external IdP is awkward:

- Pointing local development at the real IdP requires real accounts, real secrets, and
  network access — and it breaks in CI.
- Stubbing the auth layer inside the application (a "test mode" that skips login) means
  the code path you ship is not the code path you test. Token verification, session
  handling and redirect plumbing all go unexercised.
- Running a full IdP (Keycloak, for instance) is faithful but slow to boot and heavy to
  configure, and it still needs a realm export checked in somewhere.
- Existing mock providers pin the issuer to their own listen address, which makes the
  providers that matter — anything with a per-tenant issuer, anything behind a TLS
  terminating ingress — impossible to imitate. See
  [Why not an existing mock?](#why-not-an-existing-mock).

`authside` takes the middle road: a single small process that speaks the real protocol
over the wire, configured entirely up front — which users exist, what claims they carry,
which tokens arrive already expired, which endpoint fails. A test chooses *who logs in* by
clicking a user or setting one cookie, never by mutating the mock.

## Design goals

- **Real protocol on the wire.** The application under test uses its production auth
  code path unchanged. Only the issuer URL and client credentials differ.
- **The issuer is a name you choose, not the address you listen on.** Any scheme, any
  path, several issuers at once, and an issuer that varies per login. This is the
  central design constraint — see [Issuer, mount and advertise](#issuer-mount-and-advertise).
- **Two ways to run.** A container/binary sidecar for browser E2E, and a Go library
  helper (`authsidetest`) for in-process tests. Both work today; the in-process one can
  also move its own clock, which the sidecar deliberately cannot.
- **The configuration is the whole API.** Every behaviour — a token that arrives expired,
  an endpoint that returns `invalid_grant`, a deliberately corrupted claim — is a config
  value, fixed before the process starts. Nothing mutates it at runtime, so there is no
  state to reset between tests, nothing leaking from one test into the next, and nothing to
  race when they run in parallel. A test says what it wants by pointing at the target that
  behaves that way — see [Scenarios are configuration](#scenarios-are-configuration).
- **A stable signing key when you want one.** By default keys are generated at startup,
  which is all a single-process test needs. Hand a target a key with `key_file` and its
  JWKS and `kid` stop moving, so a token minted in one process verifies in another. See
  [Keys](#keys).
- **Strict about the protocol, never about the topology.** Redirect URI matching and
  client authentication are enforced by default, and PKCE is verified whenever the client
  uses it, so a misconfiguration fails locally instead of in staging. `authside` does
  *not* second-guess how your network is wired.
- **Loud about being fake.** Fake-only `kid` prefix, a marker response header, and
  loopback-only binding unless overridden, so a token from this tool is recognisable if it
  ever reaches a real environment.

## Built with

- [`tanukirpc`](https://github.com/mackee/tanukirpc) — routing, type-safe handlers and
  registry injection.
- [`lestrrat-go/jwx/v3`](https://github.com/lestrrat-go/jwx) — JWK/JWKS handling and
  JWS/JWT signing.

## Install

Three ways, all equivalent — `authside` is one static binary with no runtime
dependencies.

```console
# Container image (what a compose sidecar or CI service wants)
$ docker pull ghcr.io/mackee/authside:latest

# Binary, via Go
$ go install github.com/mackee/authside/cmd/authside@latest

# Binary, prebuilt: grab an archive for your platform from the Releases page
# https://github.com/mackee/authside/releases
```

`authside --version` reports what you got. Prebuilt archives cover linux and macOS on
amd64/arm64 plus windows/amd64, and the image is multi-arch (`linux/amd64`,
`linux/arm64`).

## Quick start

### As a docker compose sidecar

There is no published image yet, so build it from the `Dockerfile` in this repository
(`docker build -t authside .`) and refer to that tag. A complete, runnable version of
what follows — including a small real relying party to log in with — lives in
[`examples/compose/`](examples/compose).

```yaml
services:
  authside:
    image: authside            # docker build -t authside .
    # a container has to bind outside loopback, which is opt-in
    command: ["--config", "/etc/authside/authside.yaml", "--allow-external"]
    volumes:
      - ./authside.yaml:/etc/authside/authside.yaml:ro
    ports:
      - "5556:5556"

  app:
    build: .
    environment:
      OIDC_ISSUER: http://authside:5556/oidc
      OIDC_CLIENT_ID: local-app
      OIDC_CLIENT_SECRET: local-secret
    depends_on:
      - authside
```

`authside.yaml`:

```yaml
# NOTE: draft format — subject to change.
listen: 0.0.0.0:5556       # container-local loopback would be unreachable from `app`

targets:
  - name: oidc             # mounted at /oidc
    type: oidc
    issuer: http://authside:5556/oidc
    login: picker          # auto | picker | form
    clients:
      - client_id: local-app
        client_secret: local-secret
        redirect_uris:
          - http://localhost:8080/auth/callback
    users:
      - sub: user-1
        claims:
          email: alice@example.com
          email_verified: true
          name: Alice
          hd: example.com
      - sub: user-2
        claims:
          email: bob@example.net
          name: Bob
```

This is *simple mode*: the issuer string is also the URL clients fetch, so a vanilla
`oidc.NewProvider(ctx, issuer)` works with no extra wiring. For it to hold, `authside`
must be reachable at that one hostname from both the application and the browser — the
simplest way is `127.0.0.1 authside` in the host's `/etc/hosts`, which makes `authside`
resolve to the compose service from inside the network and to the published port from
the host. When that is not possible, see
[Issuer, mount and advertise](#issuer-mount-and-advertise).

### As a Go library

`authsidetest.NewOIDC` starts a real `httptest.Server` and hands back a handle to it.
No container, no ports to allocate, torn down with the test.

```go
func TestLogin(t *testing.T) {
	// Start the application first: authside needs its callback URL up front,
	// and an httptest port is not known until the server is running.
	app := newApp(t)

	as := authsidetest.NewOIDC(t,
		authsidetest.WithUsers(
			authsidetest.User{Sub: "user-1", Claims: map[string]any{"email": "alice@example.com"}},
			authsidetest.User{Sub: "user-2", Claims: map[string]any{"email": "bob@example.net"}},
		),
		authsidetest.WithLogin(authsidetest.LoginAuto), // /authorize shows no UI
		authsidetest.WithRedirectURIs(app.URL+"/callback"),
	)
	// as.Issuer() is a live http://127.0.0.1:PORT/oidc.
	app.UseIdP(as.Issuer(), as.ClientID(), as.ClientSecret())

	client := as.ClientAs("user-1") // an *http.Client whose jar decides who logs in
	// ... drive the app's login flow with it ...
}
```

**What in-process buys you over the sidecar** is the thing the sidecar deliberately gives
up (see [Scenarios are configuration](#scenarios-are-configuration)): time moves. The
server's clock is a test clock, so a token can be minted now and be expired a line later,
without sleeping.

```go
tok := login(t, as)        // minted at as.Now()
as.Advance(2 * time.Hour)
callWithToken(t, app, tok) // the application now sees an expired token
```

`as.RequestLog()` returns the JSON request-log lines this server has recorded, timestamped
by that same clock, so an assertion about what the client actually sent needs no stdout
capture.

**Ending a session from outside the application** needs no `authsidetest` method either —
the test is allowed to be an OAuth client, and it has the credentials, so it can call
RFC 7009 revocation the same way the application could:

```go
tok := login(t, as) // the test holds the token pair

resp, err := http.PostForm(as.Issuer()+"/revocation", url.Values{
	"token":         {tok.RefreshToken},
	"client_id":     {as.ClientID()},
	"client_secret": {as.ClientSecret()},
})
if err != nil {
	t.Fatal(err)
}
resp.Body.Close()

// The access token now 401s at /userinfo, and the application's next
// silent refresh fails with invalid_grant — what a real revocation looks like.
```

Revoke the **refresh** token to end a session: that takes the whole token family, access
tokens included. Revoking only an access token deliberately does not cascade, so the
application can still refresh — useful when that is the scenario you want. The one thing
this cannot express is revoking a session whose token the test never saw; there is no
"revoke everything for `user-1`" operation, because there is no protocol operation for it.

The underlying layer is still there if you want it: `authside.New(cfg)` returns a plain
`http.Handler` — which is how this repository's own acceptance tests drive it — and
`authside.WithClock` / `WithRequestLog` / `WithLogger` are the seams `authsidetest` itself
is built on. See `authsidetest/authsidetest_test.go`.

## Issuer, mount and advertise

An issuer is an **identifier**. It happens to look like a URL, and in the simple case it
is also the URL you fetch, but those are two different things and `authside` keeps them
apart. Three independent settings:

| Setting | Meaning |
|---|---|
| `issuer` | The string that goes in the `iss` claim and that clients compare against. Any scheme, any path — `https://…/v2.0` while `authside` listens on plain HTTP behind an ingress is fine. May be a template (see below). |
| `mount` | The path prefix this target is actually served under. Defaults to `/{name}`. Unrelated to `issuer`. |
| `advertise` | The base URLs to publish in the discovery document and in redirects. Set it when the address a client must use differs from the one it reached `authside` on — most often when the browser and the application need different bases. |

`authside` never rejects a configuration because `issuer` disagrees with `listen`. There
is no topology it can infer, and the configurations it would reject are legitimate. The
cost of that is that a typo is also accepted in silence; `--probe` is the opt-in rescue,
described in [Probing advertise.internal](#probing-advertiseinternal) below.

**How endpoint URLs in the discovery document are chosen.** `advertise.internal` /
`advertise.browser` when set, and otherwise the scheme and `Host` of the request that
asked for the document (honouring `X-Forwarded-Proto` and `X-Forwarded-Host`) plus the
target's `mount`. Deliberately **never** derived from `issuer`: an issuer is an
identifier, and in the two cases this tool exists for — an Entra-shaped issuer, or an
`https://` issuer behind a TLS-terminating ingress — it is not an address that reaches
`authside` at all, so issuer-derived endpoints would be unreachable. The request, by
contrast, arrived from somewhere that demonstrably works. In simple mode, where the
issuer *is* the served URL, both rules give the same answer. The `issuer` **field** in
the document is always the configured value, untouched.

### Several providers in one process

Each entry in `targets` is one IdP instance, and `type` is the protocol it speaks. An
application that offers more than one way to log in gets one target per provider — no
special mechanism, just independent configurations at different mounts:

```yaml
targets:
  - name: google           # mounted at /google
    type: oidc
    issuer: http://authside:5556/google
    clients: [{client_id: app-google, ...}]
    users:
      - sub: user-1
        claims: {email: alice@example.com, hd: example.com}

  - name: internal         # mounted at /internal
    type: oidc
    issuer: http://authside:5556/internal
    clients: [{client_id: app-internal, ...}]   # different client
    users: [...]                                # different user pool
```

Clients, users and signing keys are per target. This is distinct from a single provider
whose issuer varies per login, which is [Per-tenant issuers](#per-tenant-issuers) below.

> [!NOTE]
> The snippets above are elided (`...`), so they are illustrative rather than
> copy-pasteable. One real quirk if you do write configuration in this flow style: the
> YAML parser (`goccy/go-yaml`) mis-parses an unquoted URL containing a port when it sits
> inside nested flow collections — `clients: [{client_id: a, redirect_uris: [http://localhost:8080/cb]}]`
> fails, because `:8080` is read as a mapping. Quote the URL, or use the block style
> that the rest of this README uses; both parse correctly.

### Split-horizon dev environments

Some setups cannot funnel the browser and the application through one hostname: the
browser goes through a TLS-terminating ingress on the host while the application reaches
`authside` over the container network or loopback, and the application's outbound path to
the ingress hostname does not work (a host firewall dropping it, for example). Three
values then have to be configured separately:

```yaml
targets:
  - name: oidc
    type: oidc
    issuer: https://auth.local.test/oidc        # verified string only
    mount: /oidc
    advertise:
      internal: http://authside:5556/oidc       # token, jwks, userinfo — app-facing
      browser: https://auth.local.test/oidc     # authorize, end_session — browser-facing
```

The discovery document is assembled from both: `authorization_endpoint` and
`end_session_endpoint` use `advertise.browser`, while `token_endpoint`, `jwks_uri` and
`userinfo_endpoint` use `advertise.internal`. That is what makes discovery usable here
rather than merely skippable — the application fetches the document over the path it can
reach, and every URL in it is one the party that uses it can reach.

If your client hand-builds its provider configuration instead (with `coreos/go-oidc`,
`oidc.NewProvider` is replaced by a literal `oidc.ProviderConfig`), the discovery
document is never fetched and only `issuer` has to match.

### Probing advertise.internal

Because nothing cross-checks `issuer`, `advertise` and `listen`, a hostname typo starts
up perfectly happily. `advertise.internal: http://authsdie:5556/oidc` serves a discovery
document full of URLs that resolve nowhere, and the first sign of trouble is a DNS error
in the *application's* log during token exchange, pointing at nothing in particular.

Pass `--probe` and `authside`, once it is listening, makes a single `GET` to each
target's `advertise.internal` discovery URL and says what happened:

```console
$ authside --config authside.yaml --probe
...
level=INFO msg="probe: advertise.internal answered from authside itself (the status is reported, not judged)" target=oidc url=http://authside:5556/oidc/.well-known/openid-configuration status="200 OK"
level=WARN msg="probe: advertise.internal is NOT reachable from authside itself -- if the application reaches it by another route this is fine, otherwise check the hostname for a typo" target=entra url=http://authsdie:5556/entra/.well-known/openid-configuration error="...no such host"
```

It is a diagnostic, never a gate: it cannot fail startup, and it is off by default.
**Its scope is narrow, deliberately so** — read the warning as a prompt to look, not as a
verdict:

- Only `advertise.internal` is probed. `advertise.browser` only has to work from the
  browser, so `authside`'s own view of it means nothing.
- Only targets that *set* `advertise.internal` are probed. With `advertise` unset the
  advertised base comes from each incoming request, so at startup there is no URL to try.
  The probe says so per target rather than staying quiet.
- Only reachability *from `authside`'s own network namespace*. Whether the application can
  reach that base is a different question, and not one `authside` can answer.
- The HTTP status is reported, not judged. Any answer at all means the name resolved,
  which is the whole question; a `404` is correct under `discovery: off`, under
  `discovery: per_issuer`, and behind a path-rewriting ingress. Only a transport failure
  warns.
- TLS certificates are not verified. The probe asks whether something answers, sends
  nothing and trusts nothing, and a dev ingress with a local-CA certificate is the normal
  case here.

### Per-tenant issuers

Real issuers are not always fixed strings. Microsoft Entra ID uses
`https://login.microsoftonline.com/{tid}/v2.0`, so **every directory has a different
issuer**, and a multi-tenant application is required to verify both that `tid` is a GUID
and that `iss` has that `tid` in it. A mock with one hard-coded issuer cannot exercise
that check at all: tenant isolation ends up resting on the `tid` claim alone, and
"application pinned to a single issuer" is a bug that only shows up in production.

So `issuer` may be a template over the login's claims:

```yaml
targets:
  - name: entra
    type: oidc
    issuer: https://login.microsoftonline.com/${claims.tid}/v2.0
    mount: /entra
    users:
      - sub: user-1
        claims:
          tid: 11111111-1111-1111-1111-111111111111
          email: alice@example.com
      - sub: user-2
        claims:
          tid: 22222222-2222-2222-2222-222222222222
          email: bob@example.net
```

The same template syntax is available for claim values (`${subject}`, `${client_id}`),
so one user definition can cover several tenants.

#### Discovery under a templated issuer

There is no per-tenant discovery document, because the real provider does not have one
either. Entra's tenant-agnostic metadata at
`https://login.microsoftonline.com/organizations/v2.0/.well-known/openid-configuration`
returns, verbatim:

```json
{
  "issuer": "https://login.microsoftonline.com/{tenantid}/v2.0",
  "jwks_uri": "https://login.microsoftonline.com/organizations/discovery/v2.0/keys",
  "authorization_endpoint": "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize"
}
```

The `issuer` field is an unresolved placeholder, and the JWKS is shared across tenants.
`authside` does the same: **one discovery document per target**, whose `issuer` is the
template with its placeholders left in (`${claims.tid}` is emitted as `{tid}`), and **one
key set per target** behind a single `jwks_uri`.

This is deliberate rather than a shortcut. A client cannot resolve that placeholder, so it
has to obtain the expected `iss` out of band — which is exactly what it must do against
the real provider. `coreos/go-oidc` has an API for precisely this case, and its
documentation names Azure as the reason:

```go
// The expected iss for this tenant, supplied out of band.
ctx = oidc.InsecureIssuerURLContext(ctx, "https://login.microsoftonline.com/"+tid+"/v2.0")
// Discovery is fetched from authside; the document's own issuer field is not compared.
provider, err := oidc.NewProvider(ctx, "http://authside:5556/entra")
```

Had `authside` invented per-tenant discovery documents instead, an application that pins a
single issuer would keep passing its tests and only fail in production — the failure mode
this feature exists to catch.

`discovery` selects the behaviour per target:

| Value | Behaviour |
|---|---|
| `shared` (default) | One document, `issuer` emitted with placeholders unresolved |
| `per_issuer` | One document per rendered issuer, each naming that issuer — so vanilla discovery works per tenant. The escape hatch described below. |
| `off` | 404. In split-horizon and per-tenant setups the document is often never fetched, and a document that does not match how clients are actually configured is worse than no document at all. |

Exact placeholder fidelity is cosmetic — nothing machine-reads that string, since the whole
point is that the client cannot resolve it. Entra happens to name the claim `tid` but the
placeholder `{tenantid}`; an `entra` preset can reproduce that pair, and otherwise the
placeholder simply follows the claim name.

### Per-issuer discovery

`discovery: per_issuer` serves one document per tenant, each naming its own issuer — so a
client can point `oidc.NewProvider` straight at a tenant's issuer URL and have the
document's `issuer` field match, with no `InsecureIssuerURLContext` and no hand-built
`ProviderConfig`:

```yaml
targets:
  - name: entra
    type: oidc
    mount: /entra
    issuer: http://authside:5556/entra/${claims.tid}
    discovery: per_issuer
    clients:
      - client_id: local-app
        client_secret: local-secret
        redirect_uris: [http://localhost:8080/auth/callback]
    users:
      - sub: user-a
        claims: {tid: tenant-a}
      - sub: user-b
        claims: {tid: tenant-b}
```

That serves two documents — at `/entra/tenant-a/.well-known/openid-configuration` and
`/entra/tenant-b/...` — whose `issuer` fields are the two rendered issuers. The set of
issuers is finite because it comes from the configured users (and clients: a claim can
itself template on `${client_id}`), so the routes are enumerated at startup.

**The endpoint URLs are not per tenant.** Every document points `authorization_endpoint`,
`token_endpoint` and the rest at the target's own mount, because those endpoints are
shared: which tenant a login belongs to is decided by *who logs in*, not by which
discovery document the client happened to read. A client that discovers `tenant-a` and
then logs in as a `tenant-b` user gets a `tenant-b` issuer and — correctly — rejects it.

Two things to know before reaching for it:

- **The rendered issuer's path must sit under the target's `mount`.** Otherwise the
  document could never be served at its own URL, and `authside` refuses to start rather
  than registering a route no client will look at. What it cannot check is the issuer's
  *host* — `authside` has no idea what address it is reached at, by design — so making the
  host actually route here is your job. That is the premise of wanting vanilla discovery in
  the first place. Two distinct issuers that would land on the same route are a startup
  error too.
- **Only configured users are enumerable.** With `accept_any_username`, or an issuer
  templated on `${subject}`, a login can produce an `iss` that has no document. The token
  is still issued and still valid; discovery for that tenant just 404s. If a test needs
  discovery to work for it, configure the user.

## Client compatibility

Three tiers, in increasing order of what the client has to know:

1. **Simple mode** — `issuer` is also the served URL. Vanilla discovery works:
   `oidc.NewProvider(ctx, issuer)` fetches `{issuer}/.well-known/openid-configuration`
   and checks the document's `issuer` field against the URL it used. No client changes.
2. **Split horizon** — the client either fetches the advertise-aware discovery document
   over its internal base URL, or skips discovery and builds `oidc.ProviderConfig` by
   hand. Only the `iss` comparison has to line up.
3. **Per-tenant issuer** — the client supplies the expected `iss` out of band
   (`oidc.InsecureIssuerURLContext`, which makes `go-oidc` skip comparing the document's
   `issuer` field) or builds `ProviderConfig` per tenant. This is what a real
   multi-tenant client has to do against the real provider, so the mock is not asking for
   anything extra. `discovery: per_issuer` is the escape hatch if you want vanilla
   discovery to work here too — see [Per-issuer discovery](#per-issuer-discovery).

The first intended consumer is
[`tanukirpc/auth/oidc`](https://github.com/mackee/tanukirpc/tree/master/auth/oidc), which
uses `coreos/go-oidc`. It works unmodified in tier 1; tiers 2 and 3 need the client to
construct its provider without discovery, which `coreos/go-oidc` supports directly.

## OIDC target

### Endpoints

Relative to the target's `mount`:

| Path | Purpose |
|---|---|
| `GET /.well-known/openid-configuration` | Discovery document |
| `GET /jwks` | JWKS (public keys) |
| `GET /authorize` | Authorization endpoint (login mode applies here) |
| `POST /authorize` | Where the `picker` click and the `form` submit land, carrying the authorization parameters back |
| `POST /token` | Token endpoint |
| `GET /userinfo` | UserInfo endpoint |
| `POST /revocation` | Token revocation (RFC 7009) |
| `GET /end_session` | RP-initiated logout |

Several targets can be mounted in one process, each with its own issuer, clients, users
and keys.

### Supported flows

Implemented:

- Authorization Code flow, with and without PKCE (S256)
- Refresh token grant
- Client authentication via `client_secret_basic` and `client_secret_post`
- `nonce` echoed into the ID token, `state` passed through untouched
- Arbitrary custom claims per user — provider-specific ones included, such as Google's
  `hd` (which `tanukirpc/auth/oidc` reads for domain restriction) and Entra's `tid`

Explicitly out of scope for now: hybrid flow, implicit flow, dynamic client
registration, mTLS-bound tokens, and persistent storage.

PKCE is **verified when used, not required**. A `code_challenge` on `/authorize` makes the
matching `code_verifier` mandatory at `/token` (`S256` only; `plain` is rejected), and
mixing the two — a verifier for an exchange that never had a challenge, or the reverse —
is an `invalid_grant`. What `authside` does *not* do is insist on PKCE for clients that
do not use it: `golang.org/x/oauth2`'s `AuthCodeURL` sends no challenge unless asked, so a
confidential client such as `tanukirpc/auth/oidc` would fail against a mock that required
it, while the real provider accepts it. `require_pkce: true` per client turns it into a
hard requirement when you do want that check.

### Tokens

Access tokens are **JWTs by default**, so a resource server can verify one and you can read
its claims while debugging. `access_token: opaque` switches to a random opaque string, for
providers whose access tokens are database handles rather than assertions — and for
proving that your application only ever *presents* its access token instead of quietly
decoding one:

```yaml
targets:
  - name: oidc
    type: oidc
    issuer: http://localhost:5556/oidc
    access_token: opaque
```

An opaque token carries no claims, so `/userinfo` is the only way to learn anything from
it. That works because `authside` resolves an access token by looking it up, never by
parsing it, which is also why everything else about a token behaves identically in both
formats: expiry via `access_token_ttl` (negative included), RFC 7009 revocation, and
refresh-token family revocation. What `opaque` does give up is `tamper` — `iss`, `aud`,
`exp` and `signature` have nothing to corrupt on a token with no claims and no signature,
so on the access token those values become a no-op. They still corrupt the ID token minted
in the same exchange.

`at_hash` is always present in the ID token, opaque access tokens included: it is computed
over the bytes of whatever the `access_token` value is, so `go-oidc`'s `VerifyAccessToken`
passes either way (there is an end-to-end test for exactly that). It costs almost nothing to compute (the left
half of the signing algorithm's hash of the access token, base64url), and omitting it
actively breaks correct clients: `go-oidc`'s `IDToken.VerifyAccessToken` returns an error
when the claim is absent rather than treating it as optional. Note that
`tanukirpc/auth/oidc` — the first intended consumer — does not call it; the justification
is other strict clients plus the near-zero cost, not that first consumer.

`c_hash` is not emitted, because it only appears in the hybrid flow, which is out of scope.

The refresh grant returns a fresh `id_token` alongside the new access token, as real
providers generally do.

### Refresh tokens

Refresh tokens are opaque and held in memory. Rotation is **on by default**:

| `refresh_token` | Behaviour |
|---|---|
| `rotate` (default) | Every refresh returns a new refresh token and retires the old one |
| `static` | The same refresh token stays valid, for providers that behave that way |

Rotation is the default because it is the setting that exposes application bugs.
`golang.org/x/oauth2`'s `TokenSource` hands back a new refresh token after a refresh and
the application is responsible for persisting it — a step that is easy to miss and that a
non-rotating mock hides forever.

With rotation on, replaying a retired refresh token is treated as reuse: `authside`
responds `invalid_grant` and revokes the whole token family, which is what real providers
do and what a client's error handling should be tested against.

Expiry needs no dedicated mechanism: a target with `id_token_ttl: -5m` mints tokens that
are already expired when the client receives them — the same code path as a token that
expired while the client held it, minus the waiting. Revocation is a different thing from
expiry and stays on the protocol: `POST /revocation` (RFC 7009), which some clients call on
logout. The one scenario a static mock gives up is revocation *from outside* the
application, which is discussed in
[Scenarios are configuration](#scenarios-are-configuration).

### Login modes

| Mode | `/authorize` behaviour | Use for |
|---|---|---|
| `auto` | Redirects immediately, as the user named by the `authside_claims` or `authside_sub` cookie, or by `default_user` | Headless E2E, smoke tests |
| `picker` | One-click list of configured users | Manual development, multi-user E2E |
| `form` | Username/password form | Exercising the login UX and failure paths |

In `form` and `picker` mode an unknown username can optionally be accepted as-is and
become the `sub`, so tests can invent users without editing the config.

`picker` is the default, and `auto` has no implicit fallback subject: it needs either a
`default_user` on the target or an `authside_sub` cookie on `authside`'s own origin, set
before the flow starts (Playwright's `context.addCookies`, or the cookie jar of the
`http.Client` a Go test drives the flow with). Either way the choice lives in the test,
visible in its source and in its trace, instead of in a queue inside the server — and two
tests running at once cannot take each other's turn.

### Identities the config never listed

`accept_any_username` lets a test invent a `sub`, but that user arrives with no claims —
which is enough for "some user is logged in" and not enough when the application reads
`email`, or a claim derived from it. A suite that generates identities per run (a unique
address per test so parallel workers cannot collide over the same account's data) has
nothing to put in `users:` in the first place.

`accept_injected_claims` lets one login carry its whole identity. Set the
`authside_claims` cookie on `authside`'s own origin before the flow starts; its value is
the base64url of a flat JSON object whose `sub` is the subject and whose every other key
is a claim:

```yaml
targets:
  - name: oidc
    type: oidc
    issuer: http://authside:5556/oidc
    login: auto                    # accept_injected_claims is a login: auto input
    accept_injected_claims: true   # off by default
    clients:
      - client_id: local-app
        client_secret: local-secret
        redirect_uris:
          - http://localhost:8080/auth/callback
    users: []                      # a target can have none at all
```

```js
// Playwright: the identity is a property of the browser context, like a logged-in session
await context.addCookies([{
  name: 'authside_claims',
  value: Buffer.from(JSON.stringify({
    sub: `e2e-${runId}-sub`,
    email: `e2e-${runId}@example.com`,
    hd: 'example.com',
  })).toString('base64url'),
  url: 'https://authside.example.test',   // authside's own browser-facing origin
}]);
```

The rules, all of them:

- **The payload is the identity, not a patch on one.** A `sub` that happens to name a
  configured user does not merge with it; what the payload says is what the token carries.
- **It wins over `authside_sub` and `default_user`**, since it names a subject as well as
  its claims.
- **Values are literals.** A `${...}` in an injected value is that text, not a template.
  The target's `issuer` template still resolves *against* these claims, so
  `issuer: .../${claims.tid}/v2.0` picks up an injected `tid` — one target, a tenant per
  login, none of them configured. (`discovery: per_issuer` still enumerates only the
  configured users; an injected tenant has no discovery document of its own, which is what
  a real per-tenant provider does anyway — see [Per-tenant issuers](#per-tenant-issuers).)
- **A malformed payload fails the authorization**, with `error=invalid_request`, rather
  than quietly falling back to `default_user` and logging the test in as someone else.
- **A cookie on a target without `accept_injected_claims` is ignored** (with one log line
  per target). Every target in one process shares one origin, so a cookie set for one
  rides along to all of them.
- **`/end_session` clears it**, alongside `authside_sub`.

This does not make the server mutable. The payload is read from the request carrying it
and travels with that login's authorization code and refresh family — so a refreshed token
carries the same claims as the original — and nothing about the next request changes.
Two identities at once means two browser contexts, which is what isolates their cookie
jars from each other regardless.

### Keys

Every `kid` is prefixed `authside-` so a token from this tool is recognisable in logs and
can be alerted on if it ever reaches a real environment. The `kid` is derived from the key
itself (an RFC 7638 thumbprint), so it is stable for a given key rather than a counter.

By default a target generates an RSA-2048 key at startup, so its JWKS and `kid` change
every time the process restarts. For most tests that is invisible: the client fetches the
JWKS at run time, and `go-oidc` re-fetches it whenever it meets a `kid` it does not know
(the rotation strategy OIDC Core recommends), so restarting `authside` under a running
client just works.

Where it does show is when **the process that signs and the process that verifies are not
the same** — `authside token` piped into something that checks the signature, an app
holding a token from before a restart and re-verifying it, or a token you want to check
into a fixture. Hand the target a key and all of that works, because the `kid` is an RFC
7638 thumbprint of the key material: same key, same `kid`, same JWKS, byte for byte.

```console
$ openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out authside-key.pem
```

```yaml
targets:
  - name: oidc
    type: oidc
    issuer: http://localhost:5556/oidc
    key_file: ./authside-key.pem     # or key_pem: | for an inline key
```

`key_file` is resolved against the working directory, PKCS#8 and PKCS#1 are both accepted,
and anything smaller than 2048 bits is refused at startup (RS256 cannot use it). Keys are
per target, so two targets are two independent IdPs unless you point them at the same file.

**The key is test data, not a secret.** Checking it into the repository next to the config
is the intended usage: `authside` authenticates nobody, so being able to sign its tokens
confers nothing that asking it politely would not. The thing to be careful about is never
letting anything real trust it — hence the `authside-` `kid` prefix, so a token from this
tool is recognisable in logs and can be alerted on if it ever reaches a real environment.

There is deliberately no `key_seed`. Deriving an RSA key from a short string would mean
hand-rolling prime search (since Go 1.26 `rsa.GenerateKey` ignores the `io.Reader` it is
given, and the `GODEBUG` opt-out is scheduled for removal), and the search procedure would
then be part of the compatibility surface — change it and every `kid` ever derived from a
seed changes. Handing over the key gets the same stability for none of that.

To exercise a client against an unknown `kid`, point it at a target with
`tamper: [signature]`, which signs with a structurally valid key that is deliberately
absent from the JWKS. That key is always freshly generated, configured key or not — its
whole job is to be unverifiable.

## Scenarios are configuration

`authside` has no runtime API. Every *behaviour* a test might want to vary is a value in
the config file, and the way to have two behaviours available at once is to run two targets
— which costs nothing, because targets are independent by construction.

*Who logs in* is the one thing that has always come from the request instead: a click in
`picker`, a submitted username in `form`, the `authside_sub` cookie under `auto`, and — on
a target that opts in — a whole identity in the `authside_claims` cookie (see
[Identities the config never listed](#identities-the-config-never-listed)). None of those
mutate the server: they are read from the request carrying them, so there is still nothing
to reset between tests and nothing for two parallel tests to race over.

| Scenario | Configuration |
|---|---|
| Who logs in | `login: picker` and click, or `login: auto` with an `authside_sub` cookie / `default_user` |
| A token that is already expired | `id_token_ttl: -5m`, `access_token_ttl: -5m` |
| A token that is not valid yet | `nbf_skew: 5m` |
| An endpoint that fails | `errors: {token: invalid_grant}` — that target always fails there |
| A deliberately broken token | `tamper: [at_hash]` — see [Negative testing](#negative-testing) |
| An unknown `kid` | `tamper: [signature]` |
| A user the config does not list | `login: form` with `accept_any_username: true` |
| A user with claims the config does not list | `login: auto` with `accept_injected_claims: true` and the `authside_claims` cookie |

Targets that differ in one setting do not have to be written out twice — YAML anchors are
enough, and no scenario-inheritance syntax of `authside`'s own is involved:

```yaml
# NOTE: draft format — subject to change.
targets:
  - &base
    name: oidc
    type: oidc
    issuer: http://authside:5556/oidc
    clients:
      - client_id: local-app
        client_secret: local-secret
        redirect_uris: [http://localhost:8080/auth/callback]
    users:
      - sub: user-1
        claims: {email: alice@example.com}

  - <<: *base
    name: oidc-expired          # same clients and users; tokens arrive expired
    issuer: http://authside:5556/oidc-expired
    id_token_ttl: -5m

  - <<: *base
    name: oidc-broken-at-hash
    issuer: http://authside:5556/oidc-broken-at-hash
    tamper: [at_hash]
```

A test picks its scenario by pointing the application at the matching issuer. Nothing is
queued, nothing has to be reset afterwards, and two tests on different targets cannot
interfere — so the suite can run in parallel without a lock around the mock.

**What this model gives up** is any behaviour that has to change mid-run: rotating signing
keys while a client is connected, or an endpoint that fails once and then succeeds. Those
need a mutable server, and having one means having state that must be reset between tests —
the trade this design makes on purpose. In-process Go tests are not bound by it:
`authsidetest` offers time control (`Advance`/`SetTime`) as ordinary method calls, because
there the state cannot outlive the test that owns the server.

Revoking a token from outside the application is **not** on that list, though it reads like
it should be: revocation is part of the protocol, so a test with the client credentials can
just call `/revocation` itself — see [As a Go library](#as-a-go-library). Mid-test key
rotation is genuinely not offered; the end state it produces, a token whose `kid` is absent
from the JWKS, is reachable today with `tamper: [signature]`.

### Minting a token directly

Sometimes there is no browser and no application in the loop — you want the token itself,
to paste into a request or seed a fixture. `authside token` mints one for a configured
user and prints it as a single JSON line on stdout:

```console
$ authside token --config authside.yaml --client local-app --user user-1
{"id_token":"eyJ…","access_token":"eyJ…","expires_in":3600}
```

`--target` picks the target when the config has more than one; with a single target it can
be omitted. `--scope` sets the access token's scope (default `openid`). Everything the
target configures applies exactly as it does to a token from a real login — claims, the
issuer template, TTLs including negative ones, `nbf_skew` and `tamper` — because this is
the same code path, not a second one.

> [!IMPORTANT]
> **Give the target a `key_file` if anything is going to verify these tokens.** Without
> one, the key that signed them is generated for that invocation and gone when it exits,
> so they verify against no running `authside` — the command says so on stderr when that is
> the case. With one, the CLI and the server sign with the same key and the tokens verify
> normally. `--jwks` is the other way out: it adds the matching key set to the output, to
> hand straight to a verifier (`go-oidc`'s `oidc.StaticKeySet` with `oidc.NewVerifier`,
> for instance) instead of fetching a `jwks_uri`. There is a test for each route.

Two things a headless mint deliberately does not return. There is no `refresh_token`: it
would be a handle into state that dies with the process. And the ID token carries no
`nonce`, for the same reason a refreshed one does not — there was no authentication request
to have sent one. On an `access_token: opaque` target the access token is minted and
printed too, but nothing registers it in a session store, so the ID token is the usable
artifact there.

Warnings and the key caveat go to stderr, so stdout stays pipeable:

```console
$ authside token --config authside.yaml --client local-app --user user-1 | jq -r .id_token
```

## Request log

Assertions about what the client actually sent are read from `authside`'s log rather than
from an endpoint. Every request it handles is one JSON line on stdout:

```json
{"time":"…","target":"oidc","method":"POST","path":"/oidc/token","status":200,"client_id":"local-app","grant_type":"authorization_code","pkce":"S256","sub":"user-1"}
```

A real line, from the token exchange in the quick start above:

```json
{"time":"2026-08-20T12:48:09.171+09:00","target":"oidc","method":"POST","path":"/oidc/token","status":200,"client_id":"local-app","grant_type":"authorization_code","sub":"user-1"}
```

`time`, `target`, `method`, `path` and `status` are always present; `path` is the full
externally visible path, mount included. The protocol fields — `client_id`, `grant_type`,
`pkce`, `sub` — appear only where they apply, and are omitted rather than emitted empty, so
the absence of `pkce` above means that flow genuinely sent none.

Nothing has to be enabled, drained or read back in order, and the log outlives the process
that wrote it — which is what you want when a CI failure is all you have to go on. In
library mode the same records are available as Go values.

## Negative testing

Issuing correct tokens is table stakes. The thing a real IdP can never do for you is issue
a **wrong** one — and a client that forgets to verify something passes every test until the
day an attacker notices. So breaking tokens on purpose is a first-class feature rather than
a collection of one-off flags:

```yaml
tamper: [at_hash]   # at_hash | iss | aud | nonce | exp | signature
```

Each value corrupts exactly one thing and leaves the rest valid, so a client that fails to
reject the token tells you precisely which check is missing. `signature` signs with a
structurally valid key that is not published in the JWKS, which doubles as the test for how
a client handles an unknown `kid` during key rotation.

`errors` is the protocol-level counterpart — a target whose endpoints fail on purpose, so
a client's error handling gets exercised instead of assumed:

```yaml
errors:
  token: invalid_grant
  userinfo: 503
```

## Why not an existing mock?

[`oauth2-proxy/mockoidc`](https://github.com/oauth2-proxy/mockoidc) is the closest Go
equivalent, and the reason it is not enough is specific: it derives `iss` from its own
listen address. Three consequences that cannot be worked around, and which double as
`authside`'s acceptance criteria:

1. **The issuer path suffix is fixed.** `Issuer()` is `Addr() + IssuerBase`, and
   `IssuerBase = "/oidc"` is a const. An issuer ending in `/v2.0` is unreachable.
2. **The scheme follows the listener.** `https` is only returned when the listener itself
   has TLS, so a provider fronted by a TLS-terminating ingress cannot be imitated.
3. **One issuer per process.** `iss` comes from a single config field, so it cannot vary
   per login or per user — which is exactly what a per-tenant provider requires.

`authside` answers all three by treating the issuer as configuration rather than as a
derivative of the listen address. Since these are the acceptance criteria, each one is a
test rather than a claim — in `authside_m2_test.go`:

| Consequence | Test |
|---|---|
| 1. Trailing path segment | `TestM2_1_IssuerWithTrailingPathSegment` — an Entra-shaped issuer ending in `/v2.0`, byte-exact in the discovery document and in `iss` |
| 2. Scheme follows the listener | `TestM2_2_HTTPSIssuerOverPlainHTTPListener_AuthsideNeverRejectsIssuerListenMismatch` — an `https://` issuer served over a plain HTTP listener, verifying under a hand-built `oidc.ProviderConfig` |
| 3. One issuer per process | `TestM2_3_TemplatedPerTenantIssuer` — two users, two tenants, two different `iss` from one target |

The third test also asserts that a token minted for tenant A **fails** verification under
tenant B's issuer. That negative half is the point: both tenants share one JWKS and
`go-oidc` verifies the signature before comparing `iss`, so tenant A's token is
cryptographically valid to tenant B's verifier and the only thing that can reject it is
the `iss` check itself. Without that, "the issuer varies per login" would be a property
nothing actually depends on.

## Prior art

`authside` borrows the dual library/container packaging and claim templating of
[`navikt/mock-oauth2-server`](https://github.com/navikt/mock-oauth2-server), and the
configuration-only container of
[`Soluto/oidc-server-mock`](https://github.com/Soluto/oidc-server-mock) — the one precedent
for having no runtime control surface at all. The
[Firebase Auth Emulator](https://firebase.google.com/docs/emulator-suite/connect_auth) is
where being unmistakably fake comes from, although its unsigned tokens are not an option
here: `go-oidc` verifies signatures, so the `authside-` `kid` prefix carries that job
instead.
For a spec-complete provider, look at [`zitadel/oidc`](https://github.com/zitadel/oidc)
or [`dex`](https://github.com/dexidp/dex) instead.

A mock is not a substitute for the real thing: run your application against the actual
IdP at least once before you ship.

## Roadmap

- [x] OIDC target: discovery, authorize, token, userinfo, JWKS
- [x] Configurable `issuer` / `mount` / `advertise`, decoupled from the listen address
- [x] Multiple targets, and multiple issuers, in one process
- [x] Templated per-tenant issuers, with all three discovery modes (`shared`, `off` and
      `per_issuer`)
- [x] Login modes (`auto`, `picker`, `form`), including identities supplied per login by
      the caller — `accept_injected_claims`, for suites that generate their users at run
      time; see [Identities the config never listed](#identities-the-config-never-listed)
- [x] JWT and opaque access tokens, `at_hash`
- [x] A stable signing key on request — `key_file` / `key_pem`, so a token minted in one
      process verifies in another. There is deliberately no `key_seed`; see [Keys](#keys)
- [x] Refresh token rotation with reuse detection, RFC 7009 revocation, RP-initiated logout
- [x] Negative testing: `tamper` and configured error responses
- [x] Scenario configuration: TTLs, `nbf` skew, per-target YAML inheritance
- [x] Request log as JSON lines
- [x] `authside token` for headless minting
- [x] Go library / `httptest`-style helper — `authsidetest.NewOIDC`, with a controllable
      clock and a readable request log. Ending a session from outside the application works
      through `/revocation` and needs no extra API; rotating keys mid-test is not offered
- [x] Container image, multi-arch — published to `ghcr.io` by the release workflow
- [x] Prebuilt binaries and a GitHub Release, cut by pushing a `v*` tag
- [x] An opt-in reachability probe — `--probe`, which GETs each `advertise.internal` once
      at startup and warns without ever failing startup; see
      [Probing advertise.internal](#probing-advertiseinternal) for what it can and cannot
      see
- [ ] Plain OAuth 2.0 target (no ID token)
- [ ] Forward-auth / header injection target, for apps behind an authenticating proxy
- [ ] SAML 2.0 IdP target
- [ ] IdP presets that mirror a real provider's discovery document (Entra, Google)

## Development

```console
$ go test ./...                     # the whole suite
$ go test . -run 'TestM1|TestM2'    # the acceptance tests, driven by a real go-oidc client
$ go run ./cmd/authside --config examples/compose/authside.yaml
$ docker build -t authside .        # the sidecar image
$ cd examples/compose && docker compose up --build
```

`authside.New(cfg)` returns an `http.Handler` and is given no listen address — binding
belongs to `cmd/authside` alone. That is deliberate rather than tidy: it makes the failure
this project exists to avoid (deriving `iss` from the address you happen to listen on)
impossible to write here, because the core has no address to derive it from.

### Cutting a release

Push a `v*` tag. `.github/workflows/release.yml` then verifies (gofmt, vet, `-race`
tests), builds the archives and the GitHub Release with
[goreleaser](https://goreleaser.com), and pushes the multi-arch image to `ghcr.io`. It
runs on tags only — nothing publishes from a branch push, deliberately, so an unreviewed
`HEAD` is never one `docker pull` away.

```console
$ git tag v0.1.0 && git push origin v0.1.0
$ goreleaser check                      # validate .goreleaser.yaml
$ goreleaser release --snapshot --clean # build the artifacts locally, publish nothing
```

The version in `authside --version` comes from the tag two ways: goreleaser and the
`Dockerfile` inject it via `-ldflags -X main.version`, and for
`go install ...@v0.1.0` — which involves neither — `cmd/authside/version.go` falls back to
the module version Go stamps into the binary. A plain `go build` says `dev`.

## License

MIT. See [LICENSE](LICENSE).
