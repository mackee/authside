package config

// This file loads, as close to verbatim as possible, every YAML example
// from README.md and asserts the parse result / defaults the README
// promises. Two of the README's blocks are not literally parseable as
// written: "Several providers in one process" uses `[{client_id:
// app-google, ...}]` and `users: [...]` (literal elision for readability
// in prose), and neither the split-horizon nor the per-tenant example
// includes a `clients:` block at all (this package requires at least one
// client per target). Where that happens, the spec-relevant lines
// (issuer/mount/advertise/users/discovery) are kept character-for-character
// and only the elided/missing parts are filled in with a minimal, concrete
// stand-in — each such fill is called out in a comment at the point it
// happens.

import (
	"testing"
	"time"
)

// TestQuickStartYAML loads the README "Quick start" authside.yaml verbatim.
func TestQuickStartYAML(t *testing.T) {
	const doc = `
listen: 0.0.0.0:5556       # container-local loopback would be unreachable from ` + "`app`" + `

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
`
	cfg, err := LoadBytes([]byte(doc))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if cfg.Listen != "0.0.0.0:5556" {
		t.Fatalf("Listen = %q", cfg.Listen)
	}
	// The quick start warns about nothing: it is a single process whose
	// client discovers the JWKS at run time, so it needs no configured
	// signing key, and login: picker needs no default_user.
	if len(cfg.Warnings) != 0 {
		t.Fatalf("Warnings = %v, want none", cfg.Warnings)
	}
	if len(cfg.Targets) != 1 {
		t.Fatalf("len(Targets) = %d, want 1", len(cfg.Targets))
	}
	tgt := cfg.Targets[0]
	if tgt.Mount != "/oidc" {
		t.Fatalf("Mount = %q, want /oidc (defaulted from name)", tgt.Mount)
	}
	if tgt.Type != "oidc" {
		t.Fatalf("Type = %q", tgt.Type)
	}
	if tgt.Issuer != "http://authside:5556/oidc" {
		t.Fatalf("Issuer = %q", tgt.Issuer)
	}
	if tgt.Login != LoginPicker {
		t.Fatalf("Login = %q", tgt.Login)
	}
	// Defaulted fields not present in the YAML.
	if tgt.Discovery != DiscoverShared {
		t.Fatalf("Discovery = %q, want default shared", tgt.Discovery)
	}
	if tgt.AccessToken != AccessTokenJWT {
		t.Fatalf("AccessToken = %q, want default jwt", tgt.AccessToken)
	}
	if tgt.RefreshToken != RefreshRotate {
		t.Fatalf("RefreshToken = %q, want default rotate", tgt.RefreshToken)
	}
	if tgt.IDTokenTTL == nil || time.Duration(*tgt.IDTokenTTL) != time.Hour {
		t.Fatalf("IDTokenTTL = %v, want default 1h", tgt.IDTokenTTL)
	}
	if tgt.AccessTokenTTL == nil || time.Duration(*tgt.AccessTokenTTL) != time.Hour {
		t.Fatalf("AccessTokenTTL = %v, want default 1h", tgt.AccessTokenTTL)
	}
	if tgt.NBFSkew == nil || time.Duration(*tgt.NBFSkew) != 0 {
		t.Fatalf("NBFSkew = %v, want default 0", tgt.NBFSkew)
	}
	if len(tgt.Clients) != 1 || tgt.Clients[0].ClientID != "local-app" {
		t.Fatalf("Clients = %+v", tgt.Clients)
	}
	if len(tgt.Users) != 2 || tgt.Users[0].Sub != "user-1" || tgt.Users[1].Sub != "user-2" {
		t.Fatalf("Users = %+v", tgt.Users)
	}
	if tgt.Users[0].Claims["email"] != "alice@example.com" {
		t.Fatalf("Users[0].Claims = %+v", tgt.Users[0].Claims)
	}
}

// TestSeveralProvidersYAML mirrors README "Several providers in one
// process": the issuer/mount/type/users lines for each target are kept
// verbatim, but the prose elisions `clients: [{client_id: app-google,
// ...}]` and `users: [...]` are filled in with minimal concrete clients
// (the README does not spell out client secrets/redirect URIs there,
// since the whole point of the section is that they're independent, not
// what their values are).
func TestSeveralProvidersYAML(t *testing.T) {
	// NOTE: filled in as block-style clients rather than the README's
	// elided `clients: [{client_id: app-google, ...}]` for two reasons:
	// the elision itself doesn't parse, and (verified empirically)
	// goccy/go-yaml v1.19.2 mis-parses a redirect URI containing a port
	// number (e.g. "http://localhost:8080/cb") when it sits inside a
	// flow-sequence-of-flow-maps nested inside another flow sequence --
	// three levels of flow nesting. Block style sidesteps that; it is a
	// config-authoring choice, not something the README's spec requires
	// either way.
	const doc = `
targets:
  - name: google           # mounted at /google
    type: oidc
    issuer: http://authside:5556/google
    clients:
      - client_id: app-google
        client_secret: s
        redirect_uris: [http://localhost:8080/cb]
    users:
      - sub: user-1
        claims: {email: alice@example.com, hd: example.com}

  - name: internal         # mounted at /internal
    type: oidc
    issuer: http://authside:5556/internal
    clients:
      - client_id: app-internal
        client_secret: s
        redirect_uris: [http://localhost:8080/cb]
    users:
      - sub: user-1
        claims: {email: alice@internal.example}
`
	cfg, err := LoadBytes([]byte(doc))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if len(cfg.Targets) != 2 {
		t.Fatalf("len(Targets) = %d, want 2", len(cfg.Targets))
	}
	google, internal := cfg.Targets[0], cfg.Targets[1]
	if google.Mount != "/google" || internal.Mount != "/internal" {
		t.Fatalf("mounts = %q, %q, want /google, /internal", google.Mount, internal.Mount)
	}
	if google.Mount == internal.Mount {
		t.Fatalf("mounts must be distinct")
	}
	if google.Clients[0].ClientID == internal.Clients[0].ClientID {
		t.Fatalf("clients must be independent per target")
	}
	if google.Users[0].Claims["hd"] != "example.com" {
		t.Fatalf("google user claims = %+v", google.Users[0].Claims)
	}
	if _, ok := internal.Users[0].Claims["hd"]; ok {
		t.Fatalf("internal user must not inherit google's hd claim: %+v", internal.Users[0].Claims)
	}
}

// TestSplitHorizonYAML mirrors README "Split-horizon dev environments".
// The README's snippet has no `clients:` block at all (it is about
// issuer/mount/advertise only), so a minimal client is added to satisfy
// "at least one client per target" — everything else, in particular
// issuer/mount/advertise, is verbatim.
func TestSplitHorizonYAML(t *testing.T) {
	const doc = `
targets:
  - name: oidc
    type: oidc
    issuer: https://auth.local.test/oidc        # verified string only
    mount: /oidc
    advertise:
      internal: http://authside:5556/oidc       # token, jwks, userinfo — app-facing
      browser: https://auth.local.test/oidc     # authorize, end_session — browser-facing
    clients:
      - client_id: local-app
        client_secret: local-secret
        redirect_uris: [http://localhost:8080/auth/callback]
    users:
      - sub: user-1
`
	cfg, err := LoadBytes([]byte(doc))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	tgt := cfg.Targets[0]
	if tgt.Issuer != "https://auth.local.test/oidc" {
		t.Fatalf("Issuer = %q", tgt.Issuer)
	}
	if tgt.Advertise.Internal != "http://authside:5556/oidc" {
		t.Fatalf("Advertise.Internal = %q", tgt.Advertise.Internal)
	}
	if tgt.Advertise.Browser != "https://auth.local.test/oidc" {
		t.Fatalf("Advertise.Browser = %q", tgt.Advertise.Browser)
	}
	// The point of split-horizon is that issuer and advertise.internal
	// differ (the app reaches authside over a different base URL than
	// the one embedded in `iss`) -- and in this concrete README example
	// they do. advertise.browser, by contrast, is written identically to
	// issuer here (the browser happens to reach authside through the
	// same hostname the issuer names), which is a legitimate, unrelated
	// fact about this particular example, not something either value is
	// required to differ from.
	if tgt.Issuer == tgt.Advertise.Internal {
		t.Fatalf("issuer must differ from advertise.internal in this split-horizon example")
	}
}

// TestPerTenantIssuerYAML mirrors README "Per-tenant issuers". No
// `clients:` block in the README snippet either; a minimal one is added.
// The point of this test is that the template placeholder ${claims.tid}
// survives parsing byte-for-byte -- it must NOT be resolved or mangled
// at load time (there is no per-login context available yet at config
// load time to resolve it against, and even if there were, the whole
// point of discovery: shared is to leave it unresolved -- see README
// "Discovery under a templated issuer").
func TestPerTenantIssuerYAML(t *testing.T) {
	const doc = `
targets:
  - name: entra
    type: oidc
    issuer: https://login.microsoftonline.com/${claims.tid}/v2.0
    mount: /entra
    clients:
      - client_id: local-app
        client_secret: local-secret
        redirect_uris: [http://localhost:8080/auth/callback]
    users:
      - sub: user-1
        claims:
          tid: 11111111-1111-1111-1111-111111111111
          email: alice@example.com
      - sub: user-2
        claims:
          tid: 22222222-2222-2222-2222-222222222222
          email: bob@example.net
`
	cfg, err := LoadBytes([]byte(doc))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	tgt := cfg.Targets[0]
	const want = "https://login.microsoftonline.com/${claims.tid}/v2.0"
	if tgt.Issuer != want {
		t.Fatalf("Issuer = %q, want verbatim %q (placeholder must survive unresolved)", tgt.Issuer, want)
	}
	if tgt.Mount != "/entra" {
		t.Fatalf("Mount = %q", tgt.Mount)
	}
	if len(tgt.Users) != 2 {
		t.Fatalf("len(Users) = %d, want 2", len(tgt.Users))
	}
	if tgt.Users[0].Claims["tid"] != "11111111-1111-1111-1111-111111111111" {
		t.Fatalf("Users[0].Claims[tid] = %v", tgt.Users[0].Claims["tid"])
	}
}

// TestScenarioAnchorYAML mirrors README "Scenarios are configuration":
// the anchor/merge-key example, verbatim.
// TestPerIssuerDiscoveryYAML mirrors README "Per-issuer discovery",
// verbatim. What it pins is that the templated issuer survives parsing
// byte-for-byte alongside discovery: per_issuer -- this package must not
// resolve or reject the template, since whether the rendered issuers are
// actually servable is decided in internal/oidcop at construction (see
// the "On NOT checking discovery: per_issuer route collisions here" note
// in validate.go).
func TestPerIssuerDiscoveryYAML(t *testing.T) {
	const doc = `
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
`
	cfg, err := LoadBytes([]byte(doc))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	tgt := cfg.Targets[0]
	if tgt.Discovery != DiscoverPerIssuer {
		t.Fatalf("Discovery = %q, want %q", tgt.Discovery, DiscoverPerIssuer)
	}
	if tgt.Issuer != "http://authside:5556/entra/${claims.tid}" {
		t.Fatalf("issuer was mangled: %q", tgt.Issuer)
	}
	if len(tgt.Users) != 2 || tgt.Users[0].Claims["tid"] != "tenant-a" || tgt.Users[1].Claims["tid"] != "tenant-b" {
		t.Fatalf("users = %+v, want the two tenants the README example configures", tgt.Users)
	}
}

// TestOpaqueAccessTokenYAML mirrors README "Tokens". No `clients:` or
// `users:` block in the README snippet (the point it is making is one
// line long); minimal ones are added. What this pins is that
// `access_token: opaque` parses to AccessTokenOpaque and, unlike every
// other target in this file, does NOT come back as the jwt default --
// the enum check in Validate accepts both spellings, so a typo'd
// constant would otherwise go unnoticed here.
func TestOpaqueAccessTokenYAML(t *testing.T) {
	const doc = `
targets:
  - name: oidc
    type: oidc
    issuer: http://localhost:5556/oidc
    access_token: opaque
    clients:
      - client_id: local-app
        client_secret: local-secret
        redirect_uris: [http://localhost:8080/auth/callback]
    users:
      - sub: user-1
`
	cfg, err := LoadBytes([]byte(doc))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if got := cfg.Targets[0].AccessToken; got != AccessTokenOpaque {
		t.Fatalf("AccessToken = %q, want %q", got, AccessTokenOpaque)
	}
}

func TestScenarioAnchorYAML(t *testing.T) {
	const doc = `
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
`
	cfg, err := LoadBytes([]byte(doc))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if len(cfg.Targets) != 3 {
		t.Fatalf("len(Targets) = %d, want 3", len(cfg.Targets))
	}
	base, expired, brokenAtHash := cfg.Targets[0], cfg.Targets[1], cfg.Targets[2]

	if expired.Name != "oidc-expired" {
		t.Fatalf("expired.Name = %q", expired.Name)
	}
	if len(expired.Clients) != 1 || expired.Clients[0].ClientID != base.Clients[0].ClientID {
		t.Fatalf("expired.Clients not inherited: %+v", expired.Clients)
	}
	if len(expired.Users) != 1 || expired.Users[0].Sub != "user-1" {
		t.Fatalf("expired.Users not inherited: %+v", expired.Users)
	}
	if expired.Issuer != "http://authside:5556/oidc-expired" {
		t.Fatalf("expired.Issuer override didn't take: %q", expired.Issuer)
	}
	if expired.IDTokenTTL == nil || time.Duration(*expired.IDTokenTTL) != -5*time.Minute {
		t.Fatalf("expired.IDTokenTTL = %v, want -5m", expired.IDTokenTTL)
	}

	if brokenAtHash.Name != "oidc-broken-at-hash" {
		t.Fatalf("brokenAtHash.Name = %q", brokenAtHash.Name)
	}
	if len(brokenAtHash.Tamper) != 1 || brokenAtHash.Tamper[0] != TamperAtHash {
		t.Fatalf("brokenAtHash.Tamper = %+v", brokenAtHash.Tamper)
	}
	if len(brokenAtHash.Users) != 1 || brokenAtHash.Users[0].Sub != "user-1" {
		t.Fatalf("brokenAtHash.Users not inherited: %+v", brokenAtHash.Users)
	}

	// Mounts must still come out distinct despite the shared anchor
	// (each target's own `name` differs, and none set an explicit mount).
	seen := map[string]bool{}
	for _, tg := range cfg.Targets {
		if seen[tg.Mount] {
			t.Fatalf("duplicate mount %q", tg.Mount)
		}
		seen[tg.Mount] = true
	}
}

// TestIssuerListenMismatchAccepted is the regression test for the single
// most important design decision in this package: authside never rejects
// a configuration because `issuer` disagrees with `listen`. See the
// prohibition comment at the top of validate.go for the three README
// reasons (issuer is an identifier not an address; real split-horizon dev
// setups need exactly this; the README says so in as many words). This
// config has an https:// issuer while listen is a plain-HTTP loopback
// address, which is precisely the shape a naive consistency check would
// (wrongly) reject.
func TestIssuerListenMismatchAccepted(t *testing.T) {
	const doc = `
listen: 127.0.0.1:5556

targets:
  - name: oidc
    type: oidc
    issuer: https://login.microsoftonline.com/${claims.tid}/v2.0
    clients:
      - client_id: local-app
        client_secret: local-secret
        redirect_uris: [http://localhost:8080/auth/callback]
    users:
      - sub: user-1
        claims: {tid: 11111111-1111-1111-1111-111111111111}
`
	cfg, err := LoadBytes([]byte(doc))
	if err != nil {
		t.Fatalf("LoadBytes returned an error for a legitimate issuer/listen mismatch: %v", err)
	}
	if cfg.Listen != "127.0.0.1:5556" {
		t.Fatalf("Listen = %q", cfg.Listen)
	}
}
