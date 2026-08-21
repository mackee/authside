package config

import (
	"strings"
	"testing"
)

func minimalTarget(name string) Target {
	return Target{
		Name:   name,
		Type:   "oidc",
		Issuer: "http://authside:5556/" + name,
		Clients: []Client{
			{ClientID: "app-" + name, ClientSecret: "s", RedirectURIs: []string{"http://localhost:8080/cb"}},
		},
		Users: []User{{Sub: "user-1"}},
	}
}

func loadedOK(t *testing.T, cfg *Config) *Config {
	t.Helper()
	ApplyDefaults(cfg)
	if err := Validate(cfg); err != nil {
		t.Fatalf("Validate: unexpected error: %v", err)
	}
	return cfg
}

func mustFail(t *testing.T, cfg *Config, wantSubstr string) error {
	t.Helper()
	ApplyDefaults(cfg)
	err := Validate(cfg)
	if err == nil {
		t.Fatalf("Validate: expected an error containing %q, got nil", wantSubstr)
	}
	if !strings.Contains(err.Error(), wantSubstr) {
		t.Fatalf("Validate error = %q, want substring %q", err.Error(), wantSubstr)
	}
	return err
}

func TestValidate_MinimalOK(t *testing.T) {
	cfg := &Config{Targets: []Target{minimalTarget("oidc")}}
	loadedOK(t, cfg)
}

func TestValidate_NoTargets(t *testing.T) {
	cfg := &Config{}
	mustFail(t, cfg, "at least one target is required")
}

func TestValidate_DuplicateNames(t *testing.T) {
	a := minimalTarget("oidc")
	b := minimalTarget("oidc")
	b.Mount = "/oidc2" // avoid also tripping the mount check
	cfg := &Config{Targets: []Target{a, b}}
	mustFail(t, cfg, "duplicate target name")
}

func TestValidate_DuplicateMounts(t *testing.T) {
	a := minimalTarget("oidc")
	b := minimalTarget("oidc2")
	b.Mount = "/oidc" // same as a's default mount
	cfg := &Config{Targets: []Target{a, b}}
	mustFail(t, cfg, "collides with")
}

func TestValidate_CollidingMounts_SegmentPrefix(t *testing.T) {
	a := minimalTarget("oidc")
	a.Mount = "/oidc"
	b := minimalTarget("oidc-sub")
	b.Mount = "/oidc/sub"
	cfg := &Config{Targets: []Target{a, b}}
	mustFail(t, cfg, "collides with")
}

func TestValidate_NonCollidingSimilarMounts(t *testing.T) {
	a := minimalTarget("oidc")
	a.Mount = "/oidc"
	b := minimalTarget("oidc2")
	b.Mount = "/oidc2"
	cfg := &Config{Targets: []Target{a, b}}
	loadedOK(t, cfg) // must NOT collide -- "oidc2" is not a path segment inside "/oidc"
}

func TestValidate_RootMountCollidesWithEverything(t *testing.T) {
	a := minimalTarget("root")
	a.Mount = "/"
	b := minimalTarget("oidc")
	b.Mount = "/oidc"
	cfg := &Config{Targets: []Target{a, b}}
	mustFail(t, cfg, "collides with")
}

func TestValidate_MountMustStartWithSlash(t *testing.T) {
	a := minimalTarget("oidc")
	a.Mount = "oidc-no-leading-slash"
	cfg := &Config{Targets: []Target{a}}
	mustFail(t, cfg, `must start with "/"`)
}

func TestValidate_UnknownType(t *testing.T) {
	a := minimalTarget("oidc")
	a.Type = "saml"
	cfg := &Config{Targets: []Target{a}}
	err := mustFail(t, cfg, "unknown type")
	if !strings.Contains(err.Error(), "oidc") {
		t.Fatalf("error should name the supported values: %v", err)
	}
}

func TestValidate_UnknownTamper(t *testing.T) {
	a := minimalTarget("oidc")
	a.Tamper = []TamperTarget{"bogus"}
	cfg := &Config{Targets: []Target{a}}
	mustFail(t, cfg, "tamper")
}

func TestValidate_UnknownErrorsEndpoint(t *testing.T) {
	a := minimalTarget("oidc")
	a.Errors = map[string]ErrorSpec{"bogus_endpoint": "invalid_grant"}
	cfg := &Config{Targets: []Target{a}}
	err := mustFail(t, cfg, "unknown endpoint")
	if !strings.Contains(err.Error(), "authorize") {
		t.Fatalf("error should list valid endpoint names: %v", err)
	}
}

func TestValidate_UnknownErrorsValue(t *testing.T) {
	a := minimalTarget("oidc")
	a.Errors = map[string]ErrorSpec{"token": "not_a_real_code"}
	cfg := &Config{Targets: []Target{a}}
	mustFail(t, cfg, "neither a known OAuth error code nor a 3-digit HTTP status")
}

func TestValidate_ErrorsAcceptsKnownCodeAndHTTPStatus(t *testing.T) {
	a := minimalTarget("oidc")
	a.Errors = map[string]ErrorSpec{"token": "invalid_grant", "userinfo": "503"}
	cfg := &Config{Targets: []Target{a}}
	loadedOK(t, cfg)
}

func TestValidate_ErrorsRejectsNonThreeDigitStatus(t *testing.T) {
	a := minimalTarget("oidc")
	a.Errors = map[string]ErrorSpec{"userinfo": "9999"}
	cfg := &Config{Targets: []Target{a}}
	mustFail(t, cfg, "neither a known OAuth error code nor a 3-digit HTTP status")
}

func TestValidate_BadLoginEnum(t *testing.T) {
	a := minimalTarget("oidc")
	a.Login = "bogus"
	cfg := &Config{Targets: []Target{a}}
	mustFail(t, cfg, "login")
}

func TestValidate_BadDiscoveryEnum(t *testing.T) {
	a := minimalTarget("oidc")
	a.Discovery = "bogus"
	cfg := &Config{Targets: []Target{a}}
	mustFail(t, cfg, "discovery")
}

func TestValidate_BadAccessTokenEnum(t *testing.T) {
	a := minimalTarget("oidc")
	a.AccessToken = "bogus"
	cfg := &Config{Targets: []Target{a}}
	mustFail(t, cfg, "access_token")
}

func TestValidate_BadRefreshTokenEnum(t *testing.T) {
	a := minimalTarget("oidc")
	a.RefreshToken = "bogus"
	cfg := &Config{Targets: []Target{a}}
	mustFail(t, cfg, "refresh_token")
}

func TestValidate_MissingClientID(t *testing.T) {
	a := minimalTarget("oidc")
	a.Clients = []Client{{ClientSecret: "s", RedirectURIs: []string{"http://localhost:8080/cb"}}}
	cfg := &Config{Targets: []Target{a}}
	mustFail(t, cfg, "client_id is required")
}

func TestValidate_EmptyRedirectURIs(t *testing.T) {
	a := minimalTarget("oidc")
	a.Clients = []Client{{ClientID: "app", ClientSecret: "s"}}
	cfg := &Config{Targets: []Target{a}}
	mustFail(t, cfg, "redirect_uris")
}

func TestValidate_RelativeRedirectURI(t *testing.T) {
	a := minimalTarget("oidc")
	a.Clients = []Client{{ClientID: "app", ClientSecret: "s", RedirectURIs: []string{"/cb"}}}
	cfg := &Config{Targets: []Target{a}}
	mustFail(t, cfg, "must be an absolute URL")
}

func TestValidate_NoClients(t *testing.T) {
	a := minimalTarget("oidc")
	a.Clients = nil
	cfg := &Config{Targets: []Target{a}}
	mustFail(t, cfg, "clients: at least one client is required")
}

func TestValidate_DuplicateClientID(t *testing.T) {
	a := minimalTarget("oidc")
	a.Clients = []Client{
		{ClientID: "dup", ClientSecret: "s", RedirectURIs: []string{"http://localhost:8080/cb"}},
		{ClientID: "dup", ClientSecret: "s2", RedirectURIs: []string{"http://localhost:8080/cb2"}},
	}
	cfg := &Config{Targets: []Target{a}}
	mustFail(t, cfg, "duplicate client_id")
}

func TestValidate_DuplicateSub(t *testing.T) {
	a := minimalTarget("oidc")
	a.Users = []User{{Sub: "dup"}, {Sub: "dup"}}
	cfg := &Config{Targets: []Target{a}}
	mustFail(t, cfg, "duplicate sub")
}

func TestValidate_EmptyUsersRejectedWithoutAcceptAny(t *testing.T) {
	a := minimalTarget("oidc")
	a.Users = nil
	cfg := &Config{Targets: []Target{a}}
	mustFail(t, cfg, "accept_any_username")
}

func TestValidate_EmptyUsersOKWithAcceptAny(t *testing.T) {
	a := minimalTarget("oidc")
	a.Users = nil
	a.AcceptAnyUsername = true
	cfg := &Config{Targets: []Target{a}}
	loadedOK(t, cfg)
}

func TestValidate_DefaultUserMustExist(t *testing.T) {
	a := minimalTarget("oidc")
	a.DefaultUser = "no-such-user"
	cfg := &Config{Targets: []Target{a}}
	mustFail(t, cfg, "default_user")
}

func TestValidate_DefaultUserMatchingExistingUserOK(t *testing.T) {
	a := minimalTarget("oidc")
	a.DefaultUser = "user-1"
	cfg := &Config{Targets: []Target{a}}
	loadedOK(t, cfg)
}

func TestValidate_LoginAutoWithoutDefaultUserWarnsNotErrors(t *testing.T) {
	a := minimalTarget("oidc")
	a.Login = LoginAuto
	cfg := &Config{Targets: []Target{a}}
	loadedOK(t, cfg) // must not error
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "login: auto") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a login:auto warning, got %v", cfg.Warnings)
	}
}

func TestValidate_LoginAutoWithDefaultUserNoWarning(t *testing.T) {
	a := minimalTarget("oidc")
	a.Login = LoginAuto
	a.DefaultUser = "user-1"
	cfg := &Config{Targets: []Target{a}}
	loadedOK(t, cfg)
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "login: auto") {
			t.Fatalf("unexpected login:auto warning when default_user is set: %v", cfg.Warnings)
		}
	}
}

// TestValidate_KeyPEMAndKeyFileAreMutuallyExclusive replaces the old
// TestValidate_KeySeedWarns: key_seed is gone (README "Keys" says why),
// and the one thing this package can check about a supplied key without
// reading or parsing it is that only one source was named.
func TestValidate_KeyPEMAndKeyFileAreMutuallyExclusive(t *testing.T) {
	a := minimalTarget("oidc")
	a.KeyPEM = "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----"
	a.KeyFile = "./signing-key.pem"
	mustFail(t, &Config{Targets: []Target{a}}, "mutually exclusive")
}

// Either one alone is fine here. Whether the key actually parses is
// internal/keys' business, not this package's -- config stays a leaf and
// reads no files.
func TestValidate_EitherKeySourceAloneIsAccepted(t *testing.T) {
	for name, mutate := range map[string]func(*Target){
		"key_pem":  func(t *Target) { t.KeyPEM = "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----" },
		"key_file": func(t *Target) { t.KeyFile = "./signing-key.pem" },
		"neither":  func(t *Target) {},
	} {
		t.Run(name, func(t *testing.T) {
			a := minimalTarget("oidc")
			mutate(&a)
			loadedOK(t, &Config{Targets: []Target{a}})
		})
	}
}

func TestValidate_IssuerRequired(t *testing.T) {
	a := minimalTarget("oidc")
	a.Issuer = ""
	cfg := &Config{Targets: []Target{a}}
	mustFail(t, cfg, "issuer is required")
}

func TestValidate_IssuerMustBeAbsolute(t *testing.T) {
	a := minimalTarget("oidc")
	a.Issuer = "/relative/path"
	cfg := &Config{Targets: []Target{a}}
	mustFail(t, cfg, "must be an absolute URL")
}

func TestValidate_IssuerAcceptsTemplatePlaceholder(t *testing.T) {
	a := minimalTarget("entra")
	a.Issuer = "https://login.microsoftonline.com/${claims.tid}/v2.0"
	cfg := &Config{Targets: []Target{a}}
	loadedOK(t, cfg)
	if cfg.Targets[0].Issuer != "https://login.microsoftonline.com/${claims.tid}/v2.0" {
		t.Fatalf("issuer was mangled: %q", cfg.Targets[0].Issuer)
	}
}

func TestValidate_DiscoveryPerIssuerIsAcceptedHere(t *testing.T) {
	// discovery: per_issuer is a valid enum value and must load without
	// error. Whether its rendered issuers can actually be served -- the
	// route-collision and under-the-mount checks -- is decided in
	// internal/oidcop at construction, not here; see the "On NOT checking
	// discovery: per_issuer route collisions here" note in validate.go
	// for why this package stays out of it. This test pins "accepted",
	// and deliberately nothing more.
	a := minimalTarget("entra")
	a.Discovery = DiscoverPerIssuer
	cfg := &Config{Targets: []Target{a}}
	loadedOK(t, cfg)
}

// TestValidate_AggregatesMultipleErrors is the aggregation contract: a
// config with several independent problems reports all of them in one
// Validate call via errors.Join, not just the first one encountered.
func TestValidate_AggregatesMultipleErrors(t *testing.T) {
	a := minimalTarget("oidc")
	a.Type = "saml"                 // problem 1
	a.Tamper = []TamperTarget{"xx"} // problem 2
	a.Clients = nil                 // problem 3
	a.Users = nil                   // problem 4 (no accept_any_username)
	cfg := &Config{Targets: []Target{a}}
	ApplyDefaults(cfg)
	err := Validate(cfg)
	if err == nil {
		t.Fatalf("expected aggregated error, got nil")
	}
	msg := err.Error()
	for _, want := range []string{"unknown type", "tamper", "clients: at least one client", "accept_any_username"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("aggregated error missing %q; full error:\n%s", want, msg)
		}
	}
}
