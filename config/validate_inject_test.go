package config

import (
	"strings"
	"testing"
)

// accept_injected_claims is a login: auto input. Enabling it on a target
// that decides who logs in some other way is a configuration that cannot
// do what it says, so it fails at load rather than silently ignoring the
// cookie at request time.
func TestValidate_InjectedClaimsRequiresLoginAuto(t *testing.T) {
	for _, mode := range []LoginMode{LoginPicker, LoginForm} {
		t.Run(string(mode), func(t *testing.T) {
			tgt := minimalTarget("oidc")
			tgt.Login = mode
			tgt.AcceptInjectedClaims = true
			mustFail(t, &Config{Targets: []Target{tgt}}, "accept_injected_claims requires login: auto")
		})
	}
}

func TestValidate_InjectedClaimsWithLoginAutoOK(t *testing.T) {
	tgt := minimalTarget("oidc")
	tgt.Login = LoginAuto
	tgt.DefaultUser = "user-1"
	tgt.AcceptInjectedClaims = true
	loadedOK(t, &Config{Targets: []Target{tgt}})
}

// The "nobody could ever log in here" rule has a third way out now: a
// target whose every identity arrives in the request needs no users:
// block at all. That is the shape the feature exists for.
func TestValidate_NoUsersOKWithInjectedClaims(t *testing.T) {
	tgt := minimalTarget("oidc")
	tgt.Login = LoginAuto
	tgt.Users = nil
	tgt.AcceptInjectedClaims = true
	loadedOK(t, &Config{Targets: []Target{tgt}})
}

func TestValidate_NoUsersStillFailsWithoutAnyEscapeHatch(t *testing.T) {
	tgt := minimalTarget("oidc")
	tgt.Users = nil
	mustFail(t, &Config{Targets: []Target{tgt}}, "accept_any_username or accept_injected_claims")
}

// login: auto with no default_user is a warning, and its text names the
// cookies that could still make the target work -- including
// authside_claims once injection is on, since that is then a complete
// substitute for default_user.
func TestValidate_AutoWarningNamesClaimsCookieWhenInjectionOn(t *testing.T) {
	tgt := minimalTarget("oidc")
	tgt.Login = LoginAuto
	tgt.AcceptInjectedClaims = true
	cfg := loadedOK(t, &Config{Targets: []Target{tgt}})

	var found string
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "no default_user") {
			found = w
		}
	}
	if found == "" {
		t.Fatalf("expected a no-default_user warning, got %v", cfg.Warnings)
	}
	if !strings.Contains(found, "authside_claims") {
		t.Fatalf("warning = %q, want it to name the authside_claims cookie", found)
	}
}

func TestValidate_AutoWarningNamesOnlySubCookieWhenInjectionOff(t *testing.T) {
	tgt := minimalTarget("oidc")
	tgt.Login = LoginAuto
	cfg := loadedOK(t, &Config{Targets: []Target{tgt}})

	for _, w := range cfg.Warnings {
		if strings.Contains(w, "no default_user") && strings.Contains(w, "authside_claims") {
			t.Fatalf("warning names authside_claims on a target without accept_injected_claims: %q", w)
		}
	}
}
