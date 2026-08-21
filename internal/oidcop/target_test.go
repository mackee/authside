package oidcop

import (
	"testing"

	"github.com/mackee/authside/config"
)

// testTarget returns a minimal, valid config.Target for login: auto with
// one client and one user, suitable for New(). Individual tests mutate
// the fields they care about before calling New.
func testTarget() *config.Target {
	d := config.Duration(0)
	return &config.Target{
		Name:      "oidc",
		Type:      "oidc",
		Issuer:    "http://authside.example/oidc",
		Mount:     "/oidc",
		Login:     config.LoginAuto,
		Discovery: config.DiscoverShared,
		Clients: []config.Client{
			{ClientID: "client-1", ClientSecret: "secret-1", RedirectURIs: []string{"https://app.example/cb"}},
		},
		Users: []config.User{
			{Sub: "user-1", Claims: map[string]any{"email": "alice@example.com"}},
		},
		IDTokenTTL:     &d,
		AccessTokenTTL: &d,
		NBFSkew:        &d,
	}
}

// TestNew_AcceptsAllLoginModes confirms that login: picker and
// login: form are both implemented, so New must succeed for them exactly
// as it does for auto (see target.go's New).
func TestNew_AcceptsAllLoginModes(t *testing.T) {
	for _, mode := range []config.LoginMode{config.LoginAuto, config.LoginPicker, config.LoginForm} {
		tgt := testTarget()
		tgt.Login = mode
		if _, err := New(tgt, nil, nil); err != nil {
			t.Fatalf("New() with login: %s = %v, want nil error", mode, err)
		}
	}
}

// TestNew_AcceptsEveryDiscoveryMode confirms that per_issuer is
// implemented (discovery_periss.go), so New must succeed for all three
// modes. It can still fail for a per_issuer config whose issuers are
// unservable -- see TestPerIssuer_RefusedAtConstruction -- but never
// because of the mode itself.
func TestNew_AcceptsEveryDiscoveryMode(t *testing.T) {
	for _, mode := range []config.DiscoveryMode{config.DiscoverShared, config.DiscoverPerIssuer, config.DiscoverOff} {
		tgt := testTarget()
		tgt.Discovery = mode
		if _, err := New(tgt, nil, nil); err != nil {
			t.Fatalf("New() with discovery: %s = %v, want nil error", mode, err)
		}
	}
}

// TestNew_AcceptsBothAccessTokenFormats confirms that both access token
// formats are implemented (token.go's mintAccessToken), so New must
// succeed for either. The empty string is included deliberately -- a
// config.Target built by hand never went through config.ApplyDefaults,
// and must fall back to jwt rather than being refused (see
// Target.accessToken).
func TestNew_AcceptsBothAccessTokenFormats(t *testing.T) {
	for _, format := range []config.AccessTokenType{config.AccessTokenJWT, config.AccessTokenOpaque, ""} {
		tgt := testTarget()
		tgt.AccessToken = format
		if _, err := New(tgt, nil, nil); err != nil {
			t.Fatalf("New() with access_token: %q = %v, want nil error", format, err)
		}
	}
}

// TestNew_AcceptsAllTamperValues confirms that every tamper: value is
// implemented (see jwt.go's use of tamperSet), so New must succeed for
// each of them individually and for all six listed together, instead of
// refusing construction.
func TestNew_AcceptsAllTamperValues(t *testing.T) {
	all := []config.TamperTarget{
		config.TamperAtHash, config.TamperIss, config.TamperAud,
		config.TamperNonce, config.TamperExp, config.TamperSignature,
	}
	for _, tm := range all {
		tgt := testTarget()
		tgt.Tamper = []config.TamperTarget{tm}
		if _, err := New(tgt, nil, nil); err != nil {
			t.Fatalf("New() with tamper: [%s] = %v, want nil error", tm, err)
		}
	}

	tgt := testTarget()
	tgt.Tamper = all
	if _, err := New(tgt, nil, nil); err != nil {
		t.Fatalf("New() with all tamper values set = %v, want nil error", err)
	}
}

// TestNew_AcceptsErrors confirms that errors: is implemented (see
// errors.go's configuredError and every handler that calls it), so New
// must succeed with it set instead of refusing construction.
func TestNew_AcceptsErrors(t *testing.T) {
	tgt := testTarget()
	tgt.Errors = map[string]config.ErrorSpec{"token": "invalid_grant", "userinfo": "503"}
	if _, err := New(tgt, nil, nil); err != nil {
		t.Fatalf("New() with errors: set = %v, want nil error", err)
	}
}

func TestNew_RefusesUnknownClaimInIssuerTemplate(t *testing.T) {
	tgt := testTarget()
	tgt.Issuer = "http://authside.example/${claims.tid}/v2.0"
	_, err := New(tgt, nil, nil)
	if err == nil {
		t.Fatalf("New() with an issuer referencing a claim no user has = nil error, want a construction-time error")
	}
}

func TestNew_Succeeds(t *testing.T) {
	if _, err := New(testTarget(), nil, nil); err != nil {
		t.Fatalf("New() = %v, want nil", err)
	}
}
