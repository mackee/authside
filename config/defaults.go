package config

import "time"

// Default TTLs. An hour is a comfortable working session for a manual
// dev loop or an E2E suite, long enough that a test rarely trips over
// expiry by accident, short enough that a target left with the default
// still resembles a real provider's token lifetime rather than
// effectively-forever. A target that wants a token to already be expired
// overrides this explicitly (id_token_ttl: -5m); a target that wants a
// long-lived token overrides it the other way. nbf_skew defaults to 0
// (no "not valid yet" window), since that behaviour is opt-in only.
const (
	defaultIDTokenTTL     = time.Hour
	defaultAccessTokenTTL = time.Hour
	defaultNBFSkew        = time.Duration(0)
)

// ApplyDefaults fills in every field this package defaults, in place. It
// is exported so a Config assembled programmatically (library mode,
// tests) gets the same defaulting as one decoded from YAML, without
// having to round-trip through the YAML decoder first.
//
// Defaulting happens before validation (see LoadBytes): validation checks
// enum fields against their known values, and an empty enum field is
// valid input (it means "use the default"), so defaulting must resolve
// it to a concrete value first.
//
// Defaults applied here (see README "Login modes", "Discovery under a
// templated issuer", "Tokens" and "Refresh tokens"):
//
//	mount          -> "/{name}"
//	login          -> picker
//	discovery      -> shared
//	access_token   -> jwt
//	refresh_token  -> rotate
//	type           -> oidc
//	id_token_ttl     -> 1h  (when unset; explicit 0 and negative values are kept)
//	access_token_ttl -> 1h  (same)
//	nbf_skew         -> 0   (same)
func ApplyDefaults(cfg *Config) {
	if cfg == nil {
		return
	}
	for i := range cfg.Targets {
		t := &cfg.Targets[i]

		if t.Type == "" {
			t.Type = "oidc"
		}
		if t.Mount == "" && t.Name != "" {
			t.Mount = "/" + t.Name
		}
		if t.Login == "" {
			t.Login = LoginPicker
		}
		if t.Discovery == "" {
			t.Discovery = DiscoverShared
		}
		if t.AccessToken == "" {
			t.AccessToken = AccessTokenJWT
		}
		if t.RefreshToken == "" {
			t.RefreshToken = RefreshRotate
		}
		if t.IDTokenTTL == nil {
			d := Duration(defaultIDTokenTTL)
			t.IDTokenTTL = &d
		}
		if t.AccessTokenTTL == nil {
			d := Duration(defaultAccessTokenTTL)
			t.AccessTokenTTL = &d
		}
		if t.NBFSkew == nil {
			d := Duration(defaultNBFSkew)
			t.NBFSkew = &d
		}
	}
}
