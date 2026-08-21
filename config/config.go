// Package config defines the shape of authside's configuration file.
//
// This file holds type definitions only: the YAML/AUTHSIDE_CONFIG_INLINE
// loader, default-value filling and validation live elsewhere (a later
// change owns config.Load and friends). Nothing here should reject or
// mutate a value — it only describes what a well-formed config looks like.
//
// # YAML decoding note for whoever writes the loader
//
// The README requires YAML anchors *and* merge keys inside a sequence
// element, so that `targets` entries can inherit from a `&base` sibling
// (see README "Scenarios are configuration"). This package is decoded with
// github.com/goccy/go-yaml. That library treats a merge key's contribution
// plus an explicit local key of the same name as a "duplicate key" parse
// error by default — even though per the YAML merge-key spec the explicit
// key is supposed to simply win. Decoding this config therefore MUST use:
//
//	yaml.UnmarshalWithOptions(data, &cfg, yaml.AllowDuplicateMapKey())
//
// Using plain yaml.Unmarshal will fail on exactly the
// `<<: *base` + override shape the README's examples depend on. Note that
// this option also silences unrelated, genuine duplicate-key typos in a
// user's config file — there is no narrower knob in goccy/go-yaml v1.19.2
// that allows merge-key overrides without also allowing that. Verified
// against goccy/go-yaml v1.19.2.
package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/goccy/go-yaml"
)

// Config is the top-level shape of authside.yaml (or the value of
// AUTHSIDE_CONFIG_INLINE).
type Config struct {
	// Listen is the address the process binds to, e.g. "0.0.0.0:5556".
	// The server core (package authside) never sees this value: see
	// authside.go's package doc for why.
	Listen string `yaml:"listen"`

	Targets []Target `yaml:"targets"`

	// Warnings holds non-fatal problems found while loading and
	// validating this config (e.g. a login: auto target with no
	// default_user). It is populated by
	// Load/LoadBytes/LoadReader and by Validate (which recomputes it
	// from scratch on every call — see Validate's doc comment) and is
	// never read from YAML or written by this package to any log or
	// output stream. The caller that logs it is authside.New (see its
	// "Who logs the warnings" doc comment); cmd/authside deliberately
	// does not log it separately, to avoid showing the same slice twice.
	Warnings []string `yaml:"-"`
}

// Target is one IdP instance: one issuer, one set of clients and users,
// one signing key set, mounted at its own path prefix.
type Target struct {
	Name string `yaml:"name"`

	// Type selects the protocol this target speaks. "oidc" is the only
	// target type in the first release.
	Type string `yaml:"type"`

	// Issuer is the string that goes in the `iss` claim and that clients
	// compare against. It may be a template over the login's claims,
	// e.g. "https://login.microsoftonline.com/${claims.tid}/v2.0".
	Issuer string `yaml:"issuer"`

	// Mount is the path prefix this target is served under. Defaults to
	// "/{name}" when empty.
	Mount string `yaml:"mount"`

	// Advertise overrides the base URLs published in discovery and
	// redirects, when they differ from Issuer (split-horizon setups).
	Advertise Advertise `yaml:"advertise"`

	// Login selects /authorize's behaviour. Defaults to LoginPicker.
	Login LoginMode `yaml:"login"`

	// Discovery selects how the discovery document behaves for a
	// templated issuer. Defaults to DiscoverShared.
	Discovery DiscoveryMode `yaml:"discovery"`

	// DefaultUser is the subject LoginAuto redirects to when no
	// authside_sub cookie is present.
	DefaultUser string `yaml:"default_user"`

	// AcceptAnyUsername lets LoginForm/LoginPicker mint a session for a
	// username not present in Users, using it directly as sub.
	AcceptAnyUsername bool `yaml:"accept_any_username"`

	// AccessToken selects the access token format. Defaults to
	// AccessTokenJWT.
	AccessToken AccessTokenType `yaml:"access_token"`

	// KeyPEM and KeyFile supply this target's RSA signing key, inline or
	// by path, so that its JWKS and every kid stay the same across
	// restarts and across processes. At most one may be set; with
	// neither, a random key is generated at startup and exists only for
	// the life of that process.
	//
	// A path is resolved against the working directory (see
	// internal/keys.Spec for why not the config file's directory).
	//
	// There is no key_seed: deriving an RSA key from a short string
	// would mean hand-rolling prime search, and the search procedure
	// would then be part of the compatibility surface. Handing over the
	// key gets the same result for none of that. The key is expected to
	// sit in plain text next to this config -- authside is a fake IdP
	// whose tokens nothing real should ever trust, so its signing key is
	// test data, not a secret.
	KeyPEM  string `yaml:"key_pem"`
	KeyFile string `yaml:"key_file"`

	// RefreshToken selects refresh token rotation behaviour. Defaults
	// to RefreshRotate.
	RefreshToken RefreshTokenMode `yaml:"refresh_token"`

	// IDTokenTTL and AccessTokenTTL may be negative, to mint tokens that
	// are already expired the moment they are issued.
	//
	// These are *Duration, not Duration: a plain Duration cannot tell
	// "the field was absent" apart from "the field was explicitly set
	// to 0", and the README requires an explicit `id_token_ttl: -5m` to
	// be meaningful (and, symmetrically, an explicit `0` to mean
	// "expires immediately" rather than "use the default"). Defaulting
	// (see defaults.go) only fills these in when nil.
	IDTokenTTL     *Duration `yaml:"id_token_ttl"`
	AccessTokenTTL *Duration `yaml:"access_token_ttl"`

	// NBFSkew shifts `nbf` into the future, to mint tokens that are not
	// valid yet. *Duration for the same unset-vs-zero reason as above.
	NBFSkew *Duration `yaml:"nbf_skew"`

	// Tamper deliberately corrupts one aspect of every token this
	// target issues, for negative testing.
	Tamper []TamperTarget `yaml:"tamper"`

	// Errors maps an endpoint name (e.g. "token", "userinfo") to a
	// canned failure: an OAuth error code such as "invalid_grant", or
	// an HTTP status such as 503.
	Errors map[string]ErrorSpec `yaml:"errors"`

	Clients []Client `yaml:"clients"`
	Users   []User   `yaml:"users"`
}

// Advertise carries the base URLs published in the discovery document and
// in redirects, split by audience, for split-horizon dev environments.
type Advertise struct {
	// Internal is used for token, jwks and userinfo — endpoints the
	// application calls directly.
	Internal string `yaml:"internal"`

	// Browser is used for authorize and end_session — endpoints the
	// browser navigates to.
	Browser string `yaml:"browser"`
}

// Client is one OAuth2/OIDC client registration on a target.
type Client struct {
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret"`
	RedirectURIs []string `yaml:"redirect_uris"`

	// RequirePKCE makes PKCE mandatory for this client rather than
	// merely verified-when-used (see README "Supported flows").
	RequirePKCE bool `yaml:"require_pkce"`
}

// User is one identity a target can issue tokens for.
type User struct {
	Sub string `yaml:"sub"`

	// Claims are arbitrary custom claims merged into the ID token and
	// userinfo response. Values may contain template placeholders such
	// as ${subject} or ${client_id}.
	Claims map[string]any `yaml:"claims"`
}

// LoginMode selects /authorize's behaviour.
type LoginMode string

const (
	// LoginAuto redirects immediately as the subject named by the
	// authside_sub cookie or DefaultUser. No implicit fallback subject.
	LoginAuto LoginMode = "auto"

	// LoginPicker shows a one-click list of configured users. This is
	// the default when Login is left empty.
	LoginPicker LoginMode = "picker"

	// LoginForm shows a username/password form.
	LoginForm LoginMode = "form"
)

// DiscoveryMode selects how the discovery document behaves, in
// particular for a templated (per-tenant) issuer.
type DiscoveryMode string

const (
	// DiscoverShared serves one document per target, with the issuer
	// template's placeholders left unresolved. The default.
	DiscoverShared DiscoveryMode = "shared"

	// DiscoverPerIssuer serves one document per rendered issuer. Valid
	// only when the issuer's host is authside itself; the set of
	// issuers is enumerated at load time from the configured users.
	DiscoverPerIssuer DiscoveryMode = "per_issuer"

	// DiscoverOff serves 404 for the discovery document.
	DiscoverOff DiscoveryMode = "off"
)

// AccessTokenType selects the access token format.
type AccessTokenType string

const (
	// AccessTokenJWT issues a signed JWT access token. The default.
	AccessTokenJWT AccessTokenType = "jwt"

	// AccessTokenOpaque issues an opaque string access token.
	AccessTokenOpaque AccessTokenType = "opaque"
)

// RefreshTokenMode selects refresh token rotation behaviour.
type RefreshTokenMode string

const (
	// RefreshRotate returns a new refresh token on every refresh and
	// retires the old one, treating reuse of a retired token as a
	// signal to revoke the whole token family. The default.
	RefreshRotate RefreshTokenMode = "rotate"

	// RefreshStatic keeps the same refresh token valid across refreshes.
	RefreshStatic RefreshTokenMode = "static"
)

// TamperTarget names one thing a target deliberately corrupts in every
// token it issues, leaving everything else valid.
type TamperTarget string

const (
	TamperAtHash    TamperTarget = "at_hash"
	TamperIss       TamperTarget = "iss"
	TamperAud       TamperTarget = "aud"
	TamperNonce     TamperTarget = "nonce"
	TamperExp       TamperTarget = "exp"
	TamperSignature TamperTarget = "signature"
)

// Duration is a time.Duration that decodes from a YAML scalar holding a Go
// duration string (as accepted by time.ParseDuration), including negative
// durations such as "-5m" — used to mint tokens that arrive already
// expired. The zero value decodes an empty/absent scalar as 0.
type Duration time.Duration

// UnmarshalYAML implements goccy/go-yaml's yaml.BytesUnmarshaler.
func (d *Duration) UnmarshalYAML(b []byte) error {
	var s string
	if err := yaml.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("config: decoding duration: %w", err)
	}
	if s == "" {
		*d = 0
		return nil
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("config: invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

// MarshalYAML implements goccy/go-yaml's yaml.BytesMarshaler-compatible
// marshaling via time.Duration's String method.
func (d Duration) MarshalYAML() ([]byte, error) {
	return []byte(time.Duration(d).String()), nil
}

// Std returns d as a standard library time.Duration.
func (d Duration) Std() time.Duration {
	return time.Duration(d)
}

// ErrorSpec is a canned failure for one endpoint: either an OAuth error
// code such as "invalid_grant", or an HTTP status such as 503. It is
// always stored as a string; a value made only of digits represents an
// HTTP status.
type ErrorSpec string

// UnmarshalYAML implements goccy/go-yaml's yaml.BytesUnmarshaler. It
// accepts both a bare YAML integer scalar (e.g. `503`) and a string
// scalar (e.g. `invalid_grant`).
func (e *ErrorSpec) UnmarshalYAML(b []byte) error {
	var n int
	if err := yaml.Unmarshal(b, &n); err == nil {
		*e = ErrorSpec(strconv.Itoa(n))
		return nil
	}
	var s string
	if err := yaml.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("config: decoding error spec: %w", err)
	}
	*e = ErrorSpec(s)
	return nil
}

// IsHTTPStatus reports whether e is a bare HTTP status code rather than an
// OAuth error code.
func (e ErrorSpec) IsHTTPStatus() bool {
	return e != "" && strings.IndexFunc(string(e), func(r rune) bool {
		return r < '0' || r > '9'
	}) == -1
}
