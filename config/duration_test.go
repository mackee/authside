package config

import (
	"testing"
	"time"

	"github.com/goccy/go-yaml"
)

func TestDurationUnmarshalYAML(t *testing.T) {
	cases := []struct {
		yaml string
		want time.Duration
	}{
		{yaml: "id_token_ttl: -5m\n", want: -5 * time.Minute},
		{yaml: "id_token_ttl: 1h\n", want: time.Hour},
		{yaml: "id_token_ttl: 30s\n", want: 30 * time.Second},
		{yaml: "id_token_ttl: \"\"\n", want: 0},
	}

	for _, tc := range cases {
		t.Run(tc.yaml, func(t *testing.T) {
			var v struct {
				IDTokenTTL Duration `yaml:"id_token_ttl"`
			}
			if err := yaml.UnmarshalWithOptions([]byte(tc.yaml), &v, yaml.AllowDuplicateMapKey()); err != nil {
				t.Fatalf("Unmarshal(%q): %v", tc.yaml, err)
			}
			if v.IDTokenTTL.Std() != tc.want {
				t.Fatalf("Unmarshal(%q) = %v, want %v", tc.yaml, v.IDTokenTTL.Std(), tc.want)
			}
		})
	}
}

func TestDurationUnmarshalYAML_Invalid(t *testing.T) {
	var v struct {
		IDTokenTTL Duration `yaml:"id_token_ttl"`
	}
	err := yaml.Unmarshal([]byte("id_token_ttl: not-a-duration\n"), &v)
	if err == nil {
		t.Fatalf("expected error decoding invalid duration, got nil")
	}
}

func TestErrorSpecUnmarshalYAML(t *testing.T) {
	var v struct {
		Errors map[string]ErrorSpec `yaml:"errors"`
	}
	doc := "errors:\n  token: invalid_grant\n  userinfo: 503\n"
	if err := yaml.Unmarshal([]byte(doc), &v); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if v.Errors["token"] != "invalid_grant" {
		t.Fatalf("errors.token = %q, want invalid_grant", v.Errors["token"])
	}
	if v.Errors["userinfo"] != "503" {
		t.Fatalf("errors.userinfo = %q, want 503", v.Errors["userinfo"])
	}
	if !v.Errors["userinfo"].IsHTTPStatus() {
		t.Fatalf("errors.userinfo should report as an HTTP status")
	}
	if v.Errors["token"].IsHTTPStatus() {
		t.Fatalf("errors.token should not report as an HTTP status")
	}
}

// TestTargetsAnchorMergeKey mirrors the README's "Scenarios are
// configuration" example: a target defined with a YAML anchor, and a
// second target that merges it in and overrides one field. This must be
// decoded with yaml.AllowDuplicateMapKey() -- see the package doc comment.
func TestTargetsAnchorMergeKey(t *testing.T) {
	doc := `
targets:
  - &base
    name: oidc
    issuer: http://authside:5556/oidc
    users: [{sub: user-1}]
  - <<: *base
    name: oidc-expired
    id_token_ttl: -5m
`
	var cfg Config
	if err := yaml.UnmarshalWithOptions([]byte(doc), &cfg, yaml.AllowDuplicateMapKey()); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(cfg.Targets) != 2 {
		t.Fatalf("len(Targets) = %d, want 2", len(cfg.Targets))
	}
	base, expired := cfg.Targets[0], cfg.Targets[1]
	if expired.Name != "oidc-expired" {
		t.Fatalf("expired.Name = %q, want oidc-expired", expired.Name)
	}
	if expired.Issuer != base.Issuer {
		t.Fatalf("expired.Issuer = %q, want inherited %q", expired.Issuer, base.Issuer)
	}
	if len(expired.Users) != 1 || expired.Users[0].Sub != "user-1" {
		t.Fatalf("expired.Users = %+v, want inherited [{Sub:user-1}]", expired.Users)
	}
	if expired.IDTokenTTL.Std() != -5*time.Minute {
		t.Fatalf("expired.IDTokenTTL = %v, want -5m", expired.IDTokenTTL.Std())
	}
}
