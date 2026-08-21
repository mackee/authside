package config

import "testing"

// TestValidate_IdempotentAcrossRepeatedCalls is the regression guard for
// the "config warnings logged three times on startup" defect: LoadBytes
// runs ApplyDefaults+Validate once, and authside.New deliberately runs
// ApplyDefaults+Validate again on the same already-loaded *Config (see
// authside.go's doc comment on New) so that a hand-built Config behaves
// identically to one loaded from YAML. If Validate appended to
// cfg.Warnings instead of replacing it, that second pass would double
// every warning already found by the first. This test exercises exactly
// that load-then-validate-again path and asserts the warning count (and
// content) does not change no matter how many times Validate runs.
func TestValidate_IdempotentAcrossRepeatedCalls(t *testing.T) {
	const doc = `
targets:
  - name: oidc
    type: oidc
    issuer: http://authside:5556/oidc
    login: auto
    clients:
      - client_id: app
        client_secret: s
        redirect_uris: [http://localhost:8080/cb]
    users:
      - sub: user-1
`
	cfg, err := LoadBytes([]byte(doc))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}

	// LoadBytes already ran ApplyDefaults+Validate once. This config is
	// expected to produce exactly one warning: login: auto with no
	// default_user. (It used to produce two -- key_seed was the other --
	// but key_seed no longer exists; see README "Keys".)
	first := append([]string(nil), cfg.Warnings...)
	if len(first) != 1 {
		t.Fatalf("after one load, Warnings = %v, want exactly 1 entry", first)
	}

	// Simulate authside.New's re-run of ApplyDefaults+Validate on the
	// same, already-loaded Config, any number of times.
	for i := 0; i < 3; i++ {
		ApplyDefaults(cfg)
		if err := Validate(cfg); err != nil {
			t.Fatalf("Validate (rerun %d): unexpected error: %v", i, err)
		}
		if len(cfg.Warnings) != len(first) {
			t.Fatalf("after rerun %d, Warnings = %v, want exactly %d entries (same as after first load)", i, cfg.Warnings, len(first))
		}
		for j, w := range cfg.Warnings {
			if w != first[j] {
				t.Fatalf("after rerun %d, Warnings[%d] = %q, want %q", i, j, w, first[j])
			}
		}
	}
}
