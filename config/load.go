package config

import (
	"fmt"
	"io"
	"os"

	"github.com/goccy/go-yaml"
)

// InlineConfigEnvVar is the environment variable that may hold the config
// file's contents directly, instead of (or in addition to, see Resolve) a
// path on disk. The precedent is Soluto/oidc-server-mock's inline-env
// configs: it exists so a docker-compose "environment:" block can carry
// the whole config, with nothing to mount as a volume.
const InlineConfigEnvVar = "AUTHSIDE_CONFIG_INLINE"

// Load reads path as a YAML config file, decodes it strictly, fills in
// defaults and validates the result.
//
// Load never consults InlineConfigEnvVar; use Resolve for the "env var
// wins when set" precedence cmd/authside is expected to use.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: reading %s: %w", path, err)
	}
	cfg, err := LoadBytes(data)
	if err != nil {
		return nil, fmt.Errorf("config: loading %s: %w", path, err)
	}
	return cfg, nil
}

// LoadReader is LoadBytes for an io.Reader.
func LoadReader(r io.Reader) (*Config, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("config: reading config: %w", err)
	}
	return LoadBytes(data)
}

// LoadBytes decodes a YAML document already in memory — the contents of
// InlineConfigEnvVar, or a file read some other way — applies defaults,
// and validates the result. This is the pipeline every other loader in
// this package funnels through: decode strictly, default, validate.
func LoadBytes(data []byte) (*Config, error) {
	cfg, err := decode(data)
	if err != nil {
		return nil, err
	}
	ApplyDefaults(cfg)
	if err := Validate(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Resolve loads configuration using the precedence cmd/authside is
// expected to use: if InlineConfigEnvVar is set and non-empty, its value
// is decoded as the config document itself and path is never touched (it
// may not even exist — this is what lets a compose file carry the config
// purely in `environment:`, with no volume mount at all); otherwise path
// is read as a file via Load.
//
// This "env wins over path" precedence, rather than "path wins" or
// "merge both", is a deliberate choice: the inline env var exists
// specifically to replace the file, not to layer over it, so there is
// exactly one source of truth for a given run and no merge semantics to
// document or get wrong.
func Resolve(path string) (*Config, error) {
	if inline, ok := os.LookupEnv(InlineConfigEnvVar); ok && inline != "" {
		cfg, err := LoadBytes([]byte(inline))
		if err != nil {
			return nil, fmt.Errorf("config: loading $%s: %w", InlineConfigEnvVar, err)
		}
		return cfg, nil
	}
	return Load(path)
}

// decode parses data into a Config with strict, merge-key-aware YAML
// decoding.
//
// Both options are required together, not just AllowDuplicateMapKey:
//
//   - yaml.AllowDuplicateMapKey() — the README's target-inheritance idiom
//     (`<<: *base` plus an explicit local key of the same name, e.g. a
//     merged-in `name` overridden by a literal `name:`) is, per the YAML
//     merge-key spec, supposed to let the explicit key win. goccy/go-yaml
//     treats that shape as a duplicate-key error unless this option is
//     set. See config.go's package doc for the fuller note on this
//     (verified against goccy/go-yaml v1.19.2).
//   - yaml.DisallowUnknownField() — a typo in a config file for a *test*
//     tool must fail loudly. Verified (see config/load_test.go) that
//     combining this with AllowDuplicateMapKey still rejects a genuine
//     unknown field while accepting the merge-key-plus-override shape:
//     the two options address different things (duplicate *keys* within
//     one map vs fields absent from the Go struct) and do not conflict.
func decode(data []byte) (*Config, error) {
	var cfg Config
	err := yaml.UnmarshalWithOptions(data, &cfg, yaml.DisallowUnknownField(), yaml.AllowDuplicateMapKey())
	if err != nil {
		return nil, fmt.Errorf("config: parsing YAML: %w", err)
	}
	return &cfg, nil
}
