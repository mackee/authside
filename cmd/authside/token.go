package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/mackee/authside/config"
	"github.com/mackee/authside/internal/oidcop"
)

// tokenOutput is what `authside token` prints on stdout: one JSON object,
// so the command composes with jq and shell substitution (README
// "Minting a token directly").
//
// JWKS is present only with --jwks. It is a *json.RawMessage rather than
// a value so that omitempty actually elides it -- the default output
// stays exactly the two tokens and their lifetime.
type tokenOutput struct {
	IDToken     string           `json:"id_token"`
	AccessToken string           `json:"access_token"`
	ExpiresIn   int64            `json:"expires_in"`
	JWKS        *json.RawMessage `json:"jwks,omitempty"`
}

// keysAreEphemeralNote is printed to stderr when the target being minted
// for supplies no signing key of its own. stdout stays pure JSON, so this
// cannot corrupt a pipeline -- and it is worth printing because the
// failure it warns about is otherwise silent: the tokens look perfectly
// well-formed right up until a verifier rejects them.
//
// A target WITH key_pem/key_file gets no note, because there would be
// nothing true to say: the same key signs in every process, so these
// tokens verify against a running authside on the same config. That is
// the whole reason to configure one.
const keysAreEphemeralNote = `note: this target configures no signing key, so one was generated for this
      invocation only -- these tokens will NOT verify against a running
      authside's JWKS. Pass --jwks to print the key set they DO verify
      against, or set key_file/key_pem on the target to share one.`

// runToken implements the `authside token` subcommand: mint one ID token
// and one access token for a configured user, with no browser, no client
// and no server involved.
//
// It is dispatched from run() on the bare argument "token" (see run), and
// deliberately shares nothing with the serving path beyond config
// loading: no listener, no banner, and no request log. The minted tokens
// on stdout are the whole output -- there is no client here whose
// behaviour a request log could record.
func runToken(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("authside token", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "path to the authside YAML config file")
	targetName := fs.String("target", "", "name of the target to mint for (required when the config has more than one)")
	clientID := fs.String("client", "", "client_id the tokens are addressed to (required)")
	user := fs.String("user", "", "sub of the configured user to mint for (required)")
	scope := fs.String("scope", "openid", "scope to stamp on the access token")
	withJWKS := fs.Bool("jwks", false, "include the JWKS these tokens verify against in the output")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *configPath == "" && !inlineConfigPresent() {
		return fmt.Errorf("no config provided: pass --config <path> or set the %s environment variable", config.InlineConfigEnvVar)
	}
	if *clientID == "" {
		return fmt.Errorf("--client is required")
	}
	if *user == "" {
		return fmt.Errorf("--user is required")
	}

	cfg, err := config.Resolve(*configPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	target, err := pickTarget(cfg.Targets, *targetName)
	if err != nil {
		return err
	}

	// Warnings and the key note both go to stderr, and the logger is
	// pointed there too: stdout carries the JSON and nothing else, so
	// `authside token ... | jq` works even when the config warns.
	logger := slog.New(slog.NewTextHandler(stderr, nil))
	for _, w := range cfg.Warnings {
		logger.Warn(w)
	}

	minted, err := oidcop.Mint(target, logger, oidcop.MintParams{
		ClientID: *clientID,
		Subject:  *user,
		Scope:    *scope,
	})
	if err != nil {
		return err
	}

	out := tokenOutput{
		IDToken:     minted.IDToken,
		AccessToken: minted.AccessToken,
		ExpiresIn:   minted.ExpiresIn,
	}
	if *withJWKS {
		out.JWKS = &minted.JWKS
	}

	if target.KeyPEM == "" && target.KeyFile == "" {
		fmt.Fprintln(stderr, keysAreEphemeralNote)
	}

	// json.Encoder writes one compact line plus a newline, which is
	// exactly the shape README documents and what a pipeline wants.
	return json.NewEncoder(stdout).Encode(out)
}

// pickTarget resolves --target against the configured targets. A config
// with exactly one target needs no --target at all (the overwhelmingly
// common case); anything else must name one, and naming one that does not
// exist lists what does rather than just failing.
func pickTarget(targets []config.Target, name string) (*config.Target, error) {
	if name == "" {
		if len(targets) == 1 {
			return &targets[0], nil
		}
		return nil, fmt.Errorf("--target is required: the config has %d targets (%s)", len(targets), targetNames(targets))
	}
	for i := range targets {
		if targets[i].Name == name {
			return &targets[i], nil
		}
	}
	return nil, fmt.Errorf("no target named %q in the config (have: %s)", name, targetNames(targets))
}

func targetNames(targets []config.Target) string {
	if len(targets) == 0 {
		return "none"
	}
	names := make([]string, 0, len(targets))
	for _, t := range targets {
		names = append(names, t.Name)
	}
	return strings.Join(names, ", ")
}
