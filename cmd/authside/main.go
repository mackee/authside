// Command authside runs the authside sidecar as a standalone process.
//
// It loads configuration via the config package (config.Resolve, which
// already implements the "AUTHSIDE_CONFIG_INLINE beats --config"
// precedence), builds the handler with authside.New, and serves it with
// graceful shutdown.
//
// The listen address is exclusively this command's concern, never the
// library's (see authside.go's package doc): authside.New has no way to
// observe or influence what address the process binds to, and
// --allow-external is implemented here as a safety gate over the
// configured listen value (see resolveListenAddr).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mackee/authside"
	"github.com/mackee/authside/config"
)

// defaultPort is used for the loopback bind address when the config does
// not specify a listen address at all. It matches the port used
// throughout the README's examples.
const defaultPort = "5556"

// fakeIdPBanner is printed, verbatim and impossible to miss, on every
// startup (README "Loud about being fake"). This is plain text on
// purpose -- it is meant to be read by a human watching a terminal, not
// parsed.
const fakeIdPBanner = `================================================================================
  authside -- a FAKE identity provider, for local development and test
  environments ONLY.

  It authenticates nobody: it issues whatever token its config says to
  issue, for whoever asks. Anything that trusts it is unauthenticated,
  however real the tokens look.

  NEVER run authside in production, or on any host reachable from the
  internet.
================================================================================
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := dispatch(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "authside:", err)
		os.Exit(1)
	}
}

// dispatch routes to a subcommand or to the server.
//
// The server is the default and must stay reachable with no subcommand at
// all: the Dockerfile's CMD is ["--config", "/etc/authside/authside.yaml"]
// and the compose example passes flags directly, so anything that
// required a "serve" word would break every existing deployment. Only a
// first argument that is a bare word (no leading dash) can name a
// subcommand, and only "token" is one; a flag, or nothing, falls straight
// through to run() unchanged.
func dispatch(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) > 0 && args[0] == "token" {
		return runToken(args[1:], stdout, stderr)
	}
	return run(ctx, args, stdout, stderr)
}

// run is the whole program, minus process-level concerns (os.Args,
// os.Exit, signal wiring), so it can be unit-tested directly: pass a
// canceled context to exercise startup-then-immediate-shutdown, or a
// background context and cancel it from the test.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("authside", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "path to the authside YAML config file")
	allowExternal := fs.Bool("allow-external", false, "bind the configured listen address instead of loopback only (containers need this)")
	showVersion := fs.Bool("version", false, "print the version and exit")
	probe := fs.Bool("probe", false, "after starting, GET each target's advertise.internal discovery URL once and log whether it answered (a diagnostic; never fails startup)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// --version answers before anything else: it needs no config, and it
	// prints one bare line on stdout with no banner, so that
	// `authside --version` is usable from a script.
	if *showVersion {
		return printVersion(stdout)
	}

	fmt.Fprint(stderr, fakeIdPBanner)

	logger := slog.New(slog.NewTextHandler(stderr, nil))
	slog.SetDefault(logger)

	// Neither mechanism supplied: fail with a clear, actionable error
	// naming both.
	if *configPath == "" && !inlineConfigPresent() {
		return fmt.Errorf("no config provided: pass --config <path> or set the %s environment variable", config.InlineConfigEnvVar)
	}

	cfg, err := config.Resolve(*configPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// config.Validate returns warnings as data rather than printing them
	// (see config/config.go's doc comment on Config.Warnings): this
	// command does not print cfg.Warnings itself. authside.New (called
	// below) logs them via slog.Default(), and slog.SetDefault(logger)
	// above means that IS this command's own logger -- printing them
	// again here would just be the same slice through the same handler
	// a second time. See authside.go's "Who logs the warnings" note for
	// the full reasoning.
	addr, warning, err := resolveListenAddr(cfg.Listen, *allowExternal)
	if err != nil {
		return fmt.Errorf("listen address: %w", err)
	}
	if warning != "" {
		logger.Warn(warning)
	}

	handler, err := authside.New(cfg)
	if err != nil {
		return fmt.Errorf("building handler: %w", err)
	}

	// Confirmation that the issuer the operator configured is the issuer
	// being served -- logged next to the bind address, without implying
	// any relationship between the two (there is none; see README
	// "Issuer, mount and advertise").
	logger.Info("authside starting",
		slog.String("version", resolveVersion()),
		slog.String("bind_addr", addr),
	)
	for _, t := range cfg.Targets {
		logger.Info("target",
			slog.String("name", t.Name),
			slog.String("mount", t.Mount),
			slog.String("issuer", t.Issuer),
		)
	}

	// The reachability probe, when asked for, runs once the listener is
	// up and concurrently with serving: advertise.internal normally
	// points back at authside itself, so a probe run before the server
	// accepted anything would be guaranteed to fail. Its findings are
	// advisory only and never reach this function's error return --
	// "unreachable from authside" is a legitimate configuration (see
	// probe.go's header).
	var ready func(net.Addr)
	if *probe {
		client := probeClient()
		ready = func(net.Addr) {
			go probeTargets(ctx, logger, cfg.Targets, client)
		}
	}

	return serve(ctx, logger, addr, handler, ready)
}

// inlineConfigPresent reports whether the inline-config environment
// variable carries anything. A set-but-empty value counts as "not
// supplied", mirroring config.Resolve's own precedence rule.
func inlineConfigPresent() bool {
	return os.Getenv(config.InlineConfigEnvVar) != ""
}

// serve binds addr, serves handler on it, and blocks until ctx is
// canceled, at which point it drains connections with a bounded timeout
// and returns. ready, if non-nil, is called with the actual bound
// address once the listener is up: tests that bind to port 0 use it to
// learn which port the OS picked, and run() uses it to launch the
// --probe goroutine. It is called before Serve, so anything it does that
// dials this listener must not block -- the connection waits in the
// accept backlog until Serve picks it up moments later.
func serve(ctx context.Context, logger *slog.Logger, addr string, handler http.Handler, ready func(net.Addr)) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}

	if ready != nil {
		ready(ln.Addr())
	}

	server := &http.Server{
		Handler: handler,
		// A linter correctly flags the absence of this: with no
		// ReadHeaderTimeout, a slow or hostile client can hold a
		// connection open indefinitely while trickling in headers.
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("listening", slog.String("addr", ln.Addr().String()))
		err := server.Serve(ln)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("graceful shutdown: %w", err)
		}
		return <-errCh
	case err := <-errCh:
		return err
	}
}

// resolveListenAddr decides the address to actually bind to, and any
// warning that should accompany that decision, from the configured
// listen value and the --allow-external flag. It is a pure function so
// the safety-gate logic can be unit-tested without binding a socket.
//
// Semantics (README's warning block; "It binds to loopback unless you
// pass --allow-external, which containers need"):
//
//   - listen == "": nothing was configured at all, so the flag is moot --
//     always bind the documented default port on loopback, no warning.
//   - !allowExternal: bind to loopback only, whatever the config says.
//     If the configured host is already loopback, use it unchanged (no
//     warning -- nothing was overridden). If it is not loopback (e.g. the
//     quick start's 0.0.0.0:5556, or a bare ":5556"), keep the configured
//     port but force the host to loopback (127.0.0.1) and return a
//     warning saying so, and that --allow-external is how to bind as
//     configured. This never hard-fails: a fresh user running the
//     compose config on their host gets a working server.
//   - allowExternal: bind exactly as configured. If the resulting host is
//     not loopback, return a prominent warning that authside is now
//     reachable beyond loopback and must never be exposed to an
//     untrusted network. If it happens to be loopback anyway, no warning
//     is warranted -- nothing risky occurred.
//
// 0.0.0.0, ::, and an empty host are treated as non-loopback; 127.0.0.0/8,
// ::1 and "localhost" are treated as loopback. Both "host:port" and a
// bare ":port" are accepted. A listen value that net.SplitHostPort cannot
// parse is an error.
func resolveListenAddr(listen string, allowExternal bool) (addr string, warning string, err error) {
	if listen == "" {
		return net.JoinHostPort("127.0.0.1", defaultPort), "", nil
	}

	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", "", fmt.Errorf("invalid listen address %q: %w", listen, err)
	}

	loopback := isLoopbackHost(host)

	if allowExternal {
		if loopback {
			return listen, "", nil
		}
		return listen, fmt.Sprintf(
			"binding to %s as configured (--allow-external): authside is now reachable beyond loopback -- it must NEVER be exposed to an untrusted network",
			listen,
		), nil
	}

	if loopback {
		return listen, "", nil
	}

	forced := net.JoinHostPort("127.0.0.1", port)
	return forced, fmt.Sprintf(
		"configured listen host %q in %q is not loopback; binding to %s instead -- pass --allow-external to bind exactly as configured",
		host, listen, forced,
	), nil
}

// isLoopbackHost reports whether host (as split out of a listen address
// by net.SplitHostPort) refers to loopback only.
func isLoopbackHost(host string) bool {
	switch host {
	case "", "0.0.0.0", "::":
		return false
	case "localhost":
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
