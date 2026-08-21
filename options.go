package authside

import (
	"io"
	"log/slog"

	"github.com/mackee/authside/internal/clock"
)

// Clock is internal/clock.Clock, re-exported so a caller outside this
// module can name the type in its own signatures (e.g. to write a helper
// that takes a Clock and calls WithClock with it) despite internal/clock
// itself being unimportable from outside github.com/mackee/authside.
// Clock is an interface -- Now() time.Time -- so an outside caller can
// still satisfy it with any concrete type of its own; only the name
// "internal/clock.Clock" is unavailable to it, not the ability to
// implement or hold one. See WithClock's doc comment for the same point
// from the option's side.
type Clock = clock.Clock

// Option configures a handler built by New, beyond what a *Config itself
// carries. See WithClock, WithLogger and WithRequestLog.
type Option func(*options)

// options is the resolved form every Option mutates. New itself decides
// the zero-Option defaults (see New's construction of o below); this
// struct only holds what an Option can override.
type options struct {
	clock      Clock
	logger     *slog.Logger
	requestLog io.Writer
}

// WithClock overrides the Clock every target New builds reads
// iat/exp/nbf and authorization-code/session/refresh-token expiry from,
// and that the request-log Recorder (see WithRequestLog) timestamps
// records with. Omitting this option leaves both on clock.System{}, the
// real wall clock -- identical to New's behaviour before this package
// took any Option at all.
//
// An in-process Go test is the reason this exists: it can pass an
// *internal/clock.Test (via the Clock alias above) to pin "now" to a
// fixed instant, mint a token, and later call Advance to move time
// forward and assert a client-side verifier now rejects that same token
// as expired -- all without sleeping or racing the real clock.
func WithClock(c Clock) Option {
	return func(o *options) {
		o.clock = c
	}
}

// WithLogger overrides the *slog.Logger New logs cfg.Warnings through
// (see New's "Who logs the warnings" doc comment). Omitting this option
// leaves New resolving slog.Default() at call time, exactly as before
// this package took any Option: cmd/authside's slog.SetDefault(logger)
// call before it ever touches config still means slog.Default() here is
// cmd/authside's own logger for that entry point, and a library caller
// that never touches slog itself still gets the same handler
// slog.Default() always returns. WithLogger exists for a caller -- a Go
// test being the main one -- that wants config warnings routed
// somewhere it can assert on (e.g. a slog.Handler backed by a buffer)
// instead of wherever the process-wide default happens to point.
func WithLogger(l *slog.Logger) Option {
	return func(o *options) {
		o.logger = l
	}
}

// WithRequestLog overrides where the request log's JSON lines are
// written (README "Request log"). Omitting this option leaves it on
// os.Stdout, matching reqlog.NewStdout -- New's behaviour before this
// package took any Option.
//
// Every record's "time" field comes from the same Clock the targets
// themselves use (WithClock, or clock.System{} if that is also
// omitted) -- see New's construction of the recorder for why that
// coupling is deliberate: if the test clock moved a token's expiry but
// the request log kept stamping records with the wall clock, any
// assertion correlating a log line with a token's iat/exp would drift
// between the two clocks for no reason a caller could see.
func WithRequestLog(w io.Writer) Option {
	return func(o *options) {
		o.requestLog = w
	}
}
