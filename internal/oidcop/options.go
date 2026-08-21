package oidcop

import "github.com/mackee/authside/internal/clock"

// Option configures a *Target built by New or buildTarget, beyond what a
// config.Target itself carries. The only option today is WithClock; more
// can be added the same way without breaking either function's signature,
// since both take opts as a variadic tail.
type Option func(*options)

// options is the resolved form every Option mutates. Its zero value is
// deliberately not the resolved default -- see resolveOptions, which is
// what actually applies clock.System{} when no WithClock is given -- so
// that adding a field here later does not silently ship a wrong default
// for callers who only look at this struct.
type options struct {
	clock clock.Clock
}

// resolveOptions applies every opt over the zero options, then fills any
// field an option left unset with the value New/buildTarget used before
// this file existed: clock.System{} for clock. This is what makes "no
// options passed" behave identically to the pre-Option code path.
func resolveOptions(opts []Option) options {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	if o.clock == nil {
		o.clock = clock.System{}
	}
	return o
}

// WithClock overrides the Clock a *Target (and, via New's nil-recorder
// fallback, the *reqlog.Recorder it is paired with) reads iat/exp/nbf and
// authorization-code/session/refresh-token expiry from. Its zero-value
// behaviour -- omit this option entirely -- is clock.System{}, i.e. the
// real wall clock, exactly as before this package took any Option at all.
//
// A test that wants to control "now" for a *Target built directly via
// buildTarget (see authorize_notanerror_test.go for that pattern), or for
// the whole authside.New handler tree via authside.WithClock, passes a
// *internal/clock.Test here instead.
func WithClock(c clock.Clock) Option {
	return func(o *options) {
		o.clock = c
	}
}
