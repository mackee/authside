package oidcop

import (
	"testing"
	"time"

	"github.com/mackee/authside/internal/clock"
)

// TestBuildTarget_WithClockReachesTarget is the unit-level half of the
// clock injection seam this package exists to open (see options.go):
// WithClock must end up as the *Target's own clock field, which is what
// authorize.go/token.go/userinfo.go actually call .Now() on for every
// iat/exp/nbf and code/session/refresh-token expiry. Asserting this here,
// directly on buildTarget, is cheaper and more targeted than driving a
// full login through New and decoding a token just to prove the plumbing
// works -- that end-to-end proof belongs to authside_options_test.go one
// level up, once per behaviour it enables rather than once per
// constructor argument.
func TestBuildTarget_WithClockReachesTarget(t *testing.T) {
	fixed := time.Date(2030, 3, 4, 5, 6, 7, 0, time.UTC)
	testClock := clock.NewTest(fixed)

	tgt := testTarget()
	target, err := buildTarget(tgt, nil, WithClock(testClock))
	if err != nil {
		t.Fatalf("buildTarget() = %v", err)
	}

	if got := target.clock.Now(); !got.Equal(fixed) {
		t.Fatalf("target.clock.Now() = %v, want %v (the injected test clock's time)", got, fixed)
	}

	// The injected clock is live, not a one-time snapshot: advancing it
	// must be visible through the same *Target without rebuilding
	// anything. This is what lets a test built on top of this seam move
	// time after a token has already been minted (authside_options_test.go
	// does exactly that).
	testClock.Advance(time.Hour)
	want := fixed.Add(time.Hour)
	if got := target.clock.Now(); !got.Equal(want) {
		t.Fatalf("after Advance, target.clock.Now() = %v, want %v", got, want)
	}
}

// TestBuildTarget_NoOptionsDefaultsToSystemClock is the regression this
// whole file exists to prevent: buildTarget/New becoming variadic
// (opts ...Option) must not change behaviour for the overwhelming
// majority of callers -- every existing call site in this package and in
// authside.go -- that pass no Option at all. Before this change,
// buildTarget always used clock.System{} for target.clock; after it,
// resolveOptions must still produce exactly that when opts is empty, so
// this test builds a target with zero options and asserts the clock is a
// clock.System, not merely "some Clock that happens to read close to
// wall time" (which a flaky time-window assertion could paper over
// without actually proving System{} was chosen).
func TestBuildTarget_NoOptionsDefaultsToSystemClock(t *testing.T) {
	tgt := testTarget()
	target, err := buildTarget(tgt, nil)
	if err != nil {
		t.Fatalf("buildTarget() = %v", err)
	}

	if _, ok := target.clock.(clock.System); !ok {
		t.Fatalf("target.clock = %T, want clock.System (the pre-Option default)", target.clock)
	}
}
