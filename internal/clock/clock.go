package clock

import (
	"sync"
	"time"
)

// Clock is the time seam authside uses in place of calling time.Now
// directly. Every iat/exp/nbf claim, authorization-code expiry and
// refresh-token expiry goes through Clock.Now, so that a test can control
// what "now" means for the process it is driving.
//
// The interface exposes only Now. Advance and Set — the mutating
// operations a test needs — deliberately live on the concrete test
// implementation (see Test), not on this interface. The config-only,
// static design of the served process means the served process itself
// never mutates time: every TTL and skew that matters ("a token that
// arrives already expired") is expressed as configuration resolved once
// against Clock.Now, not as a clock that moves while the process runs.
// Only in-process tests, which hold a concrete *Test and can call
// Advance/Set directly, ever change what Now returns.
type Clock interface {
	// Now returns the current time.
	Now() time.Time
}

// System is the zero-config default Clock, backed by time.Now. Its zero
// value is ready to use.
type System struct{}

// Now returns time.Now().
func (System) Now() time.Time {
	return time.Now()
}

var _ Clock = System{}

// Test is a Clock whose "now" is controlled by the test that owns it,
// rather than by wall-clock time. It is safe for concurrent use: Now may
// be called from a handler goroutine while a test calls Advance or Set
// from another.
//
// The zero value is not usable; construct one with NewTest.
type Test struct {
	mu  sync.Mutex
	now time.Time
}

// NewTest returns a Test clock whose Now() starts at t.
func NewTest(t time.Time) *Test {
	return &Test{now: t}
}

// Now returns the clock's current time.
func (c *Test) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the clock's current time forward (or backward, for a
// negative d) by d.
func (c *Test) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// Set pins the clock's current time to t.
func (c *Test) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

var _ Clock = (*Test)(nil)
