package clock_test

import (
	"sync"
	"testing"
	"time"

	"github.com/mackee/authside/internal/clock"
)

func TestSystemNow(t *testing.T) {
	var sys clock.System
	before := time.Now()
	got := sys.Now()
	after := time.Now()
	if got.Before(before) || got.After(after) {
		t.Fatalf("System.Now() = %v, want between %v and %v", got, before, after)
	}
}

func TestTestClockAdvance(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tc := clock.NewTest(start)

	tc.Advance(5 * time.Minute)

	want := start.Add(5 * time.Minute)
	if got := tc.Now(); !got.Equal(want) {
		t.Fatalf("Now() = %v, want %v", got, want)
	}
}

func TestTestClockSet(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tc := clock.NewTest(start)

	want := time.Date(2030, 6, 15, 12, 0, 0, 0, time.UTC)
	tc.Set(want)

	if got := tc.Now(); !got.Equal(want) {
		t.Fatalf("Now() = %v, want %v", got, want)
	}
}

// TestTestClockRace exercises Now() and Advance() concurrently. Run with
// -race: it must not report a data race.
func TestTestClockRace(t *testing.T) {
	tc := clock.NewTest(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	var wg sync.WaitGroup
	const n = 50

	wg.Add(2 * n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			tc.Advance(time.Second)
		}()
		go func() {
			defer wg.Done()
			_ = tc.Now()
		}()
	}
	wg.Wait()
}

var _ clock.Clock = clock.System{}
var _ clock.Clock = (*clock.Test)(nil)
