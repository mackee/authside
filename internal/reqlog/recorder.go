package reqlog

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/mackee/authside/internal/clock"
)

// DefaultRetention is the number of most recent records a [Recorder] keeps
// in memory when [New] is called without [WithRetention].
//
// The two consumers of this package want different things: a sidecar that
// runs for the lifetime of a long docker-compose session must not grow an
// ever-larger slice of every request it has ever seen (that is a memory
// leak by another name), while an in-process test using library mode wants
// "the records from what I just did" available with no setup. A bounded
// ring buffer serves both: it is a fixed, small amount of memory regardless
// of how long the process runs (a few hundred KB at this size), and by
// default it just works for the common case of a test driving a handful of
// requests through one login flow. A test that genuinely needs a longer
// window can ask for it with WithRetention; a long-lived sidecar that wants
// no in-memory retention at all can ask for that too, with
// WithRetention(0). The stdout line is unconditional either way — turning
// retention off never turns off the log itself.
const DefaultRetention = 1024

// Option configures a Recorder constructed by New.
type Option func(*recorderConfig)

type recorderConfig struct {
	retention int
}

// WithRetention overrides how many of the most recently emitted records a
// Recorder keeps available to Records and Find.
//
//   - n > 0 keeps the last n records (a ring buffer); older records are
//     evicted as new ones arrive.
//   - n == 0 disables in-memory retention entirely: Records and Find always
//     return no records, while the JSON line is still written for every
//     request.
//
// Negative values are treated as 0.
func WithRetention(n int) Option {
	return func(c *recorderConfig) {
		if n < 0 {
			n = 0
		}
		c.retention = n
	}
}

// Recorder accepts one Record per request, writes it as a single JSON line
// to an io.Writer, and retains a bounded window of records in memory for
// library-mode retrieval. It is safe for concurrent use: a single mutex
// serializes both the write and the retention-buffer update, so lines
// written by concurrent requests are never interleaved or torn, and a
// Records/Find call never observes a half-updated buffer.
type Recorder struct {
	w     io.Writer
	clock clock.Clock

	mu     sync.Mutex
	retain int
	ring   []Record
	head   int
	count  int
}

// New returns a Recorder that writes one JSON line per record to w and
// timestamps records via clk. clk is normally an *internal/clock.Test in
// tests and a clock.System in production, so that Record.Time is
// deterministic and assertable in tests.
func New(w io.Writer, clk clock.Clock, opts ...Option) *Recorder {
	cfg := recorderConfig{retention: DefaultRetention}
	for _, opt := range opts {
		opt(&cfg)
	}
	r := &Recorder{
		w:      w,
		clock:  clk,
		retain: cfg.retention,
	}
	if cfg.retention > 0 {
		r.ring = make([]Record, cfg.retention)
	}
	return r
}

// NewStdout returns a Recorder that writes to os.Stdout, for the sidecar
// run mode. Tests should use New with an injected io.Writer instead.
func NewStdout(clk clock.Clock, opts ...Option) *Recorder {
	return New(os.Stdout, clk, opts...)
}

// emit writes rec as one JSON line and retains it, all under the same
// lock, so that a concurrent write can never interleave with this one and
// a concurrent Records/Find call never sees a torn update.
func (r *Recorder) emit(rec Record) {
	line, err := json.Marshal(rec)
	if err != nil {
		// Record's fields are all plain strings/ints/times, so this should
		// be unreachable; fail loudly into the log itself rather than
		// silently dropping the line or panicking a request goroutine.
		line = []byte(fmt.Sprintf(`{"error":"reqlog: marshal failed: %s"}`, jsonEscape(err.Error())))
	}
	line = append(line, '\n')

	r.mu.Lock()
	defer r.mu.Unlock()
	_, _ = r.w.Write(line)
	r.retainLocked(rec)
}

func jsonEscape(s string) string {
	b, _ := json.Marshal(s)
	// b is a quoted JSON string; strip the surrounding quotes since the
	// caller already supplies them in its format string.
	if len(b) >= 2 {
		return string(b[1 : len(b)-1])
	}
	return s
}

func (r *Recorder) retainLocked(rec Record) {
	if r.retain <= 0 {
		return
	}
	idx := (r.head + r.count) % r.retain
	if r.count < r.retain {
		r.ring[idx] = rec
		r.count++
		return
	}
	r.ring[r.head] = rec
	r.head = (r.head + 1) % r.retain
}

// Records returns a copy of every retained record, oldest first. The
// returned slice is a fresh copy: mutating it, or the Records within it,
// never affects what a later call returns.
func (r *Recorder) Records() []Record {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Record, r.count)
	for i := 0; i < r.count; i++ {
		out[i] = r.ring[(r.head+i)%r.retain]
	}
	return out
}

// Filter narrows [Recorder.Find] to matching records. Every non-empty field
// must match exactly; the zero Filter matches every record. This is
// intentionally minimal — exact-match narrowing by the fields a test
// actually asserts on, not a query language.
type Filter struct {
	Target string
	Method string
	Path   string
}

func (f Filter) matches(rec Record) bool {
	if f.Target != "" && rec.Target != f.Target {
		return false
	}
	if f.Method != "" && rec.Method != f.Method {
		return false
	}
	if f.Path != "" && rec.Path != f.Path {
		return false
	}
	return true
}

// Find returns a copy of the retained records matching f, oldest first. As
// with Records, the returned slice is a fresh copy safe to mutate.
func (r *Recorder) Find(f Filter) []Record {
	all := r.Records()
	out := make([]Record, 0, len(all))
	for _, rec := range all {
		if f.matches(rec) {
			out = append(out, rec)
		}
	}
	return out
}
