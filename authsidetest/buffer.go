package authsidetest

import (
	"bytes"
	"strings"
	"sync"
)

// syncBuffer is a bytes.Buffer guarded by a mutex. authside.WithRequestLog
// hands its io.Writer to handler goroutines that can run concurrently with
// each other and with a test's own call to (*OIDC).RequestLog — a bare
// *bytes.Buffer is not safe for that (its own doc comment says so
// explicitly), so every read and write here goes through mu. See
// internal/reqlog's own tests for the same pattern used to guard a test's
// receiving buffer from the opposite direction (Recorder writing while the
// test reads after the fact).
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

// Write implements io.Writer.
func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// lines returns a snapshot of the buffer's content, split into one string
// per non-empty line. It never returns the underlying buffer's own memory,
// so a caller mutating or retaining the result cannot race a concurrent
// Write.
func (b *syncBuffer) lines() []string {
	b.mu.Lock()
	snapshot := b.buf.String()
	b.mu.Unlock()

	snapshot = strings.TrimRight(snapshot, "\n")
	if snapshot == "" {
		return nil
	}
	return strings.Split(snapshot, "\n")
}
