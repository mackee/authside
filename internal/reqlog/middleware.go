package reqlog

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"sync"
)

// Fields is the per-request accumulator a handler mutates to attach
// protocol-level fields to the record [Middleware] will emit once the
// handler returns. The middleware creates one per request and puts it in
// the request's context; a handler retrieves it with FieldsFromContext and
// calls the setter that matches what it just learned:
//
//	fields := reqlog.FieldsFromContext(r.Context())
//	fields.SetClientID(clientID)
//	fields.SetGrantType("authorization_code")
//	fields.SetPKCE("S256")
//	fields.SetSub(user.Sub)
//
// Every setter is nil-safe: calling one on a nil *Fields (the value
// FieldsFromContext returns when the request was never wrapped in
// Middleware, e.g. a handler invoked directly in a unit test) is a no-op
// rather than a panic, so a handler never needs a nil check before
// attaching fields.
//
// Fields is safe for concurrent use. In the normal case the handler runs
// synchronously between the middleware's call to next.ServeHTTP and the
// point it reads the accumulated fields back, so there is no genuine
// concurrent access; the mutex exists so that a handler which hands the
// context to a helper goroutine (e.g. to log while still handling the
// request) does not turn into a data race.
type Fields struct {
	mu        sync.Mutex
	clientID  string
	grantType string
	pkce      string
	sub       string
}

// SetClientID attaches the client_id presented by the request.
func (f *Fields) SetClientID(v string) {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.clientID = v
}

// SetGrantType attaches the token endpoint's grant_type.
func (f *Fields) SetGrantType(v string) {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.grantType = v
}

// SetPKCE attaches the PKCE code_challenge_method used by the exchanged
// authorization code (e.g. "S256").
func (f *Fields) SetPKCE(v string) {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pkce = v
}

// SetSub attaches the subject the request resolved to.
func (f *Fields) SetSub(v string) {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sub = v
}

func (f *Fields) snapshot() (clientID, grantType, pkce, sub string) {
	if f == nil {
		return "", "", "", ""
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.clientID, f.grantType, f.pkce, f.sub
}

type ctxKey struct{}

// FieldsFromContext returns the Fields accumulator Middleware attached to
// ctx, or nil if ctx did not come from a request Middleware wrapped. Every
// Fields setter is a nil-safe no-op, so callers can chain off the result
// without checking for nil first.
func FieldsFromContext(ctx context.Context) *Fields {
	f, _ := ctx.Value(ctxKey{}).(*Fields)
	return f
}

func withFields(ctx context.Context, f *Fields) context.Context {
	return context.WithValue(ctx, ctxKey{}, f)
}

// statusWriter wraps an http.ResponseWriter to capture the status code
// written to it, defaulting to http.StatusOK to match the net/http
// convention that a handler which never calls WriteHeader gets a 200.
//
// tanukirpc already wraps the ResponseWriter internally, so this wrapper
// stays minimal: it adds nothing beyond status capture. Flush and Hijack
// are implemented so that wrapping never removes a capability the
// underlying writer already had — each delegates to the wrapped writer
// when it supports the corresponding optional interface, and is a no-op
// (Flush) or returns http.ErrNotSupported (Hijack) when it does not, which
// is the same contract net/http itself documents for a ResponseWriter that
// cannot be hijacked.
type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func wrapStatusWriter(w http.ResponseWriter) *statusWriter {
	return &statusWriter{ResponseWriter: w, status: http.StatusOK}
}

func (w *statusWriter) WriteHeader(status int) {
	if !w.wrote {
		w.status = status
		w.wrote = true
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	w.wrote = true
	return w.ResponseWriter.Write(b)
}

// Flush implements http.Flusher.
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack implements http.Hijacker.
func (w *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return hj.Hijack()
}

// Middleware returns net/http middleware that emits one Record to recorder
// per request handled by the wrapped handler, capturing method, path and
// response status itself. target is attached to every record as-is (the
// authside target/mount name that owns this handler); pass whatever
// identifies the target to callers of Records/Find.
//
// The wrapped handler attaches protocol-level fields (client_id,
// grant_type, pkce, sub) via FieldsFromContext(r.Context()); see Fields.
func Middleware(recorder *Recorder, target string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Capture method/path as received, before calling next: r.WithContext
			// shallow-copies the *http.Request but shares the same *url.URL, so a
			// downstream rewrite (a router or middleware that mutates URL.Path in
			// place) must not be able to change what this log says the client sent.
			method, path := r.Method, r.URL.Path

			fields := &Fields{}
			sw := wrapStatusWriter(w)
			ctx := withFields(r.Context(), fields)

			next.ServeHTTP(sw, r.WithContext(ctx))

			clientID, grantType, pkce, sub := fields.snapshot()
			recorder.emit(Record{
				Time:      Time(recorder.clock.Now()),
				Target:    target,
				Method:    method,
				Path:      path,
				Status:    sw.status,
				ClientID:  clientID,
				GrantType: grantType,
				PKCE:      pkce,
				Sub:       sub,
			})
		})
	}
}
