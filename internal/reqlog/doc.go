// Package reqlog records one JSON line per request authside handles, and
// exposes the same records as Go values for library-mode callers.
//
// authside has no runtime control API: a test that wants to assert what
// the client actually sent reads it from this log instead of calling an
// endpoint. Nothing has to be enabled, drained or read back in order, and
// the log outlives the process that wrote it. The package serves both of
// authside's run modes from the same [Recorder]:
//
//   - Sidecar/container mode: one JSON object per line on stdout (or any
//     io.Writer), for a test — or a human — to grep afterwards.
//   - Library mode: the same [Record] values, retrieved as Go values via
//     [Recorder.Records] / [Recorder.Find], since an in-process test can
//     just read them directly.
//
// A [Recorder] is wrapped around an [net/http.Handler] with [Middleware],
// which captures method, path and response status. Only the handler knows
// protocol-level details such as grant_type or pkce; it attaches them to
// the in-flight record via [FieldsFromContext].
package reqlog
