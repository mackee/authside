package httpx

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/mackee/tanukirpc"
)

// errorResponseBody is the RFC 6749 §5.2 JSON error shape:
// {"error":"...","error_description":"..."}. error_description is omitted
// entirely when empty.
type errorResponseBody struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// ErrorHooker is authside's tanukirpc.ErrorHooker. It exists because
// tanukirpc's own hookers (errorHooker, errorBodyHooker) call
// w.WriteHeader(status) before the codec sets Content-Type, which net/http
// then commits, so RFC 6749's required application/json is dropped from
// every error response. This hooker writes headers, then status, then
// body, in that order -- modeled on codec/inertiajs/inertiajs.go's
// writePageObject (lines 270-300).
type ErrorHooker struct{}

// NewErrorHooker returns authside's ErrorHooker. Install it with
// tanukirpc.WithErrorHooker.
func NewErrorHooker() *ErrorHooker { return &ErrorHooker{} }

// OnError implements tanukirpc.ErrorHooker.
func (h *ErrorHooker) OnError(w http.ResponseWriter, req *http.Request, logger *slog.Logger, codec tanukirpc.Codec, err error) {
	// Redirect-style errors: tanukirpc.ErrorRedirectTo. http.Redirect sets
	// Location before it calls WriteHeader internally, so this path is safe
	// as-is; the codec is never consulted for the body.
	if red, ok := errors.AsType[tanukirpc.ErrorWithRedirect](err); ok {
		http.Redirect(w, req, red.Redirect(), red.Status())
		return
	}

	// authside's own OIDC protocol error: RFC 6749 JSON body, correct
	// status, and (for invalid_client via HTTP Basic) a WWW-Authenticate
	// challenge.
	if oerr, ok := errors.AsType[*OIDCError](err); ok {
		writeOIDCErrorBody(w, oerr)
		return
	}

	// A bare-HTTP-status failure from the `errors:` config feature: no
	// RFC 6749 JSON shape, just the configured status.
	if serr, ok := errors.AsType[*StatusError](err); ok {
		w.WriteHeader(serr.Status())
		return
	}

	// A malformed request body is the client's fault, not ours: RFC 6749
	// §5.2 puts this at 400 invalid_request, not 500. A 500 would tell the
	// client "our fault, retry later" when the truth is "your request was
	// malformed, fix it" -- and a real IdP answers this the same way, which
	// matters given authside's whole pitch is that swapping in the real IdP
	// changes nothing.
	//
	// *formDecodeError is what authside's own formCodec actually produces
	// for a genuine (non-unknown-key) decode failure. *tanukirpc.ErrCodecDecode
	// is tanukirpc's own decode-error type (codec.go); authside's codec list
	// does not use tanukirpc.NewFormCodec/NewJSONCodec so nothing in this
	// package currently produces one, but it is checked defensively in case
	// a future codec addition ever routes decode errors through it directly.
	//
	// The underlying decoder error text is deliberately not surfaced in
	// error_description -- it can contain field names or values from the
	// request and isn't a stable, documented API -- but it is still logged
	// at the same level as the generic 500 branch below, so operators can
	// debug it.
	if isRequestDecodeError(err) {
		if logger != nil {
			logger.ErrorContext(req.Context(), "occurred internal server error", slog.Any("error", err))
		}
		writeOIDCErrorBody(w, InvalidRequest(""))
		return
	}

	// Anything else is an unexpected internal error. Log the real error for
	// operators but never leak it into the response body; the client only
	// ever sees a generic server_error.
	if logger != nil {
		logger.ErrorContext(req.Context(), "occurred internal server error", slog.Any("error", err))
	}
	writeOIDCErrorBody(w, ServerError(""))
}

// isRequestDecodeError reports whether err is a request-body decode
// failure (as opposed to some other unexpected internal error).
func isRequestDecodeError(err error) bool {
	if _, ok := errors.AsType[*formDecodeError](err); ok {
		return true
	}
	if _, ok := errors.AsType[*tanukirpc.ErrCodecDecode](err); ok {
		return true
	}
	return false
}

// writeOIDCErrorBody writes headers, then the status, then the JSON body,
// in that order, so Content-Type (and, when present, WWW-Authenticate) are
// committed to the response before WriteHeader locks the header map.
func writeOIDCErrorBody(w http.ResponseWriter, e *OIDCError) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if e.WWWAuthenticate != "" {
		w.Header().Set("WWW-Authenticate", e.WWWAuthenticate)
	}
	w.WriteHeader(e.HTTPStatus)
	body := errorResponseBody{Error: string(e.Code), ErrorDescription: e.Description}
	_ = json.NewEncoder(w).Encode(body)
}
