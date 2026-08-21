package httpx

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/ajg/form"
	"github.com/mackee/tanukirpc"
)

// RenderHTML is implemented by response values that want to be rendered as
// an HTML document rather than encoded as JSON. The login picker and login
// form implement this.
type RenderHTML interface {
	RenderHTML(w io.Writer) error
}

// ResponseHeaderer is implemented by response values that want to contribute
// headers to the HTTP response before it is written. The codec applies
// these headers before encoding the body, so they are visible on the wire
// regardless of which encoding branch (HTML or JSON) is taken. /token uses
// this to set Cache-Control: no-store.
type ResponseHeaderer interface {
	ResponseHeader(h http.Header)
}

// NewCodec returns the tanukirpc.Codec authside installs on every router.
//
// Two pitfalls in tanukirpc v0.10.0 shape this codec:
//
//  1. codec.Encode in the upstream JSON/form codecs selects by an *exact*
//     string match on the whole Accept header. A real browser's Accept
//     header, and the common case of no Accept header at all, match
//     neither "*/*" nor "application/json" and silently fall through to a
//     200 with an empty body. So encoding here dispatches on the response
//     value's Go type and never looks at Accept.
//  2. codec.Decode on the upstream form codec exact-matches Content-Type,
//     so "application/x-www-form-urlencoded; charset=UTF-8" (very common)
//     falls through to nopCodec and silently decodes to a zero-valued
//     struct. formCodec below normalises the media type with
//     mime.ParseMediaType before decoding, and surfaces a genuine decode
//     failure as an error rather than silence.
//
// The type-dispatch codec's Decode always returns
// tanukirpc.ErrRequestNotSupportedAtThisCodec so that, composed into a
// tanukirpc.CodecList alongside NewURLParamCodec/NewQueryCodec/formCodec,
// the chain keeps CodecList's tolerance for the sentinel "not for me"
// errors (a bare custom Codec used standalone via WithCodec loses that
// tolerance and turns any non-nil Decode error into a 500).
func NewCodec() tanukirpc.Codec {
	return tanukirpc.CodecList{
		tanukirpc.NewURLParamCodec(),
		tanukirpc.NewQueryCodec(),
		newFormCodec(),
		newDispatchCodec(),
	}
}

// formCodec accepts application/x-www-form-urlencoded requests regardless
// of parameters (charset, differing case, extra whitespace), by normalising
// the media type before decoding. It decodes directly with github.com/ajg/form
// (the same library tanukirpc.NewFormCodec delegates to via go-chi/render)
// rather than delegating to tanukirpc.NewFormCodec, because that codec's
// decoder does not set IgnoreUnknownKeys: any form key with no matching
// `form:"..."` struct field is a hard decode error there. A real IdP
// ignores parameters it doesn't recognise (x/oauth2 AuthCodeOptions, scope,
// resource, audience, provider-specific extras, ...), and authside's whole
// pitch is that swapping in the real IdP changes nothing -- so failing
// where a real provider succeeds would be a bug in the direction that
// matters most. Unknown keys are therefore ignored; a value that fails to
// convert into a declared field's type is still a genuine decode error.
// It never encodes.
type formCodec struct{}

func newFormCodec() tanukirpc.Codec { return formCodec{} }

func (formCodec) Name() string { return "authside-form" }

func (formCodec) Decode(r *http.Request, v any) error {
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		return tanukirpc.ErrRequestNotSupportedAtThisCodec
	}
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return tanukirpc.ErrRequestNotSupportedAtThisCodec
	}
	if !strings.EqualFold(mediaType, "application/x-www-form-urlencoded") {
		return tanukirpc.ErrRequestNotSupportedAtThisCodec
	}

	dec := form.NewDecoder(r.Body)
	dec.IgnoreUnknownKeys(true)
	if err := dec.Decode(v); err != nil {
		if errors.Is(err, io.EOF) {
			return tanukirpc.ErrRequestContinueDecode
		}
		return &formDecodeError{err: err}
	}
	return nil
}

func (formCodec) Encode(w http.ResponseWriter, r *http.Request, v any) error {
	return tanukirpc.ErrResponseNotSupportedAtThisCodec
}

// formDecodeError is a genuine (non-unknown-key) form decode failure: a
// value that could not convert into a declared field's type, or a
// malformed body. ErrorHooker maps this to 400 invalid_request rather than
// the generic 500 branch (see hooker.go).
type formDecodeError struct {
	err error
}

func (e *formDecodeError) Error() string {
	return fmt.Sprintf("authside: form decode error: %v", e.err)
}

func (e *formDecodeError) Unwrap() error { return e.err }

// dispatchCodec encodes the response by the Go type of the value returned
// from the handler, never by the request's Accept header:
//
//   - a value implementing RenderHTML is rendered as HTML.
//   - a value implementing ResponseHeaderer has its headers applied first,
//     regardless of which branch below then runs.
//   - everything else is encoded as JSON.
//
// All headers for a given branch are set before the first byte is written.
// Decode always returns ErrRequestNotSupportedAtThisCodec; this codec never
// participates in request decoding.
type dispatchCodec struct{}

func newDispatchCodec() tanukirpc.Codec { return dispatchCodec{} }

func (dispatchCodec) Name() string { return "authside-dispatch" }

func (dispatchCodec) Decode(r *http.Request, v any) error {
	return tanukirpc.ErrRequestNotSupportedAtThisCodec
}

func (dispatchCodec) Encode(w http.ResponseWriter, r *http.Request, v any) error {
	if hc, ok := v.(ResponseHeaderer); ok {
		hc.ResponseHeader(w.Header())
	}
	if hr, ok := v.(RenderHTML); ok {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		return hr.RenderHTML(w)
	}
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(v)
}
