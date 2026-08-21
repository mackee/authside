package reqlog

import (
	"encoding/json"
	"time"
)

// timeLayout is the layout Time is formatted and parsed with: RFC 3339 with a
// fixed three-digit fractional-second field (millisecond precision) and an
// explicit zone offset.
//
// time.Time's default JSON encoding (RFC3339Nano) trims trailing zeros from
// the fractional part, so "12:00:00.5" and "12:00:00.50" are both possible
// outputs depending on the exact instant — which breaks plain lexicographic
// sorting of the emitted lines by time. A fixed width keeps every line
// sortable as a string, which matters because the entire point of this log
// is to be grepped and sorted after the fact by a tool (or a person) that
// has no JSON-aware timestamp parser on hand.
const timeLayout = "2006-01-02T15:04:05.000Z07:00"

// Time is time.Time with JSON marshaling pinned to timeLayout, instead of
// encoding/json's default RFC3339Nano. See timeLayout for why the fixed
// width matters.
type Time time.Time

// MarshalJSON implements json.Marshaler.
func (t Time) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Time(t).Format(timeLayout))
}

// UnmarshalJSON implements json.Unmarshaler.
func (t *Time) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	parsed, err := time.Parse(timeLayout, s)
	if err != nil {
		return err
	}
	*t = Time(parsed)
	return nil
}

// AsTime returns t as a time.Time.
func (t Time) AsTime() time.Time {
	return time.Time(t)
}

// Record is one logged request, emitted as a single JSON line and returned
// as-is by the library-mode accessors.
//
// Field order matches the README's example line
// (time, target, method, path, status, client_id, grant_type, pkce, sub):
// encoding/json emits struct fields in declaration order, so that ordering
// is preserved by construction rather than by convention.
//
// Time, Target, Method, Path and Status are always present. The remaining
// fields are protocol-dependent — a GET /jwks request has no client_id, a
// /token request without PKCE has no pkce — and are omitted from the JSON
// entirely rather than emitted empty, via `omitempty` on their string type.
// This also leaves room to add more protocol fields later (nonce, scope,
// redirect_uri, an error code, a refresh-token family id, ...) without
// breaking existing consumers: an unrecognised omitted field simply never
// appears, and a consumer that only looks at the fields it knows about is
// unaffected by new ones appearing.
type Record struct {
	Time   Time   `json:"time"`
	Target string `json:"target"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Status int    `json:"status"`

	// ClientID is the OAuth/OIDC client_id presented by the request, when
	// the protocol stage has one (e.g. /token, /revocation).
	ClientID string `json:"client_id,omitempty"`
	// GrantType is the token endpoint's grant_type, when applicable.
	GrantType string `json:"grant_type,omitempty"`
	// PKCE records the code_challenge_method used, when the authorization
	// code being exchanged had a PKCE challenge attached to it.
	PKCE string `json:"pkce,omitempty"`
	// Sub is the subject the request resolved to, when one applies (e.g.
	// after a successful /token or /userinfo call).
	Sub string `json:"sub,omitempty"`
}
