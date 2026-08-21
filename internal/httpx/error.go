package httpx

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/mackee/tanukirpc"
)

// ErrorCode is an RFC 6749 §11.4.1 / OIDC Core error code.
type ErrorCode string

// RFC 6749 §5.2 error codes, plus the OIDC-specific interaction_required
// and login_required codes (OIDC Core §3.1.2.6).
const (
	ErrInvalidRequest         ErrorCode = "invalid_request"
	ErrInvalidClient          ErrorCode = "invalid_client"
	ErrInvalidGrant           ErrorCode = "invalid_grant"
	ErrUnauthorizedClient     ErrorCode = "unauthorized_client"
	ErrUnsupportedGrantType   ErrorCode = "unsupported_grant_type"
	ErrInvalidScope           ErrorCode = "invalid_scope"
	ErrAccessDenied           ErrorCode = "access_denied"
	ErrServerError            ErrorCode = "server_error"
	ErrTemporarilyUnavailable ErrorCode = "temporarily_unavailable"
	ErrInteractionRequired    ErrorCode = "interaction_required"
	ErrLoginRequired          ErrorCode = "login_required"
)

// OIDCError is an RFC 6749 / OIDC Core protocol-level error: an error code,
// an optional human-readable description, the HTTP status it must be
// carried with, and (for invalid_client with HTTP Basic client
// authentication) a WWW-Authenticate challenge.
//
// OIDCError implements tanukirpc.ErrorWithStatus so it composes with
// tanukirpc's own error plumbing, but authside installs its own
// ErrorHooker (see hooker.go) because the upstream hooker writes
// WriteHeader before the codec sets Content-Type, dropping the
// application/json header RFC 6749 requires.
type OIDCError struct {
	Code            ErrorCode
	Description     string
	HTTPStatus      int
	WWWAuthenticate string
}

func (e *OIDCError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Description)
	}
	return string(e.Code)
}

// Status implements tanukirpc.ErrorWithStatus.
func (e *OIDCError) Status() int { return e.HTTPStatus }

// WithDescription returns a copy of e with Description set. Useful for
// attaching a request-specific description to one of the package-level
// constructors, e.g. httpx.InvalidGrant().WithDescription("code expired").
func (e *OIDCError) WithDescription(description string) *OIDCError {
	e2 := *e
	e2.Description = description
	return &e2
}

// newOIDCError builds an OIDCError with the given RFC 6749 §5.2 status.
func newOIDCError(code ErrorCode, status int) *OIDCError {
	return &OIDCError{Code: code, HTTPStatus: status}
}

// InvalidRequest builds an "invalid_request" error (400).
func InvalidRequest(description string) *OIDCError {
	return newOIDCError(ErrInvalidRequest, http.StatusBadRequest).WithDescription(description)
}

// InvalidClient builds an "invalid_client" error (401 per RFC 6749 §5.2). If
// the client attempted HTTP Basic authentication, pass true for
// usedBasicAuth so a WWW-Authenticate challenge is attached; RFC 6749
// requires this be present when the client used the Basic scheme.
func InvalidClient(description string, usedBasicAuth bool) *OIDCError {
	e := newOIDCError(ErrInvalidClient, http.StatusUnauthorized).WithDescription(description)
	if usedBasicAuth {
		e.WWWAuthenticate = `Basic realm="authside"`
	}
	return e
}

// InvalidGrant builds an "invalid_grant" error (400).
func InvalidGrant(description string) *OIDCError {
	return newOIDCError(ErrInvalidGrant, http.StatusBadRequest).WithDescription(description)
}

// UnauthorizedClient builds an "unauthorized_client" error (400).
func UnauthorizedClient(description string) *OIDCError {
	return newOIDCError(ErrUnauthorizedClient, http.StatusBadRequest).WithDescription(description)
}

// UnsupportedGrantType builds an "unsupported_grant_type" error (400).
func UnsupportedGrantType(description string) *OIDCError {
	return newOIDCError(ErrUnsupportedGrantType, http.StatusBadRequest).WithDescription(description)
}

// InvalidScope builds an "invalid_scope" error (400).
func InvalidScope(description string) *OIDCError {
	return newOIDCError(ErrInvalidScope, http.StatusBadRequest).WithDescription(description)
}

// AccessDenied builds an "access_denied" error (400 as a JSON body; more
// commonly returned via NewRedirectError to the client's redirect_uri per
// RFC 6749 §4.1.2.1).
func AccessDenied(description string) *OIDCError {
	return newOIDCError(ErrAccessDenied, http.StatusBadRequest).WithDescription(description)
}

// ServerError builds a "server_error" error (500).
func ServerError(description string) *OIDCError {
	return newOIDCError(ErrServerError, http.StatusInternalServerError).WithDescription(description)
}

// TemporarilyUnavailable builds a "temporarily_unavailable" error (503).
func TemporarilyUnavailable(description string) *OIDCError {
	return newOIDCError(ErrTemporarilyUnavailable, http.StatusServiceUnavailable).WithDescription(description)
}

// InteractionRequired builds an OIDC "interaction_required" error (400),
// typically returned via NewRedirectError.
func InteractionRequired(description string) *OIDCError {
	return newOIDCError(ErrInteractionRequired, http.StatusBadRequest).WithDescription(description)
}

// LoginRequired builds an OIDC "login_required" error (400), typically
// returned via NewRedirectError.
func LoginRequired(description string) *OIDCError {
	return newOIDCError(ErrLoginRequired, http.StatusBadRequest).WithDescription(description)
}

// errorCodesByName backs LookupErrorCode, used by the `errors:` config
// feature (README "Negative testing") to turn a config string like
// "invalid_grant" into an OIDCError with its RFC 6749 default status and no
// description.
var errorCodesByName = map[ErrorCode]func(string) *OIDCError{
	ErrInvalidRequest:         InvalidRequest,
	ErrInvalidClient:          func(d string) *OIDCError { return InvalidClient(d, false) },
	ErrInvalidGrant:           InvalidGrant,
	ErrUnauthorizedClient:     UnauthorizedClient,
	ErrUnsupportedGrantType:   UnsupportedGrantType,
	ErrInvalidScope:           InvalidScope,
	ErrAccessDenied:           AccessDenied,
	ErrServerError:            ServerError,
	ErrTemporarilyUnavailable: TemporarilyUnavailable,
	ErrInteractionRequired:    InteractionRequired,
	ErrLoginRequired:          LoginRequired,
}

// LookupErrorCode builds the OIDCError for a config-supplied error code
// (the `errors: {token: invalid_grant}` form of README "Negative testing").
// ok is false when code is not one of the known RFC 6749 / OIDC codes; the
// config-loading package is expected to treat that as a validation error.
func LookupErrorCode(code string) (oerr *OIDCError, ok bool) {
	ctor, ok := errorCodesByName[ErrorCode(code)]
	if !ok {
		return nil, false
	}
	return ctor(""), true
}

// StatusError is a bare-HTTP-status failure with no RFC 6749 JSON error
// body, for the `errors:` config's numeric form (README "Negative testing",
// e.g. `errors: {userinfo: 503}`). Unlike OIDCError, a StatusError is not
// itself an OAuth protocol error -- it models an endpoint that simply fails
// at the transport level.
type StatusError struct {
	HTTPStatus int
}

// NewStatusError builds a StatusError carrying only an HTTP status.
func NewStatusError(status int) *StatusError {
	return &StatusError{HTTPStatus: status}
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("http status %d", e.HTTPStatus)
}

// Status implements tanukirpc.ErrorWithStatus.
func (e *StatusError) Status() int { return e.HTTPStatus }

// NewRedirectError builds the tanukirpc redirect-error for returning oerr to
// the client's redirect_uri (RFC 6749 §4.1.2.1 / §4.2.2.1), e.g.
// "https://client.example/cb?error=access_denied&state=...". Any existing
// query parameters already present on redirectURI are preserved, and state
// (which may be empty) is passed through untouched. status is normally
// http.StatusFound.
func NewRedirectError(status int, redirectURI string, oerr *OIDCError, state string) (error, error) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return nil, fmt.Errorf("httpx: invalid redirect_uri %q: %w", redirectURI, err)
	}
	q := u.Query()
	q.Set("error", string(oerr.Code))
	if oerr.Description != "" {
		q.Set("error_description", oerr.Description)
	}
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	return tanukirpc.ErrorRedirectTo(status, u.String()), nil
}
