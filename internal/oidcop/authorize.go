package oidcop

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/mackee/authside/config"
	"github.com/mackee/authside/internal/httpx"
	"github.com/mackee/authside/internal/reqlog"
	"github.com/mackee/tanukirpc"
)

// authsideSubCookie is the cookie login: auto reads to decide who is
// logging in, on authside's own origin (README "Login modes"). authside
// never sets this cookie itself: it is login: auto's own input, set by a
// caller before starting the flow (a browser test via its automation
// tool's cookie API, or a Go test via its http.Client's cookie jar).
// login: picker and login: form choose a subject a different way -- a
// click or a form submission, both of which are visible in the test's own
// trace -- and never touch this cookie.
const authsideSubCookie = "authside_sub"

// authorizeRequest is GET /authorize's query string.
type authorizeRequest struct {
	ResponseType        string `query:"response_type"`
	ClientID            string `query:"client_id"`
	RedirectURI         string `query:"redirect_uri"`
	Scope               string `query:"scope"`
	State               string `query:"state"`
	Nonce               string `query:"nonce"`
	CodeChallenge       string `query:"code_challenge"`
	CodeChallengeMethod string `query:"code_challenge_method"`
}

// hidden returns req's authorization parameters in the shape the picker
// and form pages carry as hidden form fields across a click/submit, so
// every one of them -- state, nonce, code_challenge included -- survives
// byte-identical (README "Login modes").
func (req authorizeRequest) hidden() hiddenAuthParams {
	return hiddenAuthParams{
		ResponseType:        req.ResponseType,
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		Scope:               req.Scope,
		State:               req.State,
		Nonce:               req.Nonce,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
	}
}

// authorizeHandler implements GET /authorize for all three login modes.
// auto redirects immediately; picker and form render an HTML page instead
// of redirecting -- the actual login (a click or a form submission)
// happens at POST /authorize, handled by pickerSubmitHandler /
// formSubmitHandler (see router.go, which registers only the one of those
// two matching the target's configured login mode).
func authorizeHandler(t *Target) tanukirpc.Handler[*Target] {
	return tanukirpc.NewHandler(func(ctx tanukirpc.Context[*Target], req authorizeRequest) (any, error) {
		reqlog.FieldsFromContext(ctx).SetClientID(req.ClientID)

		client, oerr := validateClientAndRedirectURI(t, req.ClientID, req.RedirectURI)
		if oerr != nil {
			return nil, oerr
		}

		// `errors: {authorize: ...}` (README "Negative testing"): only
		// reachable once client_id/redirect_uri are known good, per RFC
		// 6749 §4.1.2.1 -- see authorizeConfiguredError.
		if err := authorizeConfiguredError(t, req.RedirectURI, req.State); err != nil {
			return nil, err
		}

		if req.ResponseType != "code" {
			return nil, redirectError(req.RedirectURI, req.State,
				errUnsupportedResponseType(fmt.Sprintf("response_type %q is not supported; only \"code\" is", req.ResponseType)))
		}

		if client.RequirePKCE && req.CodeChallenge == "" {
			return nil, redirectError(req.RedirectURI, req.State,
				httpx.InvalidRequest(fmt.Sprintf("client %q requires PKCE (require_pkce: true); code_challenge is required", req.ClientID)))
		}

		switch t.login {
		case config.LoginPicker:
			return newPickerPage(t, req.hidden()), nil
		case config.LoginForm:
			return newFormPage(t, req.hidden(), "", ""), nil
		default: // config.LoginAuto
			subject, subjErr := subjectForAuto(ctx.Request(), t)
			if subjErr != nil {
				return nil, redirectError(req.RedirectURI, req.State, subjErr)
			}
			user, ok := t.lookupUser(subject)
			if !ok {
				return nil, redirectError(req.RedirectURI, req.State,
					httpx.AccessDenied(fmt.Sprintf("subject %q is not a configured user on target %q; set accept_any_username: true to allow unconfigured subjects", subject, t.name)))
			}
			return nil, completeLogin(ctx, t, loginParams{
				clientID:            req.ClientID,
				redirectURI:         req.RedirectURI,
				subject:             user.sub,
				scope:               req.Scope,
				state:               req.State,
				nonce:               req.Nonce,
				codeChallenge:       req.CodeChallenge,
				codeChallengeMethod: req.CodeChallengeMethod,
			})
		}
	})
}

// validateClientAndRedirectURI implements RFC 6749 §4.1.2.1: an invalid
// client_id or redirect_uri must NOT be redirected to the (unverified)
// redirect_uri -- it is rendered directly, as a plain httpx.OIDCError.
// Every other /authorize error, once client and redirect_uri are known
// good, goes back to the client via redirectError instead.
func validateClientAndRedirectURI(t *Target, clientID, redirectURI string) (config.Client, *httpx.OIDCError) {
	client, ok := t.clients[clientID]
	if !ok {
		return config.Client{}, httpx.InvalidRequest(fmt.Sprintf("authorize: unknown client_id %q", clientID))
	}
	if !redirectURIRegistered(client.RedirectURIs, redirectURI) {
		return config.Client{}, httpx.InvalidRequest(fmt.Sprintf("authorize: redirect_uri %q is not registered for client %q", redirectURI, clientID))
	}
	return client, nil
}

// redirectURIRegistered reports whether uri exactly string-matches one of
// registered (README "Strict about the protocol": exact match is
// deliberate strictness, no normalisation).
func redirectURIRegistered(registered []string, uri string) bool {
	for _, r := range registered {
		if r == uri {
			return true
		}
	}
	return false
}

// subjectForAuto resolves the subject login: auto redirects as: the
// authside_sub cookie on authside's own origin, else the target's
// default_user. auto deliberately has no implicit fallback subject
// (README "Login modes") -- neither present is an error naming exactly
// how to fix it.
func subjectForAuto(req *http.Request, t *Target) (string, *httpx.OIDCError) {
	if c, err := req.Cookie(authsideSubCookie); err == nil && c.Value != "" {
		return c.Value, nil
	}
	if t.defaultUser != "" {
		return t.defaultUser, nil
	}
	return "", httpx.LoginRequired(fmt.Sprintf(
		"login: auto has no subject to log in as: set the %q cookie on authside's own origin before starting the flow, or configure default_user on target %q",
		authsideSubCookie, t.name,
	))
}

// redirectError builds the tanukirpc redirect-error carrying oerr back to
// redirectURI as ?error=...&error_description=...&state=..., with state
// passed through byte-identical (README: never re-encode or normalise
// it -- httpx.NewRedirectError already honours that by using state
// verbatim as a url.Values entry).
func redirectError(redirectURI, state string, oerr *httpx.OIDCError) error {
	err, buildErr := httpx.NewRedirectError(http.StatusFound, redirectURI, oerr, state)
	if buildErr != nil {
		return httpx.ServerError(buildErr.Error())
	}
	return err
}

// successRedirect builds redirectURI + "?code=...&state=..." (state
// omitted entirely, not emitted empty, when the original request had
// none -- byte-identical passthrough, not a synthesized default).
func successRedirect(redirectURI, code, state string) (string, error) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return "", fmt.Errorf("oidcop: invalid redirect_uri %q: %w", redirectURI, err)
	}
	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// loginParams is everything completeLogin needs to mint an authorization
// code and build the success redirect, gathered from whichever login mode
// just decided who is logging in (auto's cookie/default_user, picker's
// click, or form's submission).
type loginParams struct {
	clientID            string
	redirectURI         string
	subject             string
	scope               string
	state               string
	nonce               string
	codeChallenge       string
	codeChallengeMethod string
}

// completeLogin is the single success path shared by every login mode:
// mint a fresh authorization code for subject and send the browser back
// to redirect_uri as ?code=...&state=... (state passed through
// byte-identical).
//
// This writes the 302 directly on ctx.Response() and returns a nil error,
// rather than returning tanukirpc.ErrorRedirectTo(...) as an "error" for
// tanukirpc's ErrorHooker to redirect on this handler's behalf. That
// alternative works on the wire (the ErrorHooker special-cases
// ErrorWithRedirect and calls http.Redirect directly, producing the
// identical bytes), but it means every successful login travels through
// the handler's *error* path -- which is what makes tanukirpc's own
// accesslog report a successful /authorize as `error=true` (README
// "Request log" is explicit that a successful login must not be recorded
// as an error). Writing the redirect here instead keeps success genuinely
// on the success path: handler.go only calls the codec (and, on failure,
// the ErrorHooker) when `ww.Status() == 0`, i.e. when the handler has not
// already written a status -- http.Redirect does that via WriteHeader, so
// returning (nil, nil) afterwards skips both. Error redirects
// (?error=...&state=...) keep using redirectError and
// tanukirpc.ErrorRedirectTo unchanged: those are genuinely errors and
// should keep being reported as such.
func completeLogin(ctx tanukirpc.Context[*Target], t *Target, p loginParams) error {
	code, err := t.codes.issue(t.clock.Now(), authCode{
		clientID:            p.clientID,
		redirectURI:         p.redirectURI,
		subject:             p.subject,
		scope:               p.scope,
		nonce:               p.nonce,
		codeChallenge:       p.codeChallenge,
		codeChallengeMethod: p.codeChallengeMethod,
	})
	if err != nil {
		return httpx.ServerError(fmt.Sprintf("authorize: issuing code: %v", err))
	}

	redirectURL, err := successRedirect(p.redirectURI, code, p.state)
	if err != nil {
		return httpx.ServerError(err.Error())
	}

	fields := reqlog.FieldsFromContext(ctx)
	fields.SetClientID(p.clientID)
	fields.SetSub(p.subject)

	http.Redirect(ctx.Response(), ctx.Request(), redirectURL, http.StatusFound)
	return nil
}
