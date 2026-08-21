package oidcop

import (
	"fmt"
	"html/template"
	"io"

	"github.com/mackee/authside/internal/httpx"
	"github.com/mackee/authside/internal/reqlog"
	"github.com/mackee/tanukirpc"
)

// formTemplateSrc is login: form's page: the fake-IdP banner, an
// optional error line, and a username/password form carrying every
// authorization parameter as a hidden field (README Part 2). Username is
// sticky across a failed submission (re-rendered with its previous
// value) so a typo is easy to fix without retyping everything; password
// is deliberately never echoed back.
//
// Deliberately no action attribute on the <form> -- see
// authorize_picker.go's pickerTemplateSrc comment: an omitted action
// submits to the page's own URL, which is mount-agnostic, whereas a
// hard-coded action="/authorize" would break under any non-root mount
// (README quick-start's mount: /oidc included). See
// authorize_mount_test.go.
var formTemplateSrc = `<!doctype html>
<html><head><meta charset="utf-8"><title>authside -- log in</title>
<style>` + authsidePageStyle + `</style></head>
<body>
` + authsideFakeBannerHTML + `
<h1>authside: log in ({{.TargetName}})</h1>
{{if .Error}}<p class="authside-error"><strong>Error:</strong> {{.Error}}</p>{{end}}
<form method="post">
<input type="hidden" name="response_type" value="{{.Hidden.ResponseType}}">
<input type="hidden" name="client_id" value="{{.Hidden.ClientID}}">
<input type="hidden" name="redirect_uri" value="{{.Hidden.RedirectURI}}">
<input type="hidden" name="scope" value="{{.Hidden.Scope}}">
<input type="hidden" name="state" value="{{.Hidden.State}}">
<input type="hidden" name="nonce" value="{{.Hidden.Nonce}}">
<input type="hidden" name="code_challenge" value="{{.Hidden.CodeChallenge}}">
<input type="hidden" name="code_challenge_method" value="{{.Hidden.CodeChallengeMethod}}">
<p><label>Username <input type="text" name="username" value="{{.Username}}" autofocus></label></p>
<p><label>Password <input type="password" name="password"></label></p>
<p><em>This is a fake IdP: any password is accepted for a configured user.</em></p>
<button type="submit">Log in</button>
</form>
</body></html>
`

var formTmpl = template.Must(template.New("form").Parse(formTemplateSrc))

// formPage is /authorize's response body for login: form, both the
// initial GET and a failed POST re-render. It implements
// httpx.RenderHTML, routing around the tanukirpc Accept-header pitfall
// exactly as pickerPage does.
type formPage struct {
	TargetName string
	Hidden     hiddenAuthParams
	Username   string // sticky across a failed submission
	Error      string // empty on the initial GET
}

// RenderHTML implements httpx.RenderHTML.
func (f *formPage) RenderHTML(w io.Writer) error {
	return formTmpl.Execute(w, f)
}

// newFormPage builds the form page for target t. username and errMsg are
// both empty for the initial GET; a failed POST passes the username that
// was tried (so it need not be retyped) and a human-readable error.
func newFormPage(t *Target, hidden hiddenAuthParams, username, errMsg string) *formPage {
	return &formPage{
		TargetName: t.name,
		Hidden:     hidden,
		Username:   username,
		Error:      errMsg,
	}
}

// formSubmitHandler implements POST /authorize for login: form.
//
// Any password is accepted for a configured (or, with
// accept_any_username: true, an unconfigured) user: this is a fake IdP,
// and README "Login modes" frames login: form as existing to exercise the
// login UX and failure paths, not to verify real credentials -- there is
// no password field anywhere in config.Target or config.User for a
// submitted password to be checked against, and this pass does not
// invent one. req.Password is read into the decoded request purely so a
// real login form's shape (username + password) is preserved, and then
// deliberately never inspected.
//
// Only registered when the target's login mode is form (router.go).
func formSubmitHandler(t *Target) tanukirpc.Handler[*Target] {
	return tanukirpc.NewHandler(func(ctx tanukirpc.Context[*Target], req authorizeSubmitRequest) (any, error) {
		reqlog.FieldsFromContext(ctx).SetClientID(req.ClientID)

		client, oerr := validateClientAndRedirectURI(t, req.ClientID, req.RedirectURI)
		if oerr != nil {
			return nil, oerr
		}
		if err := authorizeConfiguredError(t, req.RedirectURI, req.State); err != nil {
			return nil, err
		}
		if req.ResponseType != "" && req.ResponseType != "code" {
			return nil, redirectError(req.RedirectURI, req.State,
				errUnsupportedResponseType(fmt.Sprintf("response_type %q is not supported; only \"code\" is", req.ResponseType)))
		}
		if client.RequirePKCE && req.CodeChallenge == "" {
			return nil, redirectError(req.RedirectURI, req.State,
				httpx.InvalidRequest(fmt.Sprintf("client %q requires PKCE (require_pkce: true); code_challenge is required", req.ClientID)))
		}

		// The failure path re-renders the form with a 200 and a visible
		// error -- never a redirect, never a 500 -- so a test (or a human)
		// can retry from exactly where they were, with every
		// authorization parameter still intact in the hidden fields.
		if req.Username == "" {
			return newFormPage(t, req.hidden(), "", "a username is required"), nil
		}

		user, ok := t.lookupUser(req.Username)
		if !ok {
			return newFormPage(t, req.hidden(), req.Username, fmt.Sprintf(
				"unknown username %q; set accept_any_username: true on target %q to allow inventing users, or add it to users:",
				req.Username, t.name,
			)), nil
		}

		return nil, completeLogin(ctx, t, loginParams{
			loginIdentity:       loginIdentity{subject: user.sub},
			clientID:            req.ClientID,
			redirectURI:         req.RedirectURI,
			scope:               req.Scope,
			state:               req.State,
			nonce:               req.Nonce,
			codeChallenge:       req.CodeChallenge,
			codeChallengeMethod: req.CodeChallengeMethod,
		})
	})
}
