package oidcop

import (
	"fmt"
	"html/template"
	"io"

	"github.com/mackee/authside/internal/httpx"
	"github.com/mackee/authside/internal/reqlog"
	"github.com/mackee/tanukirpc"
)

// pickerTemplateSrc is login: picker's whole page: the fake-IdP banner,
// then one form per configured user. Each form is a separate <form
// method="post"> (README Part 1: "The click should be a POST ... it
// causes a state change: minting a code") carrying every authorization
// parameter as a hidden field plus which user this particular button
// picks, so that submitting it is a complete, self-sufficient POST
// /authorize.
//
// Deliberately no action attribute: per the HTML spec, a <form> with no
// action submits to the page's own URL. This page is served at
// ".../authorize" under whatever mount the target is configured with
// (README "Issuer, mount and advertise"), and this package has no idea
// what that mount actually is at the HTTP layer -- only the caller that
// mounts this handler (outside this package -- authside.go) does. A
// hard-coded action="/authorize" would resolve to the origin root in a
// real browser, missing any non-root mount entirely (exactly the README
// quick-start's mount: /oidc); letting the browser default to "submit
// here" is mount-agnostic by construction. See authorize_mount_test.go
// for the check that a non-root mount still works.
//
// Every {{.}} placed here is escaped by html/template for its context (an
// attribute value, or text content) -- a claim value containing
// "<script>" renders as inert escaped text, never executes. See
// authorize_picker_test.go's XSS case.
var pickerTemplateSrc = `<!doctype html>
<html><head><meta charset="utf-8"><title>authside -- choose a user</title>
<style>` + authsidePageStyle + `</style></head>
<body>
` + authsideFakeBannerHTML + `
<h1>authside: choose a user ({{.TargetName}})</h1>
{{if .Users}}
{{range .Users}}
<form method="post" class="authside-user">
<input type="hidden" name="response_type" value="{{$.Hidden.ResponseType}}">
<input type="hidden" name="client_id" value="{{$.Hidden.ClientID}}">
<input type="hidden" name="redirect_uri" value="{{$.Hidden.RedirectURI}}">
<input type="hidden" name="scope" value="{{$.Hidden.Scope}}">
<input type="hidden" name="state" value="{{$.Hidden.State}}">
<input type="hidden" name="nonce" value="{{$.Hidden.Nonce}}">
<input type="hidden" name="code_challenge" value="{{$.Hidden.CodeChallenge}}">
<input type="hidden" name="code_challenge_method" value="{{$.Hidden.CodeChallengeMethod}}">
<input type="hidden" name="sub" value="{{.Sub}}">
<button type="submit"><strong>{{.Sub}}</strong>{{if .Email}} &mdash; {{.Email}}{{end}}{{if .Name}} ({{.Name}}){{end}}</button>
</form>
{{end}}
{{else}}
<p>No users are configured on this target.</p>
{{end}}
</body></html>
`

var pickerTmpl = template.Must(template.New("picker").Parse(pickerTemplateSrc))

// pickerUser is one line of the picker's listing: sub plus the couple of
// claims (email, name) a human uses to tell configured users apart
// (README Part 1). Only string-typed claim values are surfaced here --
// this is a display convenience, not a general claims dump.
type pickerUser struct {
	Sub   string
	Email string
	Name  string
}

// pickerPage is GET /authorize's response body for login: picker. It
// implements httpx.RenderHTML, so authside's dispatch codec (see
// internal/httpx/codec.go) renders it as text/html regardless of the
// request's Accept header (or its total absence) -- the tanukirpc pitfall
// this package's codec exists to route around.
type pickerPage struct {
	TargetName string
	Hidden     hiddenAuthParams
	Users      []pickerUser
}

// RenderHTML implements httpx.RenderHTML.
func (p *pickerPage) RenderHTML(w io.Writer) error {
	return pickerTmpl.Execute(w, p)
}

// newPickerPage builds the picker page for target t, carrying hidden as
// every configured user's one-click login form.
func newPickerPage(t *Target, hidden hiddenAuthParams) *pickerPage {
	return &pickerPage{
		TargetName: t.name,
		Hidden:     hidden,
		Users:      pickerUsersFor(t, hidden.ClientID),
	}
}

// pickerUsersFor resolves each of t's configured users' claims (as this
// clientID would see them -- a claim template may reference
// ${client_id}) and extracts email/name for display. A user whose claims
// somehow fail to resolve here (unreachable in practice: target.go's New
// already dry-runs every user's claims against every client at
// construction time) is still listed, just without those two optional
// fields, rather than breaking the whole picker page.
func pickerUsersFor(t *Target, clientID string) []pickerUser {
	users := t.orderedUsers()
	out := make([]pickerUser, 0, len(users))
	for _, u := range users {
		var email, name string
		if claims, err := u.resolveClaims(clientID); err == nil {
			if v, ok := claims["email"].(string); ok {
				email = v
			}
			if v, ok := claims["name"].(string); ok {
				name = v
			}
		}
		out = append(out, pickerUser{Sub: u.sub, Email: email, Name: name})
	}
	return out
}

// pickerSubmitHandler implements POST /authorize for login: picker: the
// click that completes the flow. It re-validates client_id and
// redirect_uri exactly as the GET handler does (a POST body is untrusted
// input regardless of where its hidden fields came from), then mints a
// code for whichever user's form was submitted and redirects to
// redirect_uri with ?code=...&state=... -- state, nonce and
// code_challenge carried through byte-identical from the hidden fields
// that produced this POST (see completeLogin).
//
// Only registered when the target's login mode is picker (router.go);
// login: auto and login: form each get their own POST /authorize wiring
// (form: formSubmitHandler; auto: none at all).
func pickerSubmitHandler(t *Target) tanukirpc.Handler[*Target] {
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

		// The picker only ever shows buttons for t.orderedUsers(), so a
		// miss here means either a tampered POST body or (per README
		// "Login modes", accept_any_username applying to both form and
		// picker) an accept_any_username target whose caller posted a sub
		// by hand rather than clicking a rendered button -- lookupUser
		// covers both without the picker's own template needing a
		// free-text field.
		user, ok := t.lookupUser(req.Sub)
		if !ok {
			return nil, redirectError(req.RedirectURI, req.State,
				httpx.AccessDenied(fmt.Sprintf("subject %q is not a configured user on target %q; set accept_any_username: true to allow unconfigured subjects", req.Sub, t.name)))
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
