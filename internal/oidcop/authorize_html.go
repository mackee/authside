package oidcop

// hiddenAuthParams is every /authorize parameter that must survive
// unmodified across a login: picker click or a login: form submission --
// client_id, redirect_uri, state, nonce, scope, code_challenge and
// code_challenge_method. Losing nonce or code_challenge here would break
// token verification in a way that looks like a completely different bug
// (a token bug, not a login-page bug), so both the picker and the form
// carry every one of these as an explicit hidden <input>, never a subset.
//
// html/template escapes every field automatically wherever a template
// places it (an attribute value here), so a claim or parameter containing
// "<script>" renders as inert text, never executes.
type hiddenAuthParams struct {
	ResponseType        string
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
}

// authorizeSubmitRequest is POST /authorize's form body. It is shared by
// both pickerSubmitHandler and formSubmitHandler -- exactly one of which
// is ever registered for a given target, per its configured login mode
// (see router.go) -- so each handler only reads the fields relevant to
// its own mode (Sub for picker; Username/Password for form) and simply
// ignores the others.
type authorizeSubmitRequest struct {
	ResponseType        string `form:"response_type"`
	ClientID            string `form:"client_id"`
	RedirectURI         string `form:"redirect_uri"`
	Scope               string `form:"scope"`
	State               string `form:"state"`
	Nonce               string `form:"nonce"`
	CodeChallenge       string `form:"code_challenge"`
	CodeChallengeMethod string `form:"code_challenge_method"`

	// Sub is which configured user was clicked, for login: picker.
	Sub string `form:"sub"`

	// Username and Password are login: form's fields. Password is
	// deliberately never checked -- see formSubmitHandler's comment.
	Username string `form:"username"`
	Password string `form:"password"`
}

// hidden returns req's authorization parameters in the shape the picker
// and form pages carry as hidden form fields, mirroring
// authorizeRequest.hidden -- used to re-render a login: form page with an
// error after a failed submission, still carrying every original
// parameter.
func (req authorizeSubmitRequest) hidden() hiddenAuthParams {
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

// authsideFakeBannerHTML is the "unmistakably fake" banner both the
// picker and the form pages open with (README "Loud about being fake"):
// deliberately plain, unstyled-beyond-a-warning-color markup, not
// production-plausible styling, so a screenshot of this page could never
// be mistaken for a real login screen.
const authsideFakeBannerHTML = `<div style="border:4px solid #d9822b;background:#2a1a00;color:#ffd699;padding:0.75em 1em;margin-bottom:1em;font-family:monospace;">
<strong>&#9888; authside &mdash; FAKE identity provider.</strong><br>
This page exists only for local development and test environments.
It accepts whatever its config told it to accept. Never expose it to a
real user or a production network.
</div>`

// authsidePageStyle is the shared, deliberately plain page style: a
// monospace font and a dark background are enough to make every page this
// package serves visually distinct from a real IdP's login screen at a
// glance, without reaching for anything that could look production-grade.
const authsidePageStyle = `body{font-family:monospace;background:#111;color:#eee;max-width:40em;margin:2em auto;padding:0 1em;}
h1{font-size:1.1em;}
button{font-family:monospace;padding:0.4em 0.8em;cursor:pointer;}
input[type=text],input[type=password]{font-family:monospace;padding:0.3em;}
.authside-user{border:1px solid #444;padding:0.5em 0.8em;margin:0.5em 0;}
.authside-error{color:#ff8080;border:1px solid #ff8080;padding:0.5em 0.8em;margin:0.5em 0;}`
