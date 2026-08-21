package oidcop

import (
	"encoding/base64"
	"encoding/json"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/mackee/authside/internal/reqlog"
	"github.com/mackee/tanukirpc"
)

// endSessionRequest is GET /end_session's query string (OIDC RP-Initiated
// Logout 1.0's standard parameters).
type endSessionRequest struct {
	IDTokenHint           string `query:"id_token_hint"`
	PostLogoutRedirectURI string `query:"post_logout_redirect_uri"`
	State                 string `query:"state"`
	ClientID              string `query:"client_id"`
}

// endSessionHandler implements GET /end_session (RP-initiated logout).
//
// Every call clears the authside_sub and authside_claims cookies on
// authside's own origin (README "Login modes": between them those are
// login: auto's only identity sources), so a subsequent login starts
// fresh regardless of
// whether a redirect follows -- this is the one behaviour a logout test
// actually needs, and it happens unconditionally, before anything about
// post_logout_redirect_uri is even looked at.
//
// post_logout_redirect_uri rule: config has no separate registered-logout-
// URI list (unlike a real OIDC provider, which usually has one), so this
// package validates it the same way /authorize validates redirect_uri --
// against the identified client's registered `redirect_uris` -- rather
// than inventing a new registration surface or, worse, redirecting to
// whatever URI shows up. client_id names which client's list to check;
// when it is absent, the client is instead identified from
// id_token_hint's (unverified -- it is only ever a hint per spec, and
// signature verification buys nothing extra here since authside is
// choosing whether to trust *its own* previously-issued token) `aud`
// claim. Any of the following renders the plain "signed out" page instead
// of redirecting, rather than ever forwarding to an unvalidated URI (an
// open redirect, which this strict-about-the-protocol tool does not
// allow): no post_logout_redirect_uri given, no client identified, an
// unknown client_id, or a post_logout_redirect_uri not in that client's
// redirect_uris. When it does redirect, state is passed through
// byte-identical, exactly like /authorize's success redirect.
func endSessionHandler(t *Target) tanukirpc.Handler[*Target] {
	return tanukirpc.NewHandler(func(ctx tanukirpc.Context[*Target], req endSessionRequest) (any, error) {
		if err := t.configuredError("end_session"); err != nil {
			return nil, err
		}

		clearLoginCookies(ctx.Response())

		clientID := req.ClientID
		if clientID == "" {
			clientID = clientIDFromIDTokenHint(req.IDTokenHint)
		}
		if clientID != "" {
			reqlog.FieldsFromContext(ctx).SetClientID(clientID)
		}

		if req.PostLogoutRedirectURI != "" && clientID != "" {
			if client, ok := t.clients[clientID]; ok && redirectURIRegistered(client.RedirectURIs, req.PostLogoutRedirectURI) {
				redirectURL, err := endSessionRedirect(req.PostLogoutRedirectURI, req.State)
				if err == nil {
					http.Redirect(ctx.Response(), ctx.Request(), redirectURL, http.StatusFound)
					return nil, nil
				}
			}
		}

		return newSignedOutPage(t), nil
	})
}

// endSessionRedirect builds post_logout_redirect_uri with state appended
// untouched (omitted entirely, not emitted empty, when absent -- same
// byte-identical passthrough rule as /authorize's successRedirect).
func endSessionRedirect(postLogoutRedirectURI, state string) (string, error) {
	u, err := url.Parse(postLogoutRedirectURI)
	if err != nil {
		return "", err
	}
	if state != "" {
		q := u.Query()
		q.Set("state", state)
		u.RawQuery = q.Encode()
	}
	return u.String(), nil
}

// clearLoginCookies deletes both cookies a caller can use to say who
// logs in -- authside_sub and authside_claims -- using RFC 6265's
// convention (same name, Max-Age -1, in the past) at Path "/", so each is
// removed regardless of which path under this target's mount it was
// originally set at. A caller (browser test automation, or a Go test's
// http.Client cookie jar) that itself set them at Path "/" -- the common
// case; Playwright's context.addCookies defaults to it -- sees them gone
// after this response.
//
// authside_claims is cleared even on a target without
// accept_injected_claims: the cookie is set on authside's origin, shared
// by every target in the process, so a logout that left it behind would
// carry one target's injected identity into the next login on another.
func clearLoginCookies(w http.ResponseWriter) {
	for _, name := range []string{authsideSubCookie, authsideClaimsCookie} {
		http.SetCookie(w, &http.Cookie{
			Name:   name,
			Value:  "",
			Path:   "/",
			MaxAge: -1,
		})
	}
}

// clientIDFromIDTokenHint best-effort extracts the `aud` claim from an
// id_token_hint's payload segment, without verifying its signature.
// id_token_hint exists purely as a hint per the RP-Initiated Logout spec
// ("It is RECOMMENDED that the RP pass ... as a hint"), and every ID
// token this package has ever issued carries a single string `aud` (this
// package issues no multi-audience tokens) -- so an unverified decode is
// enough to identify which client is logging out, for the sole purpose of
// picking which redirect_uris list to validate
// post_logout_redirect_uri against. Returns "" for anything malformed,
// which simply falls through to the safe "render the signed-out page"
// default above.
func clientIDFromIDTokenHint(idTokenHint string) string {
	if idTokenHint == "" {
		return ""
	}
	parts := strings.Split(idTokenHint, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Aud string `json:"aud"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	return claims.Aud
}

// signedOutPage is GET /end_session's response body when no valid
// redirect applies. It implements httpx.RenderHTML, same as the picker
// and form pages, so it renders as text/html regardless of Accept.
type signedOutPage struct {
	TargetName string
}

// RenderHTML implements httpx.RenderHTML.
func (p *signedOutPage) RenderHTML(w io.Writer) error {
	return signedOutTmpl.Execute(w, p)
}

func newSignedOutPage(t *Target) *signedOutPage {
	return &signedOutPage{TargetName: t.name}
}

// signedOutTmplSrc reuses the same fake banner and page style as the
// picker/form pages (README "Loud about being fake"), so this page is as
// unmistakably authside-branded/fake as every other one this package
// serves.
var signedOutTmplSrc = `<!doctype html>
<html><head><meta charset="utf-8"><title>authside -- signed out</title>
<style>` + authsidePageStyle + `</style></head>
<body>
` + authsideFakeBannerHTML + `
<h1>authside: signed out ({{.TargetName}})</h1>
<p>You have been signed out of this FAKE identity provider. No valid
<code>post_logout_redirect_uri</code> was supplied for a recognised
client, so there is nowhere to send you automatically.</p>
</body></html>
`

var signedOutTmpl = template.Must(template.New("signed-out").Parse(signedOutTmplSrc))
