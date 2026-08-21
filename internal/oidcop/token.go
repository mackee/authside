package oidcop

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mackee/authside/config"
	"github.com/mackee/authside/internal/httpx"
	"github.com/mackee/authside/internal/reqlog"
	"github.com/mackee/authside/internal/tmpl"
	"github.com/mackee/tanukirpc"
)

// tokenRequest is POST /token's form body: every field either grant type
// this package supports may send.
type tokenRequest struct {
	GrantType    string `form:"grant_type"`
	Code         string `form:"code"`
	RedirectURI  string `form:"redirect_uri"`
	CodeVerifier string `form:"code_verifier"`
	ClientID     string `form:"client_id"`
	ClientSecret string `form:"client_secret"`
	Scope        string `form:"scope"`
	RefreshToken string `form:"refresh_token"`
}

// tokenResponse is POST /token's success body.
//
// RefreshToken is always populated -- see issueFromCode's comment on why
// this package does not gate refresh token issuance on scope=offline_access
// -- but is still `omitempty` rather than a hard requirement of the type,
// since a hand-built response (there is none today, but nothing here
// should assume otherwise) with no refresh token is still a valid OAuth
// token response. x/oauth2's Token.RefreshToken reads this field
// additively: a client that never asked about refresh tokens is
// unaffected by its appearance.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// ResponseHeader implements httpx.ResponseHeaderer: RFC 6749 §5.1 requires
// Cache-Control: no-store on every token response.
func (tokenResponse) ResponseHeader(h http.Header) {
	h.Set("Cache-Control", "no-store")
}

// tokenHandler implements POST /token: authorization_code and
// refresh_token (README "Supported flows" / "Refresh tokens").
func tokenHandler(t *Target) tanukirpc.Handler[*Target] {
	return tanukirpc.NewHandler(func(ctx tanukirpc.Context[*Target], req tokenRequest) (*tokenResponse, error) {
		reqlog.FieldsFromContext(ctx).SetGrantType(req.GrantType)

		// `errors: {token: ...}` (README "Negative testing"): checked
		// before anything else -- including client authentication -- so
		// the target fails here deterministically, with no dependence on
		// whether the request would otherwise have been valid.
		if err := t.configuredError("token"); err != nil {
			return nil, err
		}

		clientID, cerr := authenticateClient(t, ctx.Request(), req)
		if cerr != nil {
			return nil, cerr
		}
		reqlog.FieldsFromContext(ctx).SetClientID(clientID)

		switch req.GrantType {
		case "authorization_code":
			return issueFromCode(ctx, t, clientID, req)
		case "refresh_token":
			return issueFromRefresh(ctx, t, clientID, req)
		case "":
			return nil, httpx.InvalidRequest("grant_type is required")
		default:
			return nil, httpx.UnsupportedGrantType(fmt.Sprintf("grant_type %q is not supported", req.GrantType))
		}
	})
}

// authenticateClient implements client_secret_basic and client_secret_post
// (README "Supported flows"). client_secret_basic is checked first
// whenever an Authorization header is present, since that is what
// x/oauth2 always tries first; a client sending no Authorization header
// falls back to the body's client_id/client_secret.
//
// Crucially, this runs -- and can fail -- entirely before anything in
// t.codes is touched, so a rejected client_secret_basic attempt never
// consumes the authorization code, leaving it available for x/oauth2's
// automatic client_secret_post retry with the very same code.
func authenticateClient(t *Target, req *http.Request, form tokenRequest) (clientID string, oerr *httpx.OIDCError) {
	clientID, secret, usedBasic, err := extractClientCredentials(req, form)
	if err != nil {
		return "", httpx.InvalidClient(err.Error(), usedBasic)
	}
	if clientID == "" {
		return "", httpx.InvalidClient("client_id is required (via HTTP Basic auth or the client_id form field)", usedBasic)
	}
	client, ok := t.clients[clientID]
	if !ok {
		return "", httpx.InvalidClient(fmt.Sprintf("unknown client_id %q", clientID), usedBasic)
	}
	if client.ClientSecret != secret {
		return "", httpx.InvalidClient("invalid client credentials", usedBasic)
	}
	return clientID, nil
}

// extractClientCredentials pulls (client_id, client_secret) out of either
// the Authorization: Basic header or the form body, and reports which
// method was used (for the WWW-Authenticate challenge RFC 6749 requires
// when a Basic attempt is rejected).
func extractClientCredentials(req *http.Request, form tokenRequest) (clientID, secret string, usedBasic bool, err error) {
	if auth := req.Header.Get("Authorization"); auth != "" {
		rest, ok := strings.CutPrefix(auth, "Basic ")
		if !ok {
			return "", "", true, fmt.Errorf("unsupported Authorization scheme; only Basic is accepted")
		}
		decoded, decErr := base64.StdEncoding.DecodeString(rest)
		if decErr != nil {
			return "", "", true, fmt.Errorf("malformed Basic credentials: %w", decErr)
		}
		id, pw, found := strings.Cut(string(decoded), ":")
		if !found {
			return "", "", true, fmt.Errorf("malformed Basic credentials: missing \":\"")
		}
		// x/oauth2 encodes each half with url.QueryEscape before base64;
		// unescape symmetrically.
		if unescaped, uerr := url.QueryUnescape(id); uerr == nil {
			id = unescaped
		}
		if unescaped, uerr := url.QueryUnescape(pw); uerr == nil {
			pw = unescaped
		}
		return id, pw, true, nil
	}
	return form.ClientID, form.ClientSecret, false, nil
}

// mintAccessToken produces the access token both grants hand back, in
// whichever format the target's access_token: is set to (README
// "Tokens").
//
// jwt (the default) signs in's claims, so a resource server can verify
// the token and a human can read it while debugging. opaque returns a
// random string carrying no claims at all -- what a provider whose
// access tokens are database handles rather than assertions hands out,
// and the thing to point an application at when you want to prove it
// never quietly parses an access token it was only ever meant to present.
// in is ignored in that case; both call sites build it unconditionally
// because the ID token minted in the same exchange needs the same values
// anyway.
//
// Whichever format comes out, the caller stores the string in t.sessions
// and that is what /userinfo resolves it through -- the lookup path is
// identical for both formats and always was, which is the whole reason
// this is one branch rather than a second /userinfo (see sessions.go).
// at_hash needs no special case either: it hashes the octets of whatever
// the access_token value is, so go-oidc's VerifyAccessToken still passes
// against an opaque one (jwt.go's atHashS256).
//
// Note what opaque gives up: tamper: [iss], [aud], [exp] and [signature]
// have nothing to act on here, since an opaque token has no claims and no
// signature to corrupt. Those values still corrupt the ID token from the
// same exchange; on an opaque access token they are a deliberate no-op,
// for the same reason tamper: [nonce] is one on a flow that carried no
// nonce (buildIDToken's doc comment) -- corrupting a claim that is not
// there would mean fabricating one no real IdP would have sent.
func (t *Target) mintAccessToken(in accessTokenInput) (string, error) {
	if t.accessToken == config.AccessTokenOpaque {
		tok, err := randomToken(32)
		if err != nil {
			return "", fmt.Errorf("oidcop: minting opaque access token: %w", err)
		}
		return tok, nil
	}
	return buildAccessToken(t.keys, in)
}

// nbfFor computes the nbf claim for a token issued at now: a pointer to
// the skewed time when the target configures nbf_skew, and nil when it
// does not, so buildIDToken omits the claim entirely rather than emitting
// a redundant nbf equal to iat.
//
// Both grants and the headless Mint (mint.go) need exactly this, which is
// why it is one function: an nbf that applied to a login but not to a
// refresh, or to neither but to a CLI mint, would be a difference between
// code paths that are supposed to be indistinguishable.
func nbfFor(t *Target, now time.Time) *time.Time {
	if t.nbfSkew == 0 {
		return nil
	}
	v := now.Add(t.nbfSkew)
	return &v
}

// issueFromCode implements the authorization_code grant: consume the
// code (single-use, only once every check -- client match, redirect_uri
// match, expiry, PKCE -- passes), then mint and return a fresh ID token
// and access token.
func issueFromCode(ctx tanukirpc.Context[*Target], t *Target, clientID string, req tokenRequest) (*tokenResponse, error) {
	if req.Code == "" {
		return nil, httpx.InvalidRequest("code is required")
	}

	now := t.clock.Now()
	ac, err := t.codes.consume(now, req.Code, clientID, req.RedirectURI)
	if err != nil {
		return nil, err
	}

	if err := checkPKCE(ac.codeChallenge, ac.codeChallengeMethod, req.CodeVerifier); err != nil {
		return nil, err
	}
	// pkce is only attached when the exchanged code actually had a
	// challenge -- Fields.SetPKCE left unset renders as an absent field
	// (Record.PKCE's `omitempty`), matching README "Request log"'s "pkce
	// ... absent when the client sent no PKCE".
	if ac.codeChallengeMethod != "" {
		reqlog.FieldsFromContext(ctx).SetPKCE(ac.codeChallengeMethod)
	}

	resolvedClaims, ok, err := t.claimsFor(ac.loginIdentity, clientID)
	if !ok {
		// Unreachable in practice: /authorize already validated the
		// subject before minting this code. Fail closed rather than
		// silently issuing a claims-less token for a subject that
		// should not exist.
		return nil, httpx.ServerError(fmt.Sprintf("token: subject %q from a previously-issued code is no longer valid on target %q", ac.subject, t.name))
	}
	if err != nil {
		return nil, httpx.ServerError(fmt.Sprintf("token: resolving claims: %v", err))
	}

	issuer, err := t.issuerTmpl.Resolve(tmpl.Login{Subject: ac.subject, ClientID: clientID, Claims: resolvedClaims})
	if err != nil {
		return nil, httpx.ServerError(fmt.Sprintf("token: resolving issuer: %v", err))
	}

	idExp := now.Add(t.idTokenTTL)
	atExp := now.Add(t.accessTokenTTL)
	nbf := nbfFor(t, now)

	accessToken, err := t.mintAccessToken(accessTokenInput{
		issuer:    issuer,
		subject:   ac.subject,
		audience:  clientID,
		clientID:  clientID,
		scope:     ac.scope,
		issuedAt:  now,
		expiresAt: atExp,
		tamper:    t.tamper,
	})
	if err != nil {
		return nil, httpx.ServerError(err.Error())
	}

	idToken, err := buildIDToken(t.keys, idTokenInput{
		issuer:       issuer,
		subject:      ac.subject,
		audience:     clientID,
		nonce:        ac.nonce,
		nbf:          nbf,
		issuedAt:     now,
		expiresAt:    idExp,
		accessToken:  accessToken,
		customClaims: resolvedClaims,
		tamper:       t.tamper,
	})
	if err != nil {
		return nil, httpx.ServerError(err.Error())
	}

	t.sessions.put(accessToken, accessTokenSession{
		subject:   ac.subject,
		claims:    resolvedClaims,
		clientID:  clientID,
		expiresAt: atExp,
	})

	// Refresh tokens are issued unconditionally here, not gated on
	// scope=offline_access. Real providers often gate on it; this
	// package does not, for two reasons: (1) config has no scope-gating
	// knob at all (README's `refresh_token: rotate|static` only selects
	// rotation behaviour, never whether a refresh token is issued in the
	// first place), and (2) the behaviours this package exists to test --
	// rotation, reuse detection, revocation -- all need a refresh token to
	// exist with no extra ceremony on the client's authorize request. The
	// simpler behaviour is deliberate.
	refreshToken, familyID, err := t.refreshTokens.issue(clientID, ac.loginIdentity, ac.scope)
	if err != nil {
		return nil, httpx.ServerError(fmt.Sprintf("token: issuing refresh token: %v", err))
	}
	t.refreshTokens.trackAccessToken(familyID, accessToken, t.sessions)

	reqlog.FieldsFromContext(ctx).SetSub(ac.subject)

	return &tokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(t.accessTokenTTL.Seconds()),
		IDToken:      idToken,
		RefreshToken: refreshToken,
	}, nil
}

// issueFromRefresh implements the refresh_token grant (README "Refresh
// tokens"): validate and, per the target's rotate/static configuration,
// rotate the presented refresh token (see refreshStore.refresh for the
// rotation and reuse-detection rules), then mint a fresh access token and
// ID token for the same subject and claims -- exactly as if the client
// had just exchanged a code, with recomputed iat/exp/nbf honouring the
// target's TTLs (including negative ones, same as issueFromCode).
//
// The refreshed ID token deliberately omits `nonce`. OIDC Core §12.2
// ("Successful Refresh Response") lists exactly which claims a refreshed
// ID Token MUST/MAY carry, and does not include nonce among them -- nonce
// is defined (§2) as "the value sent in the Authentication Request", and
// a refresh has no Authentication Request to have sent one in. Some
// providers echo the original nonce anyway; this package does not,
// preferring the reading a client's verifier should never end up relying
// on nonce surviving a refresh (go-oidc's own verifier does not check
// nonce at all -- that is left to the caller of Verify -- so this cannot
// break a client that re-verifies its ID token after a refresh).
func issueFromRefresh(ctx tanukirpc.Context[*Target], t *Target, clientID string, req tokenRequest) (*tokenResponse, error) {
	if req.RefreshToken == "" {
		return nil, httpx.InvalidRequest("refresh_token is required")
	}

	result, err := t.refreshTokens.refresh(t.sessions, req.RefreshToken, clientID)
	if err != nil {
		return nil, err
	}

	// The claims come from the refresh family, not from a fresh lookup of
	// the subject: an identity injected at /authorize exists nowhere in
	// the config, so re-deriving it here would silently refresh into a
	// different (empty) claim set. See loginIdentity.
	resolvedClaims, ok, err := t.claimsFor(result.loginIdentity, clientID)
	if !ok {
		// Unreachable in practice, same reasoning as issueFromCode: fail
		// closed rather than issue a claims-less token.
		return nil, httpx.ServerError(fmt.Sprintf("token: subject %q from a refresh token is no longer valid on target %q", result.subject, t.name))
	}
	if err != nil {
		return nil, httpx.ServerError(fmt.Sprintf("token: resolving claims: %v", err))
	}

	issuer, err := t.issuerTmpl.Resolve(tmpl.Login{Subject: result.subject, ClientID: clientID, Claims: resolvedClaims})
	if err != nil {
		return nil, httpx.ServerError(fmt.Sprintf("token: resolving issuer: %v", err))
	}

	now := t.clock.Now()
	idExp := now.Add(t.idTokenTTL)
	atExp := now.Add(t.accessTokenTTL)
	nbf := nbfFor(t, now)

	accessToken, err := t.mintAccessToken(accessTokenInput{
		issuer:    issuer,
		subject:   result.subject,
		audience:  clientID,
		clientID:  clientID,
		scope:     result.scope,
		issuedAt:  now,
		expiresAt: atExp,
		tamper:    t.tamper,
	})
	if err != nil {
		return nil, httpx.ServerError(err.Error())
	}

	idToken, err := buildIDToken(t.keys, idTokenInput{
		issuer:       issuer,
		subject:      result.subject,
		audience:     clientID,
		nonce:        "", // see doc comment above: refreshed ID tokens omit nonce
		nbf:          nbf,
		issuedAt:     now,
		expiresAt:    idExp,
		accessToken:  accessToken,
		customClaims: resolvedClaims,
		tamper:       t.tamper,
	})
	if err != nil {
		return nil, httpx.ServerError(err.Error())
	}

	t.sessions.put(accessToken, accessTokenSession{
		subject:   result.subject,
		claims:    resolvedClaims,
		clientID:  clientID,
		expiresAt: atExp,
	})
	t.refreshTokens.trackAccessToken(result.familyID, accessToken, t.sessions)

	reqlog.FieldsFromContext(ctx).SetSub(result.subject)

	return &tokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(t.accessTokenTTL.Seconds()),
		IDToken:      idToken,
		RefreshToken: result.nextToken,
	}, nil
}
