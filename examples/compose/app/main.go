// Command app is a minimal OIDC relying party used to exercise authside's
// login flow end to end from examples/compose.
//
// It implements exactly two routes:
//
//	GET /login         redirects to the provider's authorization endpoint
//	GET /auth/callback exchanges the code, verifies the ID token, shows claims
//
// This is deliberately not a template for a real application's auth
// integration -- state/nonce handling here is a single pair of cookies with
// no session store, kept minimal for readability. What matters is that it
// uses the real production code path (github.com/coreos/go-oidc/v3 and
// golang.org/x/oauth2 talking actual OIDC over the wire) against authside,
// which is the entire point of authside: the application under test does
// not change its code path, only the issuer URL and client credentials.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func main() {
	issuer := os.Getenv("OIDC_ISSUER")
	clientID := os.Getenv("OIDC_CLIENT_ID")
	clientSecret := os.Getenv("OIDC_CLIENT_SECRET")
	redirectURL := envOr("OIDC_REDIRECT_URL", "http://localhost:8080/auth/callback")
	if issuer == "" || clientID == "" || clientSecret == "" {
		log.Fatal("OIDC_ISSUER, OIDC_CLIENT_ID and OIDC_CLIENT_SECRET must all be set")
	}

	ctx := context.Background()

	// authside can take a moment to accept connections after the
	// container starts; retry discovery briefly so `docker compose up`
	// doesn't require a manual restart of this service.
	var provider *oidc.Provider
	var err error
	for i := 0; i < 30; i++ {
		provider, err = oidc.NewProvider(ctx, issuer)
		if err == nil {
			break
		}
		log.Printf("waiting for OIDC discovery at %s: %v", issuer, err)
		time.Sleep(1 * time.Second)
	}
	if err != nil {
		log.Fatalf("OIDC discovery against %s failed after retrying: %v", issuer, err)
	}
	log.Printf("discovered provider at %s", issuer)

	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})
	oauth2Config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<!doctype html><html><body>
<h1>authside demo app</h1>
<p>Issuer: %s</p>
<p><a href="/login">Log in</a></p>
</body></html>`, html.EscapeString(issuer))
	})

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		state := randString()
		nonce := randString()
		http.SetCookie(w, &http.Cookie{Name: "state", Value: state, Path: "/", HttpOnly: true})
		http.SetCookie(w, &http.Cookie{Name: "nonce", Value: nonce, Path: "/", HttpOnly: true})
		http.Redirect(w, r, oauth2Config.AuthCodeURL(state, oidc.Nonce(nonce)), http.StatusFound)
	})

	mux.HandleFunc("/auth/callback", func(w http.ResponseWriter, r *http.Request) {
		stateCookie, err := r.Cookie("state")
		if err != nil || r.URL.Query().Get("state") != stateCookie.Value {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			return
		}
		nonceCookie, err := r.Cookie("nonce")
		if err != nil {
			http.Error(w, "missing nonce cookie", http.StatusBadRequest)
			return
		}

		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "missing code (error="+r.URL.Query().Get("error")+")", http.StatusBadRequest)
			return
		}

		token, err := oauth2Config.Exchange(r.Context(), code)
		if err != nil {
			http.Error(w, "code exchange failed: "+err.Error(), http.StatusBadGateway)
			return
		}

		rawIDToken, ok := token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "no id_token in token response", http.StatusInternalServerError)
			return
		}
		idToken, err := verifier.Verify(r.Context(), rawIDToken)
		if err != nil {
			http.Error(w, "id_token verification failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if idToken.Nonce != nonceCookie.Value {
			http.Error(w, "nonce mismatch", http.StatusBadRequest)
			return
		}

		var claims map[string]any
		if err := idToken.Claims(&claims); err != nil {
			http.Error(w, "decoding claims: "+err.Error(), http.StatusInternalServerError)
			return
		}
		claimsJSON, _ := json.MarshalIndent(claims, "", "  ")

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<!doctype html><html><body>
<h1>Logged in via authside (fake IdP -- dev/test only)</h1>
<p>ID token subject: <code>%s</code></p>
<h2>Claims</h2>
<pre>%s</pre>
<p><a href="/login">Log in again</a></p>
</body></html>`, html.EscapeString(idToken.Subject), html.EscapeString(string(claimsJSON)))
	})

	log.Println("demo app listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

func randString() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
