// Package clock provides the Clock interface authside uses in place of
// time.Now, so iat/exp/nbf, authorization code and refresh token expiry
// are all testable via a single seam.
package clock
