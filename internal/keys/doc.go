// Package keys holds the RSA signing key behind each target's JWKS and
// assigns it its authside-prefixed kid.
//
// A key is either supplied by the target's configuration (Spec, from
// key_pem / key_file) or generated randomly at startup. Supplying one is
// what makes a token verifiable across two processes -- a generated key
// exists only for the life of the process that made it.
package keys
