// Package tmpl resolves the "${...}" placeholder syntax used in a target's
// issuer string and in claim values, so that authside can serve a different
// iss per login. See the README sections "Per-tenant issuers" and
// "Discovery under a templated issuer" for the motivating scenario
// (Microsoft Entra ID's per-directory issuer).
//
// # Syntax
//
// A template is an ordinary string containing zero or more placeholders of
// the form "${...}". Three placeholder forms are recognised:
//
//	${claims.<name>}   the login's claim named <name>
//	${subject}         the login's sub
//	${client_id}       the client the flow is running for
//
// Everything between "claims." and the closing "}" is taken verbatim as the
// claim name, including any further dots: "${claims.a.b}" looks up a claim
// literally named "a.b", not a nested "a" -> "b" path. This is the simpler
// of the two possible rules and it is the one this package implements —
// JWT claim names are conventionally flat, and a literal reading needs no
// extra lookup rules. A degenerate consequence of scanning for the first
// "}" is that "${claims.${x}}" names a claim literally called "${x" (the
// inner "${" is not special); this is expected, not a bug.
//
// There is no escape sequence for "$". Each "$" byte is examined
// independently: it starts a placeholder only when immediately followed by
// "{", and is otherwise passed through as a literal character. This means
// "$$" (not followed by "{") is byte-identical literal output, while
// "$${claims.x}" is a literal "$" followed by the resolved claim value
// (the first "$" is literal because the next byte is "$", not "{"; the
// second "$" then starts a real placeholder). There is no way to emit a
// literal "${" followed by what looks like a placeholder body — that
// combination is always parsed as a placeholder.
//
// Whitespace inside "${ }" is not trimmed or otherwise special-cased: it is
// part of the placeholder content, so "${ subject }" does not match
// "subject" and is rejected as an unknown placeholder (see below). This
// falls directly out of parsing the content as an exact match and needs no
// separate rule.
//
// A template with no "$" at all — the common case, a plain string issuer —
// passes through Resolve and Placeholderize unchanged and without copying.
//
// # Parse-time vs. resolve-time errors
//
// Parse validates everything that does not depend on a specific login: an
// unterminated "${", an empty "${}", an empty claim name ("${claims.}"),
// and a placeholder that is not one of the three recognised forms (for
// example "${bogus}") are all rejected by Parse, not by Resolve. This is a
// deliberate choice: which placeholder *forms* exist is fixed by this
// package, not by any particular login, so a config with a malformed or
// unrecognised placeholder fails at load time (when Parse is called)
// instead of lazily, the first time a token happens to be issued for some
// user. Because a *Template can only be constructed by Parse, a caller can
// never hold a Template whose placeholders are not one of the three known
// kinds — Resolve and Placeholderize can assume that invariant and do not
// re-check it.
//
// What Parse cannot know is whether a *specific* login has the claim a
// template asks for, or whether that claim's value can be turned into a
// string. Those are exactly the two errors Resolve reports: an unknown
// claim name, and a claim value of a type this package does not
// stringify (see below). Both errors name the offending placeholder and
// list what was available, so a misconfigured claim name fails loudly
// instead of resolving to an empty string.
//
// # Claim value stringification
//
// Resolve accepts claim values of type string, bool, int, int64, float64
// and encoding/json.Number, with a fixed rule for each: strings are used
// as-is; bools become "true"/"false"; integers are formatted in base 10;
// floats and json.Number use the shortest decimal representation that
// round-trips. Any other type — including nil, maps, slices and any
// numeric type not in that list — is a resolve error naming the claim and
// its Go type, because there is no obviously-correct string form for a
// composite or absent value and silently stringifying one (e.g. "[]" or
// "map[]") would produce a plausible-looking but wrong issuer.
//
// # Two operations, and why they are different
//
// Resolve substitutes real values for one login (a subject, a client ID and
// that login's claims) and is used to produce the actual iss that goes into
// an issued token. Two different logins with different claims resolve the
// same template to two different strings — that is the entire point of a
// per-tenant issuer.
//
// Placeholderize renders the template for the shared discovery document,
// with placeholders deliberately left unresolved, in the shape a real
// provider emits: Entra's tenant-agnostic metadata returns
// "https://login.microsoftonline.com/{tenantid}/v2.0" verbatim. So
// "${claims.tid}" becomes "{tid}" — the claim name in braces, with no
// leading "claims." — following an optional caller-supplied override map
// from claim name to emitted placeholder name (Entra itself names the claim
// "tid" but the placeholder "{tenantid}"; that pairing is a hook for a
// future "entra" preset, not something this package builds). "${subject}"
// and "${client_id}" always become the fixed strings "{subject}" and
// "{client_id}"; the override map applies only to claim placeholders, since
// there is no per-login data available in this mode to override in the
// first place. Placeholderize cannot fail: every placeholder in a parsed
// Template is already known to be one of the three recognised forms, so
// rendering it as "{name}" needs no further validation.
package tmpl
