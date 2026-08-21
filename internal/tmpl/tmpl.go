package tmpl

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Kind identifies which of the three recognised placeholder forms a
// Placeholder is.
type Kind int

const (
	// KindClaim is "${claims.<name>}".
	KindClaim Kind = iota
	// KindSubject is "${subject}".
	KindSubject
	// KindClientID is "${client_id}".
	KindClientID
)

// String returns a short name for k, for use in error messages and logs.
func (k Kind) String() string {
	switch k {
	case KindClaim:
		return "claims"
	case KindSubject:
		return "subject"
	case KindClientID:
		return "client_id"
	default:
		return "unknown"
	}
}

// Placeholder describes one "${...}" occurrence found by Parse.
type Placeholder struct {
	// Kind is which of the three recognised forms this placeholder is.
	Kind Kind
	// Name is the claim name for a KindClaim placeholder, and is empty
	// for KindSubject and KindClientID.
	Name string
	// Raw is the placeholder's content exactly as written, without the
	// surrounding "${" and "}" (e.g. "claims.tid", "subject").
	Raw string
}

// Login carries the values used to Resolve a Template for one specific
// login: the subject that logged in, the client the flow is running for,
// and that login's claims.
type Login struct {
	Subject  string
	ClientID string
	Claims   map[string]any
}

// Overrides maps a claim name to the placeholder name Placeholderize emits
// for it, in place of the claim name itself. A nil or empty Overrides
// behaves exactly like the default: the placeholder name is the claim name.
type Overrides map[string]string

// Sentinel errors identifying the class of a parse or resolve failure.
// Use errors.Is to test for them; the returned error's message additionally
// carries the offending placeholder and, where relevant, the names that
// were available.
var (
	// ErrSyntax is returned by Parse for a malformed "${...}" — an
	// unterminated "${", an empty "${}", or an empty claim name.
	ErrSyntax = errors.New("tmpl: syntax error")
	// ErrUnknownPlaceholder is returned by Parse when a placeholder's
	// content is not "subject", "client_id", or "claims.<name>".
	ErrUnknownPlaceholder = errors.New("tmpl: unknown placeholder")
	// ErrUnknownClaim is returned by Resolve when a login has no claim
	// matching a "${claims.<name>}" placeholder.
	ErrUnknownClaim = errors.New("tmpl: unknown claim")
	// ErrUnsupportedClaimType is returned by Resolve when a claim value
	// cannot be turned into a string (see the package doc comment for
	// the exact list of supported types).
	ErrUnsupportedClaimType = errors.New("tmpl: unsupported claim value type")
)

// Template is a parsed "${...}" template string. The zero value is not a
// valid Template; construct one with Parse. A *Template is immutable after
// Parse returns and is safe for concurrent use.
type Template struct {
	raw      string
	literals []string      // len(literals) == len(phs)+1
	phs      []Placeholder // occurrences in order, may repeat
	unique   []Placeholder // phs deduplicated, first-seen order
}

// Parse parses s into a Template. It returns an error if s contains a
// malformed placeholder (an unterminated "${", an empty "${}", an empty
// claim name) or a placeholder that is not one of "${claims.<name>}",
// "${subject}" or "${client_id}". A string with no "$" at all always
// parses successfully and resolves byte-identically.
func Parse(s string) (*Template, error) {
	if strings.IndexByte(s, '$') == -1 {
		return &Template{raw: s, literals: []string{s}}, nil
	}

	var literals []string
	var phs []Placeholder
	litStart := 0
	i := 0
	for i < len(s) {
		if s[i] != '$' {
			i++
			continue
		}
		if i+1 >= len(s) || s[i+1] != '{' {
			// A literal '$' not followed by '{'. No escape sequence is
			// supported; this byte is passed through and scanning
			// resumes at the next byte (which may itself be '$').
			i++
			continue
		}

		rest := s[i+2:]
		end := strings.IndexByte(rest, '}')
		if end == -1 {
			return nil, fmt.Errorf("%w: unterminated \"${\" in %q (starting at byte %d)", ErrSyntax, s, i)
		}
		content := rest[:end]
		if content == "" {
			return nil, fmt.Errorf("%w: empty placeholder \"${}\" in %q (at byte %d)", ErrSyntax, s, i)
		}

		ph, err := parsePlaceholder(content)
		if err != nil {
			return nil, err
		}

		literals = append(literals, s[litStart:i])
		phs = append(phs, ph)

		i = i + 2 + end + 1
		litStart = i
	}
	literals = append(literals, s[litStart:])

	return &Template{
		raw:      s,
		literals: literals,
		phs:      phs,
		unique:   dedupePlaceholders(phs),
	}, nil
}

// parsePlaceholder classifies the content of one "${...}" (without the
// braces) into one of the three recognised placeholder forms.
func parsePlaceholder(content string) (Placeholder, error) {
	switch content {
	case "subject":
		return Placeholder{Kind: KindSubject, Raw: content}, nil
	case "client_id":
		return Placeholder{Kind: KindClientID, Raw: content}, nil
	}
	if name, ok := strings.CutPrefix(content, "claims."); ok {
		if name == "" {
			return Placeholder{}, fmt.Errorf("%w: placeholder \"${%s}\": claim name must not be empty", ErrSyntax, content)
		}
		return Placeholder{Kind: KindClaim, Name: name, Raw: content}, nil
	}
	return Placeholder{}, fmt.Errorf(
		"%w: placeholder \"${%s}\": must be \"subject\", \"client_id\", or \"claims.<name>\"",
		ErrUnknownPlaceholder, content,
	)
}

func dedupePlaceholders(phs []Placeholder) []Placeholder {
	if len(phs) == 0 {
		return nil
	}
	seen := make(map[Placeholder]bool, len(phs))
	out := make([]Placeholder, 0, len(phs))
	for _, p := range phs {
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// String returns the original, unparsed template string.
func (t *Template) String() string {
	return t.raw
}

// HasPlaceholders reports whether t contains at least one "${...}"
// placeholder. A false result means Resolve and Placeholderize both return
// the original string unchanged.
func (t *Template) HasPlaceholders() bool {
	return len(t.phs) > 0
}

// Placeholders returns the distinct placeholders used in t, in the order
// they first appear. A placeholder repeated more than once is reported
// once. The returned slice is a copy and safe for the caller to mutate.
func (t *Template) Placeholders() []Placeholder {
	if len(t.unique) == 0 {
		return nil
	}
	out := make([]Placeholder, len(t.unique))
	copy(out, t.unique)
	return out
}

// Resolve substitutes real values for one login and returns the resolved
// string — for example the actual iss to put in an issued token. It
// returns an error, naming the offending placeholder, if a "${claims.X}"
// placeholder has no corresponding entry in login.Claims, or if a claim's
// value cannot be turned into a string (see the package doc comment for
// the supported types).
//
// Two logins with different claims generally resolve the same Template to
// two different strings; that is the mechanism a per-tenant issuer relies
// on.
func (t *Template) Resolve(login Login) (string, error) {
	if len(t.phs) == 0 {
		return t.raw, nil
	}

	var b strings.Builder
	b.Grow(len(t.raw))
	for i, lit := range t.literals {
		b.WriteString(lit)
		if i >= len(t.phs) {
			continue
		}
		val, err := resolvePlaceholder(t.phs[i], login)
		if err != nil {
			return "", err
		}
		b.WriteString(val)
	}
	return b.String(), nil
}

func resolvePlaceholder(ph Placeholder, login Login) (string, error) {
	switch ph.Kind {
	case KindSubject:
		return login.Subject, nil
	case KindClientID:
		return login.ClientID, nil
	case KindClaim:
		v, ok := login.Claims[ph.Name]
		if !ok {
			return "", fmt.Errorf(
				"%w: placeholder \"${%s}\": no claim named %q (available claims: %s)",
				ErrUnknownClaim, ph.Raw, ph.Name, formatAvailableClaims(login.Claims),
			)
		}
		return stringifyClaim(ph.Name, v)
	default:
		// Unreachable: Parse never produces any other Kind.
		return "", fmt.Errorf("tmpl: internal error: unhandled placeholder kind %v", ph.Kind)
	}
}

func formatAvailableClaims(claims map[string]any) string {
	if len(claims) == 0 {
		return "(no claims)"
	}
	names := make([]string, 0, len(claims))
	for k := range claims {
		names = append(names, k)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// stringifyClaim converts a claim value to a string using a fixed rule per
// type: strings are used as-is, bools become "true"/"false", integers are
// formatted in base 10, and floats and json.Number use the shortest
// round-tripping decimal form. Any other type — including nil, maps and
// slices — is an error, since there is no unambiguous string form for a
// composite or absent value.
func stringifyClaim(name string, v any) (string, error) {
	switch x := v.(type) {
	case string:
		return x, nil
	case bool:
		return strconv.FormatBool(x), nil
	case int:
		return strconv.Itoa(x), nil
	case int64:
		return strconv.FormatInt(x, 10), nil
	case float64:
		return strconv.FormatFloat(x, 'g', -1, 64), nil
	case json.Number:
		return x.String(), nil
	default:
		return "", fmt.Errorf(
			"%w: claim %q has type %T, which cannot be used in a template (supported: string, bool, int, int64, float64, json.Number)",
			ErrUnsupportedClaimType, name, v,
		)
	}
}

// Placeholderize renders t for the shared discovery document: every
// placeholder is left unresolved, in the shape a real provider emits
// ("${claims.tid}" becomes "{tid}"), rather than substituted with a real
// value. overrides, if non-nil, maps a claim name to the placeholder name
// to emit in its place (for example Entra's claim "tid" emitted as the
// placeholder "{tenantid}"); a claim with no entry in overrides emits its
// own name. "${subject}" and "${client_id}" always become the fixed
// strings "{subject}" and "{client_id}" — overrides applies only to claim
// placeholders, since Placeholderize has no per-login data to override in
// the first place.
//
// Placeholderize cannot fail: a *Template's placeholders are always one of
// the three forms Parse recognises, so there is nothing left to validate.
func (t *Template) Placeholderize(overrides Overrides) string {
	if len(t.phs) == 0 {
		return t.raw
	}

	var b strings.Builder
	b.Grow(len(t.raw))
	for i, lit := range t.literals {
		b.WriteString(lit)
		if i >= len(t.phs) {
			continue
		}
		b.WriteByte('{')
		b.WriteString(placeholderizeName(t.phs[i], overrides))
		b.WriteByte('}')
	}
	return b.String()
}

func placeholderizeName(ph Placeholder, overrides Overrides) string {
	switch ph.Kind {
	case KindSubject:
		return "subject"
	case KindClientID:
		return "client_id"
	case KindClaim:
		if overrides != nil {
			if name, ok := overrides[ph.Name]; ok {
				return name
			}
		}
		return ph.Name
	default:
		// Unreachable: Parse never produces any other Kind.
		return ph.Raw
	}
}
