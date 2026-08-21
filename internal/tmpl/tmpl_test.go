package tmpl

import (
	"errors"
	"strings"
	"testing"
)

func TestParse_PlainStringPassesThroughByteIdentical(t *testing.T) {
	const s = "http://authside:5556/oidc"
	tpl, err := Parse(s)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if tpl.HasPlaceholders() {
		t.Fatalf("HasPlaceholders() = true, want false")
	}
	if got := tpl.String(); got != s {
		t.Fatalf("String() = %q, want %q", got, s)
	}
	got, err := tpl.Resolve(Login{Subject: "user-1", ClientID: "app", Claims: map[string]any{"x": "y"}})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != s {
		t.Fatalf("Resolve() = %q, want byte-identical %q", got, s)
	}
	if got := tpl.Placeholderize(nil); got != s {
		t.Fatalf("Placeholderize() = %q, want byte-identical %q", got, s)
	}
}

func TestEntraExampleEndToEnd(t *testing.T) {
	const issuer = "https://login.microsoftonline.com/${claims.tid}/v2.0"
	tpl, err := Parse(issuer)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !tpl.HasPlaceholders() {
		t.Fatalf("HasPlaceholders() = false, want true")
	}

	user1, err := tpl.Resolve(Login{
		Subject: "user-1",
		Claims:  map[string]any{"tid": "11111111-1111-1111-1111-111111111111"},
	})
	if err != nil {
		t.Fatalf("Resolve(user-1): %v", err)
	}
	const wantUser1 = "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0"
	if user1 != wantUser1 {
		t.Fatalf("Resolve(user-1) = %q, want %q", user1, wantUser1)
	}

	user2, err := tpl.Resolve(Login{
		Subject: "user-2",
		Claims:  map[string]any{"tid": "22222222-2222-2222-2222-222222222222"},
	})
	if err != nil {
		t.Fatalf("Resolve(user-2): %v", err)
	}
	const wantUser2 = "https://login.microsoftonline.com/22222222-2222-2222-2222-222222222222/v2.0"
	if user2 != wantUser2 {
		t.Fatalf("Resolve(user-2) = %q, want %q", user2, wantUser2)
	}

	// Per-tenant isolation: two different users' resolved issuers differ
	// from each other.
	if user1 == user2 {
		t.Fatalf("user-1 and user-2 resolved to the same issuer %q; per-tenant isolation is broken", user1)
	}

	got := tpl.Placeholderize(nil)
	const want = "https://login.microsoftonline.com/{tid}/v2.0"
	if got != want {
		t.Fatalf("Placeholderize() = %q, want %q", got, want)
	}
}

func TestPlaceholderizeOverride(t *testing.T) {
	tpl, err := Parse("https://login.microsoftonline.com/${claims.tid}/v2.0")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got := tpl.Placeholderize(Overrides{"tid": "tenantid"})
	const want = "https://login.microsoftonline.com/{tenantid}/v2.0"
	if got != want {
		t.Fatalf("Placeholderize(override) = %q, want %q", got, want)
	}

	// A claim not present in the override map falls back to its own name.
	tpl2, err := Parse("${claims.tid}:${claims.other}")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got2 := tpl2.Placeholderize(Overrides{"tid": "tenantid"})
	const want2 = "{tenantid}:{other}"
	if got2 != want2 {
		t.Fatalf("Placeholderize(partial override) = %q, want %q", got2, want2)
	}
}

func TestSubjectAndClientIDInClaimValue(t *testing.T) {
	tpl, err := Parse("urn:test:${subject}:${client_id}")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got, err := tpl.Resolve(Login{Subject: "user-1", ClientID: "local-app"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	const want = "urn:test:user-1:local-app"
	if got != want {
		t.Fatalf("Resolve() = %q, want %q", got, want)
	}
}

func TestPlaceholderizeSubjectAndClientID(t *testing.T) {
	tpl, err := Parse("urn:test:${subject}:${client_id}")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got := tpl.Placeholderize(nil)
	const want = "urn:test:{subject}:{client_id}"
	if got != want {
		t.Fatalf("Placeholderize() = %q, want %q", got, want)
	}
}

func TestDottedClaimNameIsLiteral(t *testing.T) {
	tpl, err := Parse("${claims.a.b}")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	phs := tpl.Placeholders()
	if len(phs) != 1 || phs[0].Kind != KindClaim || phs[0].Name != "a.b" {
		t.Fatalf("Placeholders() = %+v, want single claim named \"a.b\"", phs)
	}

	got, err := tpl.Resolve(Login{Claims: map[string]any{"a.b": "literal-value", "a": map[string]any{"b": "nested-value"}}})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "literal-value" {
		t.Fatalf("Resolve() = %q, want the literally-named claim \"literal-value\", not a nested lookup", got)
	}
}

func TestNonStringClaimValues(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  string
	}{
		{"bool true", true, "true"},
		{"bool false", false, "false"},
		{"int", 42, "42"},
		{"int64", int64(-7), "-7"},
		{"float64", 3.5, "3.5"},
		{"float64 whole", float64(4), "4"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tpl, err := Parse("${claims.v}")
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			got, err := tpl.Resolve(Login{Claims: map[string]any{"v": tt.value}})
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if got != tt.want {
				t.Fatalf("Resolve() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNonScalarClaimValueIsError(t *testing.T) {
	tests := []struct {
		name  string
		value any
	}{
		{"map", map[string]any{"x": 1}},
		{"slice", []any{1, 2}},
		{"nil", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tpl, err := Parse("${claims.v}")
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			_, err = tpl.Resolve(Login{Claims: map[string]any{"v": tt.value}})
			if err == nil {
				t.Fatalf("Resolve() = nil error, want an error for a non-scalar claim value")
			}
			if !errors.Is(err, ErrUnsupportedClaimType) {
				t.Fatalf("Resolve() error = %v, want ErrUnsupportedClaimType", err)
			}
			if !strings.Contains(err.Error(), `"v"`) {
				t.Fatalf("Resolve() error = %q, want it to name the claim %q", err.Error(), "v")
			}
		})
	}
}

func TestUnknownClaimIsError(t *testing.T) {
	tpl, err := Parse("${claims.nope}")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	_, err = tpl.Resolve(Login{Claims: map[string]any{"tid": "abc", "email": "a@example.com"}})
	if err == nil {
		t.Fatalf("Resolve() = nil error, want an error naming the unknown claim")
	}
	if !errors.Is(err, ErrUnknownClaim) {
		t.Fatalf("Resolve() error = %v, want ErrUnknownClaim", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "nope") {
		t.Fatalf("error %q does not name the placeholder %q", msg, "nope")
	}
	if !strings.Contains(msg, "tid") || !strings.Contains(msg, "email") {
		t.Fatalf("error %q does not list the available claims", msg)
	}
}

func TestUnknownClaimWithNoClaimsAtAll(t *testing.T) {
	tpl, err := Parse("${claims.nope}")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	_, err = tpl.Resolve(Login{})
	if err == nil {
		t.Fatalf("Resolve() = nil error, want an error")
	}
	if !strings.Contains(err.Error(), "no claims") {
		t.Fatalf("error %q should say there were no claims available, not an empty list", err.Error())
	}
}

func TestUnknownPlaceholderIsParseError(t *testing.T) {
	// ${bogus} is neither "subject", "client_id" nor "claims.<name>": this
	// is a structural error, independent of any login, so it is rejected
	// by Parse rather than deferred to Resolve.
	_, err := Parse("${bogus}")
	if err == nil {
		t.Fatalf("Parse() = nil error, want an error for an unrecognised placeholder")
	}
	if !errors.Is(err, ErrUnknownPlaceholder) {
		t.Fatalf("Parse() error = %v, want ErrUnknownPlaceholder", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "bogus") {
		t.Fatalf("error %q does not name the placeholder %q", msg, "bogus")
	}
	for _, want := range []string{"subject", "client_id", "claims"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error %q does not mention the valid form %q", msg, want)
		}
	}
}

func TestUnterminatedPlaceholderIsParseError(t *testing.T) {
	_, err := Parse("https://example.com/${claims.tid")
	if err == nil {
		t.Fatalf("Parse() = nil error, want an error for an unterminated placeholder")
	}
	if !errors.Is(err, ErrSyntax) {
		t.Fatalf("Parse() error = %v, want ErrSyntax", err)
	}
	if !strings.Contains(err.Error(), "unterminated") {
		t.Fatalf("error %q should say the placeholder is unterminated", err.Error())
	}
}

func TestEmptyPlaceholderIsParseError(t *testing.T) {
	_, err := Parse("https://example.com/${}/v2.0")
	if err == nil {
		t.Fatalf("Parse() = nil error, want an error for an empty placeholder")
	}
	if !errors.Is(err, ErrSyntax) {
		t.Fatalf("Parse() error = %v, want ErrSyntax", err)
	}
	if !strings.Contains(err.Error(), "empty placeholder") {
		t.Fatalf("error %q should say the placeholder is empty", err.Error())
	}
}

func TestEmptyClaimNameIsParseError(t *testing.T) {
	_, err := Parse("${claims.}")
	if err == nil {
		t.Fatalf("Parse() = nil error, want an error for an empty claim name")
	}
	if !errors.Is(err, ErrSyntax) {
		t.Fatalf("Parse() error = %v, want ErrSyntax", err)
	}
	if !strings.Contains(err.Error(), "claim name must not be empty") {
		t.Fatalf("error %q should say the claim name must not be empty", err.Error())
	}
}

func TestLiteralDollarNotFollowedByBrace(t *testing.T) {
	const s = "cost: $5, not a placeholder"
	tpl, err := Parse(s)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if tpl.HasPlaceholders() {
		t.Fatalf("HasPlaceholders() = true, want false for a lone '$'")
	}
	got, err := tpl.Resolve(Login{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != s {
		t.Fatalf("Resolve() = %q, want byte-identical %q", got, s)
	}
}

func TestDoubleDollarIsLiteralWithNoEscape(t *testing.T) {
	// No escape sequence is supported. A plain "$$" (not followed by "{")
	// passes through as two literal '$' characters.
	const s = "price is $$5"
	tpl, err := Parse(s)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if tpl.HasPlaceholders() {
		t.Fatalf("HasPlaceholders() = true, want false for %q", s)
	}
	got, err := tpl.Resolve(Login{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != s {
		t.Fatalf("Resolve() = %q, want byte-identical %q", got, s)
	}
}

func TestDoubleDollarBeforePlaceholder(t *testing.T) {
	// "$${claims.x}": the first '$' is literal (followed by '$', not
	// '{'); the second '$' then starts a real placeholder. Documented
	// consequence of having no escape sequence at all.
	tpl, err := Parse("$${claims.x}")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !tpl.HasPlaceholders() {
		t.Fatalf("HasPlaceholders() = false, want true")
	}
	got, err := tpl.Resolve(Login{Claims: map[string]any{"x": "V"}})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	const want = "$V"
	if got != want {
		t.Fatalf("Resolve() = %q, want %q", got, want)
	}
}

func TestPlaceholderRepeatedMultipleTimes(t *testing.T) {
	tpl, err := Parse("${claims.tid}-${claims.tid}")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got, err := tpl.Resolve(Login{Claims: map[string]any{"tid": "T"}})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "T-T" {
		t.Fatalf("Resolve() = %q, want %q", got, "T-T")
	}

	phs := tpl.Placeholders()
	if len(phs) != 1 {
		t.Fatalf("Placeholders() returned %d entries, want 1 deduplicated entry: %+v", len(phs), phs)
	}
}

func TestAdjacentPlaceholders(t *testing.T) {
	tpl, err := Parse("${claims.a}${claims.b}")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got, err := tpl.Resolve(Login{Claims: map[string]any{"a": "A", "b": "B"}})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "AB" {
		t.Fatalf("Resolve() = %q, want %q", got, "AB")
	}

	if pgot := tpl.Placeholderize(nil); pgot != "{a}{b}" {
		t.Fatalf("Placeholderize() = %q, want %q", pgot, "{a}{b}")
	}
}

func TestTemplateWithNoPlaceholdersAtAll(t *testing.T) {
	const s = "no placeholders here at all"
	tpl, err := Parse(s)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if tpl.HasPlaceholders() {
		t.Fatalf("HasPlaceholders() = true, want false")
	}
	if phs := tpl.Placeholders(); phs != nil {
		t.Fatalf("Placeholders() = %+v, want nil", phs)
	}
}
