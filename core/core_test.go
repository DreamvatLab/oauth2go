package core

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAppendQuery_NoExistingQuery(t *testing.T) {
	got := AppendQuery("https://app.example/cb",
		[2]string{"code", "abc"},
		[2]string{"state", "xyz"},
	)
	assert.Equal(t, "https://app.example/cb?code=abc&state=xyz", got)
}

func TestAppendQuery_PreservesExistingQuery(t *testing.T) {
	// redirect URIs are allowed to carry their own query string; appending must
	// use '&', not produce a second '?'.
	got := AppendQuery("https://app.example/cb?keep=1",
		[2]string{"code", "abc"},
	)
	assert.Equal(t, "https://app.example/cb?keep=1&code=abc", got)
}

func TestAppendQuery_URLEncodesKeysAndValues(t *testing.T) {
	got := AppendQuery("https://app.example/cb",
		[2]string{"redirect uri", "https://x/y?a=b&c=d"},
	)
	assert.Contains(t, got, "redirect+uri=")
	assert.NotContains(t, got, " ")
	// embedded '&' and '?' in the value must be encoded so they don't break parsing
	assert.NotContains(t, strings.TrimPrefix(got, "https://app.example/cb?redirect+uri="), "&")
	assert.NotContains(t, strings.TrimPrefix(got, "https://app.example/cb?redirect+uri="), "?")
}

func TestAppendQuery_SkipsEmptyValues(t *testing.T) {
	got := AppendQuery("https://app.example/cb",
		[2]string{"code", "abc"},
		[2]string{"state", ""},
		[2]string{"scope", "read"},
	)
	assert.Equal(t, "https://app.example/cb?code=abc&scope=read", got)
}

func TestAppendQuery_AllEmpty_ReturnsBase(t *testing.T) {
	got := AppendQuery("https://app.example/cb",
		[2]string{"state", ""},
	)
	assert.Equal(t, "https://app.example/cb", got)
}

func TestAppendFragment_NoExistingFragment(t *testing.T) {
	got := AppendFragment("https://app.example/cb",
		[2]string{"access_token", "tok"},
		[2]string{"token_type", "Bearer"},
	)
	assert.Equal(t, "https://app.example/cb#access_token=tok&token_type=Bearer", got)
}

func TestAppendFragment_PreservesExistingFragment(t *testing.T) {
	got := AppendFragment("https://app.example/cb#section",
		[2]string{"access_token", "tok"},
	)
	assert.Equal(t, "https://app.example/cb#section&access_token=tok", got)
}

func TestAppendFragment_KeepsQueryStringIntact(t *testing.T) {
	// implicit-flow redirects may have both a query string and a fragment; the
	// fragment helper must not collapse them into one.
	got := AppendFragment("https://app.example/cb?keep=1",
		[2]string{"access_token", "tok"},
	)
	assert.Equal(t, "https://app.example/cb?keep=1#access_token=tok", got)
}

func TestAppendFragment_SkipsEmptyValues(t *testing.T) {
	got := AppendFragment("https://app.example/cb",
		[2]string{"access_token", "tok"},
		[2]string{"state", ""},
	)
	assert.Equal(t, "https://app.example/cb#access_token=tok", got)
}

func TestToSHA256Base64URL_KnownVector(t *testing.T) {
	// RFC 7636 worked example: code_verifier "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	// yields challenge "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	got := ToSHA256Base64URL("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
	assert.Equal(t, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", got)
}

func TestGenerateID_NonEmptyAndUnique(t *testing.T) {
	a := GenerateID()
	b := GenerateID()
	assert.NotEmpty(t, a)
	assert.NotEqual(t, a, b)
}

func TestRandom64String_NonEmptyAndUnique(t *testing.T) {
	a := Random64String()
	b := Random64String()
	assert.NotEmpty(t, a)
	assert.NotEqual(t, a, b)
}
