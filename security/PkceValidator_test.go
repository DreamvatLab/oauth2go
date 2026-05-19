package security

import (
	"strings"
	"testing"

	"github.com/DreamvatLab/oauth2go/core"
	"github.com/stretchr/testify/assert"
)

// RFC 7636 §B.1 example
const (
	rfcVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	rfcChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

func TestPkceValidator_S256_HappyPath(t *testing.T) {
	v := NewDefaultPkceValidator()
	assert.True(t, v.Verify(rfcVerifier, rfcChallenge, core.Pkce_S256))
}

func TestPkceValidator_S256_Mismatch(t *testing.T) {
	v := NewDefaultPkceValidator()
	assert.False(t, v.Verify(rfcVerifier, "not-the-challenge-not-the-challenge-not-th", core.Pkce_S256))
}

func TestPkceValidator_Plain_HappyPath(t *testing.T) {
	v := NewDefaultPkceValidator()
	// plain mode: challenge == verifier
	verifier := strings.Repeat("a", 43)
	assert.True(t, v.Verify(verifier, verifier, core.Pkce_Plain))
}

func TestPkceValidator_Plain_Mismatch(t *testing.T) {
	v := NewDefaultPkceValidator()
	verifier := strings.Repeat("a", 43)
	other := strings.Repeat("b", 43)
	assert.False(t, v.Verify(verifier, other, core.Pkce_Plain))
}

func TestPkceValidator_VerifierTooShort(t *testing.T) {
	// RFC 7636 §4.1: code_verifier must be 43..128 characters.
	v := NewDefaultPkceValidator()
	assert.False(t, v.Verify("short", "short", core.Pkce_Plain))
}

func TestPkceValidator_VerifierTooLong(t *testing.T) {
	v := NewDefaultPkceValidator()
	tooLong := strings.Repeat("a", 129)
	assert.False(t, v.Verify(tooLong, tooLong, core.Pkce_Plain))
}

func TestPkceValidator_UnknownMethod(t *testing.T) {
	v := NewDefaultPkceValidator()
	verifier := strings.Repeat("a", 43)
	assert.False(t, v.Verify(verifier, verifier, "MD5"))
}
