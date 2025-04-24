package security

import (
	"github.com/DreamvatLab/go/xlog"
	"github.com/DreamvatLab/oauth2go/core"
)

type IPkceValidator interface {
	Verify(codeVerifier, codeChallenge, codeChallengeMethod string) bool
}

func NewDefaultPkceValidator() IPkceValidator {
	return &DefaultPkceValidator{}
}

type DefaultPkceValidator struct{}

func (x *DefaultPkceValidator) Verify(codeVerifier, codeChallenge, codeChallengeMethod string) bool {
	// check code_verifier length
	if len(codeVerifier) < 43 || len(codeVerifier) > 128 {
		xlog.Warn("code_verifier length is invalid")
		return false
	}

	r := false

	// check code_challenge_method
	if codeChallengeMethod == core.Pkce_Plain {
		r = codeVerifier == codeChallenge
		if !r {
			xlog.Debugf("code_challenge is not equal to code_verifier: %s != %s", codeChallenge, codeVerifier)
		}
	} else if codeChallengeMethod == core.Pkce_S256 {
		r = codeChallenge == core.ToSHA256Base64URL(codeVerifier)
		if !r {
			xlog.Debugf("code_challenge is not equal to SHA256(code_verifier): %s != %s", codeChallenge, core.ToSHA256Base64URL(codeVerifier))
		}
	} else {
		xlog.Warnf("Unsupported code_challenge_method: %s", codeChallengeMethod)
	}

	return r
}
