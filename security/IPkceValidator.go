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

	// check code_challenge_method (constant-time compares to avoid leaking match length;
	// never log the code_verifier — it is a secret, logging it defeats PKCE)
	if codeChallengeMethod == core.Pkce_Plain {
		r = core.FixedTimeCompare(codeVerifier, codeChallenge)
		if !r {
			xlog.Debug("PKCE plain verification failed")
		}
	} else if codeChallengeMethod == core.Pkce_S256 {
		r = core.FixedTimeCompare(codeChallenge, core.ToSHA256Base64URL(codeVerifier))
		if !r {
			xlog.Debug("PKCE S256 verification failed")
		}
	} else {
		xlog.Warnf("Unsupported code_challenge_method: %s", codeChallengeMethod)
	}

	return r
}
