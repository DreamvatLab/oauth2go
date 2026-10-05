package token

import (
	"errors"

	"github.com/DreamvatLab/oauth2go/model"
)

// ErrSubjectDenied is returned (or wrapped) by ITokenClaimsGenerator.Generate when the subject
// is no longer allowed to obtain tokens, e.g. the user has been disabled or removed.
// TokenHost answers it with invalid_grant (token endpoint) / access_denied (implicit) instead of server_error.
var ErrSubjectDenied = errors.New("subject is not allowed to obtain tokens")

type ITokenClaimsGenerator interface {
	// Generate(ctx *fasthttp.RequestCtx, grantType string, client model.IClient, scopes []string, username string) *map[string]interface{}
	Generate(grantType string, client model.IClient, scopes []string, username string) (*map[string]interface{}, error)
}
