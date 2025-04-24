package token

import (
	"github.com/DreamvatLab/oauth2go/model"
)

type ITokenClaimsGenerator interface {
	// Generate(ctx *fasthttp.RequestCtx, grantType string, client model.IClient, scopes []string, username string) *map[string]interface{}
	Generate(grantType string, client model.IClient, scopes []string, username string) *map[string]interface{}
}
