package token

import (
	"crypto/rsa"
	"errors"

	"github.com/DreamvatLab/go/xbytes"
	"github.com/DreamvatLab/oauth2go/core"
	"github.com/DreamvatLab/oauth2go/model"
	"github.com/pascaldekloe/jwt"
	"github.com/valyala/fasthttp"
)

type ITokenGenerator interface {
	GenerateAccessToken(ctx *fasthttp.RequestCtx, grantType string, client model.IClient, scopes []string, username string) (string, error)
	GenerateRefreshToken() string
}

func NewDefaultTokenGenerator(privateKey *rsa.PrivateKey, signingAlgorithm string, claimsGenerator ITokenClaimsGenerator) ITokenGenerator {
	return &DefaultTokenGenerator{
		PrivateKey:       privateKey,
		SigningAlgorithm: signingAlgorithm,
		ClaimsGenerator:  claimsGenerator,
	}
}

type DefaultTokenGenerator struct {
	SigningAlgorithm string
	PrivateKey       *rsa.PrivateKey
	ClaimsGenerator  ITokenClaimsGenerator
}

func (x *DefaultTokenGenerator) GenerateAccessToken(ctx *fasthttp.RequestCtx, grantType string, client model.IClient, scopes []string, username string) (string, error) {
	claims := new(jwt.Claims)
	claims.KeyID = core.GenerateID()
	// claims.Set = *x.ClaimsGenerator.Generate(ctx, grantType, client, scopes, username)
	set, err := x.ClaimsGenerator.Generate(grantType, client, scopes, username)
	if err != nil {
		return "", err
	}
	if set == nil {
		return "", errors.New("claims generator returned nil claims")
	}
	claims.Set = *set
	if subValue, ok := claims.Set["sub"]; ok {
		if sub, b := subValue.(string); b {
			claims.Subject = sub
		}
	}

	token, err := claims.RSASign(x.SigningAlgorithm, x.PrivateKey)
	return xbytes.BytesToStr(token), err
}

func (x *DefaultTokenGenerator) GenerateRefreshToken() string {
	return core.Random64String()
}
