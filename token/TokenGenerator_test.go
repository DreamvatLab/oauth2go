package token

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"testing"

	"github.com/DreamvatLab/oauth2go/model"
	"github.com/pascaldekloe/jwt"
	"github.com/stretchr/testify/assert"
)

type stubClaimsGenerator struct {
	claims *map[string]interface{}
	err    error
}

func (g *stubClaimsGenerator) Generate(grantType string, client model.IClient, scopes []string, username string) (*map[string]interface{}, error) {
	return g.claims, g.err
}

func newTestTokenGenerator(t *testing.T, g ITokenClaimsGenerator) ITokenGenerator {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return NewDefaultTokenGenerator(key, jwt.PS256, g)
}

func TestDefaultTokenGenerator_SignsClaims(t *testing.T) {
	g := newTestTokenGenerator(t, &stubClaimsGenerator{claims: &map[string]interface{}{"sub": "u1"}})

	tok, err := g.GenerateAccessToken(nil, "authorization_code", &model.Client{}, nil, "alice")

	assert.NoError(t, err)
	assert.NotEmpty(t, tok)
}

func TestDefaultTokenGenerator_PropagatesSubjectDenied(t *testing.T) {
	g := newTestTokenGenerator(t, &stubClaimsGenerator{err: fmt.Errorf("user 'alice' is inactive: %w", ErrSubjectDenied)})

	tok, err := g.GenerateAccessToken(nil, "refresh_token", &model.Client{}, nil, "alice")

	assert.Empty(t, tok)
	assert.True(t, errors.Is(err, ErrSubjectDenied))
}

func TestDefaultTokenGenerator_NilClaimsIsError(t *testing.T) {
	g := newTestTokenGenerator(t, &stubClaimsGenerator{})

	tok, err := g.GenerateAccessToken(nil, "refresh_token", &model.Client{}, nil, "alice")

	assert.Empty(t, tok)
	assert.Error(t, err)
	assert.False(t, errors.Is(err, ErrSubjectDenied))
}
