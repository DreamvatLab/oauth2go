package redis

import (
	"testing"

	"github.com/DreamvatLab/go/xconfig"
	"github.com/DreamvatLab/go/xredis"
	"github.com/DreamvatLab/oauth2go/model"
	"github.com/DreamvatLab/oauth2go/security/rsa"
	"github.com/stretchr/testify/assert"
)

func TestRedisTokenStore(t *testing.T) {
	var redisConfig *xredis.RedisConfig
	configProvider := xconfig.NewJsonConfigProvider()
	configProvider.GetStruct("Redis", &redisConfig)
	secretEncryptor := rsa.NewRSASecretEncryptor("../../examples/cert/test.key")
	_tokenStore := NewRedisTokenStore("rt:", secretEncryptor, redisConfig)

	a := &model.TokenInfo{
		ClientID: "test",
	}
	refreshToken := "abcdefg"
	_tokenStore.SaveRefreshToken(
		refreshToken,
		a,
		30,
	)
	b := _tokenStore.GetThenRemoveTokenInfo(refreshToken)

	assert.Equal(t, a.ClientID, b.ClientID)
	t.Log(b.ClientID)
}
