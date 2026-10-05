package redis

import (
	"context"
	"encoding/json"
	"time"

	"github.com/DreamvatLab/go/xerr"
	"github.com/DreamvatLab/go/xredis"
	"github.com/DreamvatLab/oauth2go/core"
	"github.com/DreamvatLab/oauth2go/model"
	"github.com/DreamvatLab/oauth2go/security"
	"github.com/DreamvatLab/oauth2go/store"
	"github.com/redis/go-redis/v9"
)

type RedisTokenStore struct {
	Prefix          string
	SecretEncryptor security.ISecretEncryptor
	RedisClient     redis.UniversalClient
}

func NewRedisTokenStore(prefix string, secretEncryptor security.ISecretEncryptor, config *xredis.RedisConfig) store.ITokenStore {
	return &RedisTokenStore{
		Prefix:          prefix,
		SecretEncryptor: secretEncryptor,
		RedisClient:     xredis.NewClient(config),
	}
}

// key derives the Redis key from a refresh token. Only the SHA-256 digest is stored, never the
// token itself, so anyone able to list Redis keys cannot replay the refresh tokens they see.
// Refresh tokens are 64 random bytes, so an unsalted fast hash is sufficient.
// Must stay identical to RedisRefreshTokenInfoStore.GetKey in oauth2net.
func (x *RedisTokenStore) key(refreshToken string) string {
	return x.Prefix + core.ToSHA256Base64URL(refreshToken)
}

func (x *RedisTokenStore) SaveRefreshToken(refreshToken string, requestInfo *model.TokenInfo, expireSeconds int32) {
	// serialize to json
	bytes, err := json.Marshal(requestInfo)
	if xerr.LogError(err) {
		return
	}

	// encrypt
	encodedRefreshToken := x.SecretEncryptor.EncryptBytesToString(bytes)

	// save to redis
	err = x.RedisClient.Set(context.Background(), x.key(refreshToken), encodedRefreshToken, time.Second*time.Duration(expireSeconds)).Err()
	xerr.LogError(err)
}
func (x *RedisTokenStore) RemoveRefreshToken(refreshToken string) {
	err := x.RedisClient.Del(context.Background(), x.key(refreshToken)).Err()
	xerr.LogError(err)
}
func (x *RedisTokenStore) GetThenRemoveTokenInfo(refreshToken string) *model.TokenInfo {
	key := x.key(refreshToken)

	// Atomic read+delete (Redis 6.2+ GETDEL) — closes a race where two concurrent
	// refresh requests could both observe the same token before either deletes it,
	// defeating refresh-token rotation.
	str, err := x.RedisClient.GetDel(context.Background(), key).Result()
	if err != nil {
		if err == redis.Nil { // do not log this error
			return nil
		}
		xerr.LogError(err)
		return nil
	}

	// decrypt & deserialize json
	bytes := x.SecretEncryptor.DecryptStringToBytes(str)
	var info *model.TokenInfo
	err = json.Unmarshal(bytes, &info)
	if xerr.LogError(err) {
		return nil
	}

	return info
}
