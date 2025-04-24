package redis

import (
	"context"
	"encoding/json"
	"time"

	"github.com/DreamvatLab/go/xerr"
	"github.com/DreamvatLab/go/xredis"
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
func (x *RedisTokenStore) SaveRefreshToken(refreshToken string, requestInfo *model.TokenInfo, expireSeconds int32) {
	// serialize to json
	bytes, err := json.Marshal(requestInfo)
	if xerr.LogError(err) {
		return
	}

	// encrypt
	encodedRefreshToken := x.SecretEncryptor.EncryptBytesToString(bytes)

	// save to redis
	err = x.RedisClient.Set(context.Background(), x.Prefix+refreshToken, encodedRefreshToken, time.Second*time.Duration(expireSeconds)).Err()
	xerr.LogError(err)
}
func (x *RedisTokenStore) RemoveRefreshToken(refreshToken string) {
	err := x.RedisClient.Del(context.Background(), x.Prefix+refreshToken).Err()
	xerr.LogError(err)
}
func (x *RedisTokenStore) GetThenRemoveTokenInfo(refreshToken string) *model.TokenInfo {
	key := x.Prefix + refreshToken

	// get from redis
	str, err := x.RedisClient.Get(context.Background(), key).Result()
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

	// delete used token
	err = x.RedisClient.Del(context.Background(), key).Err()
	xerr.LogError(err)

	return info
}
