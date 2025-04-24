package redis

import (
	"context"
	"time"

	"github.com/DreamvatLab/go/xerr"
	"github.com/DreamvatLab/go/xredis"
	"github.com/DreamvatLab/oauth2go/security"
	"github.com/DreamvatLab/oauth2go/store"
	"github.com/redis/go-redis/v9"
)

type RedisStateStore struct {
	Prefix          string
	SecretEncryptor security.ISecretEncryptor
	RedisClient     redis.UniversalClient
}

func NewRedisStateStore(prefix string, secretEncryptor security.ISecretEncryptor, config *xredis.RedisConfig) store.ITokenStore {
	return &RedisTokenStore{
		Prefix:          prefix,
		SecretEncryptor: secretEncryptor,
		RedisClient:     xredis.NewClient(config),
	}
}

func (x *RedisStateStore) Save(key, value string, expireSeconds int) {
	err := x.RedisClient.Set(context.Background(), x.Prefix+key, value, time.Duration(expireSeconds)*time.Second).Err()
	xerr.LogError(err)
}
func (x *RedisStateStore) GetThenRemove(key string) (r string) {
	ctx := context.Background()
	key = x.Prefix + key
	r = x.RedisClient.Get(ctx, key).String()
	if r != "" {
		err := x.RedisClient.Del(ctx, key).Err()
		xerr.LogError(err)
	}
	return
}
