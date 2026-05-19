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

func NewRedisStateStore(prefix string, secretEncryptor security.ISecretEncryptor, config *xredis.RedisConfig) store.IStateStore {
	return &RedisStateStore{
		Prefix:          prefix,
		SecretEncryptor: secretEncryptor,
		RedisClient:     xredis.NewClient(config),
	}
}

func (x *RedisStateStore) Save(key, value string, expireSeconds int) {
	err := x.RedisClient.Set(context.Background(), x.Prefix+key, value, time.Duration(expireSeconds)*time.Second).Err()
	xerr.LogError(err)
}
func (x *RedisStateStore) GetThenRemove(key string) string {
	// Atomic read+delete (Redis 6.2+ GETDEL) — prevents the state value from being
	// observed and consumed twice in concurrent end-session flows.
	r, err := x.RedisClient.GetDel(context.Background(), x.Prefix+key).Result()
	if err != nil {
		if err == redis.Nil {
			return ""
		}
		xerr.LogError(err)
		return ""
	}
	return r
}
