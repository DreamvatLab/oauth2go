package redis

import (
	"context"
	"encoding/json"

	"github.com/DreamvatLab/go/xbytes"
	"github.com/DreamvatLab/go/xerr"
	"github.com/DreamvatLab/go/xhttp"
	"github.com/DreamvatLab/go/xlog"
	"github.com/DreamvatLab/go/xredis"
	"github.com/DreamvatLab/oauth2go/model"
	"github.com/DreamvatLab/oauth2go/security"
	"github.com/DreamvatLab/oauth2go/store"
	"github.com/redis/go-redis/v9"
)

type RedisClientStore struct {
	Key             string
	SecretEncryptor security.ISecretEncryptor
	RedisClient     redis.UniversalClient
}

func NewRedisClientStore(key string, secretEncryptor security.ISecretEncryptor, config *xredis.RedisConfig) store.IClientStore {
	return &RedisClientStore{
		Key:             key,
		SecretEncryptor: secretEncryptor,
		RedisClient:     xredis.NewClient(config),
	}
}

func (x *RedisClientStore) GetClient(clientID string) model.IClient {
	jsonBytes, err := x.RedisClient.HGet(context.Background(), x.Key, clientID).Bytes()
	if err != nil {
		if err.Error() == "redis: nil" {
			xlog.Warnf("client id: '%s' doesn't exist.", clientID)
			return nil
		}
		xlog.Error(err)
		return nil
	}

	var client *model.Client
	err = json.Unmarshal(jsonBytes, &client)
	if xerr.LogError(err) {
		return nil
	}

	if xhttp.IsBase64String(client.Secret) {
		client.Secret = x.SecretEncryptor.DecryptStringToString(client.Secret)
	}

	return client
}

func (x *RedisClientStore) GetClients() map[string]model.IClient {
	maps, err := x.RedisClient.HGetAll(context.Background(), x.Key).Result()
	if xerr.LogError(err) {
		return nil
	}

	r := make(map[string]model.IClient, len(maps))

	for k, v := range maps {
		var client *model.Client
		err = json.Unmarshal(xbytes.StrToBytes(v), &client)
		if xerr.LogError(err) {
			return nil
		}
		client.Secret = x.SecretEncryptor.DecryptStringToString(client.Secret)
		r[k] = client
	}

	return r
}

func (x *RedisClientStore) Verify(clientID, clientSecret string) model.IClient {
	client := x.GetClient(clientID)
	if client == nil || client.GetSecret() != clientSecret {
		return nil
	}

	return client
}
