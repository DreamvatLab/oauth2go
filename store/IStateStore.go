package store

import (
	"time"

	"github.com/DreamvatLab/go/xerr"
	"github.com/muesli/cache2go"
)

const _clientStateKey = "ClientState"

type IStateStore interface {
	Save(key, value string, expireSeconds int)
	GetThenRemove(key string) string
}

func NewDefaultStateStore() IStateStore {
	cache := cache2go.Cache(_clientStateKey)

	return &DefaultStateStore{
		cache: cache,
	}
}

type DefaultStateStore struct {
	cache *cache2go.CacheTable
}

// Save client state to memory.
// This default in memory store doesn't encrypt state.
// Encryption is an option for security enhancement,
// you can implement your own store to do that.
func (x *DefaultStateStore) Save(key, value string, expireSeconds int) {
	x.cache.Add(key, time.Duration(expireSeconds)*time.Second, value)
}

func (x *DefaultStateStore) GetThenRemove(key string) string {
	cacheItem, err := x.cache.Delete(key)
	if err == cache2go.ErrKeyNotFound || xerr.LogError(err) {
		return ""
	}

	r := cacheItem.Data()

	return r.(string)
}
