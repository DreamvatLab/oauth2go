package store

import (
	"time"

	"github.com/DreamvatLab/go/xerr"
	"github.com/DreamvatLab/oauth2go/model"
	"github.com/muesli/cache2go"
)

const _authCodeKey = "AuthCode"

type IAuthorizationCodeStore interface {
	Save(code string, requestInfo *model.TokenInfo)
	GetThenRemove(code string) *model.TokenInfo
}

func NewDefaultAuthorizationCodeStore(durationSecondes int) IAuthorizationCodeStore {
	cache := cache2go.Cache(_authCodeKey)

	return &DefaultAuthorizationCodeStore{
		cache:    cache,
		duration: time.Second * time.Duration(durationSecondes),
	}
}

type DefaultAuthorizationCodeStore struct {
	cache    *cache2go.CacheTable
	duration time.Duration
}

// Save save request info to memory.
// This default in memory store doesn't encrypt request info.
// Encryption is an option for security enhancement,
// you can implement your own store to do that.
func (x *DefaultAuthorizationCodeStore) Save(code string, requestInfo *model.TokenInfo) {
	x.cache.Add(code, x.duration, requestInfo)
}

func (x *DefaultAuthorizationCodeStore) GetThenRemove(code string) *model.TokenInfo {
	cacheItem, err := x.cache.Delete(code)
	if err == cache2go.ErrKeyNotFound || xerr.LogError(err) {
		return nil
	}

	r := cacheItem.Data()

	return r.(*model.TokenInfo)
}
