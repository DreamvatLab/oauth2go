package store

import (
	"testing"
	"time"

	"github.com/DreamvatLab/oauth2go/model"
	"github.com/stretchr/testify/assert"
)

func TestDefaultAuthorizationCodeStore(t *testing.T) {
	code := "abc"
	a := &model.TokenInfo{ClientID: "test"}
	store := NewDefaultAuthorizationCodeStore(3)
	store.Save(code, a)

	b := store.GetThenRemove(code)
	assert.Equal(t, a.ClientID, b.ClientID)
}

func TestDefaultAuthorizationCodeStore_Expire(t *testing.T) {
	code := "def"
	a := &model.TokenInfo{ClientID: "test"}
	store := NewDefaultAuthorizationCodeStore(1)
	store.Save(code, a)

	time.Sleep(time.Second * 2)

	b := store.GetThenRemove(code)
	assert.Nil(t, b)
}
