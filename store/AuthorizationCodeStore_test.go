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

// TestDefaultAuthorizationCodeStore_ExpiryRejectedEvenIfNotSwept is the H-4
// regression: cache2go only sweeps lazily, so for up to the sweep interval an
// "expired" entry is still present in the underlying map. GetThenRemove must
// re-check expiry on read and refuse to return such an entry.
//
// We can't directly suppress cache2go's sweeper, but reading shortly after the
// TTL elapses exercises the in-handler check (and any race where the sweeper
// has already run just yields the same nil result).
func TestDefaultAuthorizationCodeStore_ExpiryRejectedEvenIfNotSwept(t *testing.T) {
	code := "h4"
	store := NewDefaultAuthorizationCodeStore(1)
	store.Save(code, &model.TokenInfo{ClientID: "test"})

	// 1.05s — just past the 1s TTL.
	time.Sleep(1050 * time.Millisecond)

	assert.Nil(t, store.GetThenRemove(code))
}
