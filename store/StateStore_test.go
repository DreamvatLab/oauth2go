package store

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDefaultStateStore_SaveThenGetRemoves(t *testing.T) {
	s := NewDefaultStateStore()
	s.Save("k1", "v1", 60)

	got := s.GetThenRemove("k1")
	assert.Equal(t, "v1", got)

	// second read must be empty — the value has been consumed.
	again := s.GetThenRemove("k1")
	assert.Equal(t, "", again)
}

func TestDefaultStateStore_MissingKey(t *testing.T) {
	s := NewDefaultStateStore()
	assert.Equal(t, "", s.GetThenRemove("nope"))
}

func TestDefaultStateStore_Expire(t *testing.T) {
	s := NewDefaultStateStore()
	s.Save("k2", "v2", 1)
	time.Sleep(1500 * time.Millisecond)
	assert.Equal(t, "", s.GetThenRemove("k2"))
}
