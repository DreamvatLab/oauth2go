package redis

import (
	"strings"
	"testing"
)

// The Redis key must be the prefix plus the SHA-256 (base64url) digest of the refresh token,
// never the token itself. The expected value is shared with oauth2net's test.
func TestRedisTokenStore_KeyIsHashOfRefreshToken(t *testing.T) {
	s := &RedisTokenStore{Prefix: "t:"}

	got := s.key("abc")

	if got != "t:ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0" {
		t.Fatalf("unexpected key %q", got)
	}

	const token = "not-a-real-refresh-token-0123456789-abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTU"
	if k := s.key(token); strings.Contains(k, token) {
		t.Fatalf("key %q must not contain the raw refresh token", k)
	}
}
