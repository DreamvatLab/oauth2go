package rsa

import (
	cryptorand "crypto/rand"
	cryptorsa "crypto/rsa"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

// newTestEncryptor returns an encryptor backed by a freshly generated 2048-bit
// RSA key, so the tests don't need an on-disk fixture.
func newTestEncryptor(t *testing.T) *RSASecretEncryptor {
	t.Helper()
	key, err := cryptorsa.GenerateKey(cryptorand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return &RSASecretEncryptor{key: key}
}

// ---------- C-4 roundtrip: OAEP-SHA256 in both directions ----------

func TestRSASecretEncryptor_StringRoundtrip(t *testing.T) {
	e := newTestEncryptor(t)

	encrypted := e.EncryptStringToString("hello world")
	assert.NotEmpty(t, encrypted)
	assert.NotEqual(t, "hello world", encrypted)
	// must be a valid base64 string
	_, err := base64.StdEncoding.DecodeString(encrypted)
	assert.NoError(t, err)

	decrypted := e.DecryptStringToString(encrypted)
	assert.Equal(t, "hello world", decrypted)
}

func TestRSASecretEncryptor_BytesToString_Roundtrip(t *testing.T) {
	e := newTestEncryptor(t)
	plain := []byte{0x01, 0x02, 0x03, 0xff}

	encrypted := e.EncryptBytesToString(plain)
	got := e.DecryptStringToBytes(encrypted)
	assert.Equal(t, plain, got)
}

func TestRSASecretEncryptor_BytesToBytes_Roundtrip(t *testing.T) {
	e := newTestEncryptor(t)
	plain := []byte("payload")

	cipher := e.EncryptBytesToBytes(plain)
	got := e.DecryptBytesToBytes(cipher)
	assert.Equal(t, plain, got)
}

// ---------- C-4 negative: PKCS#1 v1.5 ciphertext must fail under OAEP-SHA256 ----------

func TestRSASecretEncryptor_RejectsPKCS1v15Ciphertext(t *testing.T) {
	e := newTestEncryptor(t)

	// Encrypt with the legacy PKCS#1 v1.5 padding directly against the same key
	// — this is the format produced by v1.x of the library.
	legacy, err := cryptorsa.EncryptPKCS1v15(cryptorand.Reader, &e.key.PublicKey, []byte("legacy-secret"))
	if err != nil {
		t.Fatalf("pkcs1v15 encrypt: %v", err)
	}

	// OAEP decrypt of PKCS#1-v15 ciphertext must NOT yield the plaintext.
	got := e.DecryptBytesToBytes(legacy)
	assert.NotEqual(t, []byte("legacy-secret"), got, "PKCS#1 v1.5 ciphertext must not decrypt under OAEP-SHA256")
}

// ---------- C-4 negative: garbage input ----------

func TestRSASecretEncryptor_DecryptInvalidBase64_ReturnsInput(t *testing.T) {
	// Documented fallback: when input is not valid base64, the decrypt-string
	// methods return the input unchanged (they log the error). This isn't a
	// security property but locks the contract so callers can detect failure.
	e := newTestEncryptor(t)
	assert.Equal(t, "!!!not-base64!!!", e.DecryptStringToString("!!!not-base64!!!"))
}

func TestRSASecretEncryptor_OAEPCiphertextIsNondeterministic(t *testing.T) {
	// OAEP includes randomness, so encrypting the same input twice MUST yield
	// different ciphertexts — guards against an accidental "deterministic"
	// regression.
	e := newTestEncryptor(t)
	a := e.EncryptStringToString("same")
	b := e.EncryptStringToString("same")
	assert.NotEqual(t, a, b)
}
