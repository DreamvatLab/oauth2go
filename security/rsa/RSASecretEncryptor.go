package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"

	"github.com/DreamvatLab/go/xbytes"
	"github.com/DreamvatLab/go/xerr"
	"github.com/DreamvatLab/go/xsecurity"
	"github.com/DreamvatLab/oauth2go/security"
)

// RSASecretEncryptor encrypts/decrypts secrets with RSA-OAEP using SHA-256.
//
// PKCS#1 v1.5 padding (the previous implementation) has known padding-oracle
// attack surface (Bleichenbacher 1998) — OAEP-SHA256 is the modern replacement.
//
// Capacity caveat: ciphertext output is base64(rsa-encrypt(plain)). Maximum
// plaintext size = keySize − 2·hLen − 2 bytes (with hLen=32 for SHA-256), i.e.
// ~190 bytes for RSA-2048, ~318 for RSA-3072, ~446 for RSA-4096.
type RSASecretEncryptor struct {
	key *rsa.PrivateKey
}

func NewRSASecretEncryptor(certPath string) security.ISecretEncryptor {
	rsaEncryptor, err := xsecurity.CreateRSAEncryptorFromFile(certPath)
	xerr.FatalIfErr(err)

	return &RSASecretEncryptor{
		key: rsaEncryptor.Key,
	}
}

func (x *RSASecretEncryptor) encrypt(plain []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, &x.key.PublicKey, plain, nil)
}

func (x *RSASecretEncryptor) decrypt(cipher []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, x.key, cipher, nil)
}

func (x *RSASecretEncryptor) EncryptStringToString(input string) string {
	cipher, err := x.encrypt(xbytes.StrToBytes(input))
	if xerr.LogError(err) {
		return input
	}
	return base64.StdEncoding.EncodeToString(cipher)
}

func (x *RSASecretEncryptor) EncryptBytesToString(input []byte) string {
	cipher, err := x.encrypt(input)
	if xerr.LogError(err) {
		return base64.StdEncoding.EncodeToString(input)
	}
	return base64.StdEncoding.EncodeToString(cipher)
}

func (x *RSASecretEncryptor) EncryptBytesToBytes(input []byte) []byte {
	cipher, err := x.encrypt(input)
	if xerr.LogError(err) {
		return input
	}
	return cipher
}

func (x *RSASecretEncryptor) DecryptStringToString(input string) string {
	cipher, err := base64.StdEncoding.DecodeString(input)
	if xerr.LogError(err) {
		return input
	}
	plain, err := x.decrypt(cipher)
	if xerr.LogError(err) {
		return input
	}
	return xbytes.BytesToStr(plain)
}

func (x *RSASecretEncryptor) DecryptBytesToBytes(input []byte) []byte {
	plain, err := x.decrypt(input)
	if xerr.LogError(err) {
		return input
	}
	return plain
}

func (x *RSASecretEncryptor) DecryptStringToBytes(input string) []byte {
	cipher, err := base64.StdEncoding.DecodeString(input)
	if xerr.LogError(err) {
		return xbytes.StrToBytes(input)
	}
	plain, err := x.decrypt(cipher)
	if xerr.LogError(err) {
		return xbytes.StrToBytes(input)
	}
	return plain
}
