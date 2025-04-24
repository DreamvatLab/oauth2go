package rsa

import (
	"encoding/base64"

	"github.com/DreamvatLab/go/xbytes"
	"github.com/DreamvatLab/go/xerr"
	"github.com/DreamvatLab/go/xsecurity"
	"github.com/DreamvatLab/oauth2go/security"
)

type RSASecretEncryptor struct {
	encryptor *xsecurity.RSAEncryptor
}

func NewRSASecretEncryptor(certPath string) security.ISecretEncryptor {
	rsaEncryptor, err := xsecurity.CreateRSAEncryptorFromFile(certPath)
	xerr.FatalIfErr(err)

	return &RSASecretEncryptor{
		encryptor: rsaEncryptor,
	}
}

func (x *RSASecretEncryptor) EncryptStringToString(input string) string {
	r, err := x.encryptor.EncryptString(input)
	if xerr.LogError(err) {
		return input
	}

	return r
}

func (x *RSASecretEncryptor) EncryptBytesToString(input []byte) string {
	r, err := x.encryptor.Encrypt(input)
	if xerr.LogError(err) {
		return base64.StdEncoding.EncodeToString(input)
	}

	return base64.StdEncoding.EncodeToString(r)
}

func (x *RSASecretEncryptor) EncryptBytesToBytes(input []byte) []byte {
	r, err := x.encryptor.Encrypt(input)
	if xerr.LogError(err) {
		return input
	}

	return r
}

func (x *RSASecretEncryptor) DecryptStringToString(input string) string {
	r, err := x.encryptor.DecryptString(input)
	if xerr.LogError(err) {
		return input
	}

	return r
}

func (x *RSASecretEncryptor) DecryptBytesToBytes(input []byte) []byte {
	r, err := x.encryptor.Decrypt(input)
	if xerr.LogError(err) {
		return input
	}

	return r
}

func (x *RSASecretEncryptor) DecryptStringToBytes(input string) []byte {
	bytes, err := base64.StdEncoding.DecodeString(input)
	if xerr.LogError(err) {
		return xbytes.StrToBytes(input)
	}

	r, err := x.encryptor.Decrypt(bytes)
	if xerr.LogError(err) {
		return xbytes.StrToBytes(input)
	}

	return r
}
