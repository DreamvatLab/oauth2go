package security

import (
	"encoding/base64"
	"testing"

	"github.com/DreamvatLab/oauth2go/core"
	"github.com/DreamvatLab/oauth2go/model"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
)

// fakeClientStore is a minimal in-memory IClientStore for the tests below.
type fakeClientStore struct {
	clients map[string]model.IClient
}

func (s *fakeClientStore) GetClient(id string) model.IClient {
	return s.clients[id]
}

func newClient(id, secret string, opts ...func(*model.Client)) *model.Client {
	c := &model.Client{
		ID:                       id,
		Secret:                   secret,
		AccessTokenExpireSeconds: 3600,
		Grants:                   []string{core.GrantType_Client},
		Scopes:                   []string{"read", "write"},
		RedirectUris:             []string{"https://app.example/cb"},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func newCtxWithAuthHeader(h string) *fasthttp.RequestCtx {
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.Set(core.Header_Authorization, h)
	return ctx
}

func newCtxWithBody(values map[string]string) *fasthttp.RequestCtx {
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod("POST")
	ctx.Request.Header.SetContentType("application/x-www-form-urlencoded")
	args := fasthttp.AcquireArgs()
	defer fasthttp.ReleaseArgs(args)
	for k, v := range values {
		args.Set(k, v)
	}
	ctx.Request.SetBody(args.QueryString())
	return ctx
}

// ---------- Basic auth header extraction (H-3 regressions) ----------

func TestExtractCredentialsFromHeader_HappyPath(t *testing.T) {
	v := NewDefaultClientValidator(&fakeClientStore{}).(*DefaultClientValidator)
	encoded := base64.StdEncoding.EncodeToString([]byte("alice:s3cr3t"))
	ctx := newCtxWithAuthHeader("Basic " + encoded)

	cred, err, _ := v.exractClientCredentialsFromHeader(ctx)
	assert.NoError(t, err)
	assert.Equal(t, "alice", cred.Username)
	assert.Equal(t, "s3cr3t", cred.Password)
}

func TestExtractCredentialsFromHeader_PasswordContainsColon(t *testing.T) {
	// RFC 7617: passwords may legally contain ':'. Splitting on every ':' would
	// truncate the password — must split on the first one only.
	v := NewDefaultClientValidator(&fakeClientStore{}).(*DefaultClientValidator)
	encoded := base64.StdEncoding.EncodeToString([]byte("alice:pa:ss:wd"))
	ctx := newCtxWithAuthHeader("Basic " + encoded)

	cred, err, _ := v.exractClientCredentialsFromHeader(ctx)
	assert.NoError(t, err)
	assert.Equal(t, "alice", cred.Username)
	assert.Equal(t, "pa:ss:wd", cred.Password)
}

func TestExtractCredentialsFromHeader_RejectsBearerScheme(t *testing.T) {
	// "Bearer xxx" must not fall through to Basic decoding.
	v := NewDefaultClientValidator(&fakeClientStore{}).(*DefaultClientValidator)
	ctx := newCtxWithAuthHeader("Bearer some-jwt")

	_, err, errDesc := v.exractClientCredentialsFromHeader(ctx)
	assert.Error(t, err)
	assert.Contains(t, errDesc.Error(), "not Basic")
}

func TestExtractCredentialsFromHeader_CaseInsensitiveScheme(t *testing.T) {
	v := NewDefaultClientValidator(&fakeClientStore{}).(*DefaultClientValidator)
	encoded := base64.StdEncoding.EncodeToString([]byte("alice:s3cr3t"))
	ctx := newCtxWithAuthHeader("basic " + encoded)

	cred, err, _ := v.exractClientCredentialsFromHeader(ctx)
	assert.NoError(t, err)
	assert.Equal(t, "alice", cred.Username)
}

func TestExtractCredentialsFromHeader_RejectsRawBase64Url(t *testing.T) {
	// RFC 7617 mandates STANDARD base64 (with '+', '/', '='). A base64-url
	// string containing '-' or '_' should not be silently accepted.
	v := NewDefaultClientValidator(&fakeClientStore{}).(*DefaultClientValidator)
	// "????:????" -> standard base64 would have '+'/'/' chars. Force an invalid char:
	ctx := newCtxWithAuthHeader("Basic !!!not-base64!!!")

	_, err, _ := v.exractClientCredentialsFromHeader(ctx)
	assert.Error(t, err)
}

func TestExtractCredentialsFromHeader_NoColon(t *testing.T) {
	v := NewDefaultClientValidator(&fakeClientStore{}).(*DefaultClientValidator)
	encoded := base64.StdEncoding.EncodeToString([]byte("nocolonhere"))
	ctx := newCtxWithAuthHeader("Basic " + encoded)

	_, err, _ := v.exractClientCredentialsFromHeader(ctx)
	assert.Error(t, err)
}

func TestExtractCredentialsFromHeader_EmptyHeader(t *testing.T) {
	v := NewDefaultClientValidator(&fakeClientStore{}).(*DefaultClientValidator)
	ctx := &fasthttp.RequestCtx{}

	_, err, errDesc := v.exractClientCredentialsFromHeader(ctx)
	assert.Error(t, err)
	assert.Contains(t, errDesc.Error(), "no authorization")
}

// ---------- Body extraction fallback ----------

func TestExtractCredentials_FallbacksToBody(t *testing.T) {
	v := NewDefaultClientValidator(&fakeClientStore{})
	ctx := newCtxWithBody(map[string]string{
		core.Form_ClientID:     "alice",
		core.Form_ClientSecret: "s3cr3t",
	})

	cred, err, _ := v.ExractClientCredentials(ctx)
	assert.NoError(t, err)
	assert.Equal(t, "alice", cred.Username)
	assert.Equal(t, "s3cr3t", cred.Password)
}

// ---------- VerifyCredential (C-2 constant-time path) ----------

func TestVerifyCredential_MissingClient(t *testing.T) {
	v := NewDefaultClientValidator(&fakeClientStore{clients: map[string]model.IClient{}})
	_, err, _ := v.VerifyCredential(&model.Credential{Username: "ghost", Password: "x"})
	assert.EqualError(t, err, core.Err_invalid_client)
}

func TestVerifyCredential_WrongPassword(t *testing.T) {
	c := newClient("c1", "right")
	v := NewDefaultClientValidator(&fakeClientStore{clients: map[string]model.IClient{"c1": c}})
	_, err, _ := v.VerifyCredential(&model.Credential{Username: "c1", Password: "wrong"})
	assert.EqualError(t, err, core.Err_invalid_client)
}

func TestVerifyCredential_WrongPasswordDifferentLength(t *testing.T) {
	// C-2 regression: length mismatch must be handled (subtle.ConstantTimeCompare
	// returns 0 on length mismatch — we must still reject).
	c := newClient("c1", "right")
	v := NewDefaultClientValidator(&fakeClientStore{clients: map[string]model.IClient{"c1": c}})
	_, err, _ := v.VerifyCredential(&model.Credential{Username: "c1", Password: "r"})
	assert.EqualError(t, err, core.Err_invalid_client)
}

func TestVerifyCredential_RightPassword(t *testing.T) {
	c := newClient("c1", "right")
	v := NewDefaultClientValidator(&fakeClientStore{clients: map[string]model.IClient{"c1": c}})
	got, err, _ := v.VerifyCredential(&model.Credential{Username: "c1", Password: "right"})
	assert.NoError(t, err)
	assert.Equal(t, "c1", got.GetID())
}

func TestVerifyCredential_PublicClientNoSecret(t *testing.T) {
	c := newClient("c1", "right", func(c *model.Client) { c.IsPublic = true })
	v := NewDefaultClientValidator(&fakeClientStore{clients: map[string]model.IClient{"c1": c}})
	got, err, _ := v.VerifyCredential(&model.Credential{Username: "c1", Password: ""})
	assert.NoError(t, err)
	assert.Equal(t, "c1", got.GetID())
}

// ---------- VerifyRespTypeRedirectURIScope ----------

func TestVerifyRespTypeRedirectURIScope_HappyPath(t *testing.T) {
	c := newClient("c1", "s", func(c *model.Client) {
		c.Grants = []string{core.GrantType_AuthorizationCode}
	})
	v := NewDefaultClientValidator(&fakeClientStore{clients: map[string]model.IClient{"c1": c}})
	got, err, _ := v.VerifyRespTypeRedirectURIScope("c1", core.ResponseType_Code, "https://app.example/cb", "read")
	assert.NoError(t, err)
	assert.NotNil(t, got)
}

func TestVerifyRespTypeRedirectURIScope_RejectsUnknownRedirect(t *testing.T) {
	c := newClient("c1", "s")
	v := NewDefaultClientValidator(&fakeClientStore{clients: map[string]model.IClient{"c1": c}})
	_, err, _ := v.VerifyRespTypeRedirectURIScope("c1", core.ResponseType_Code, "https://evil.example/cb", "read")
	assert.Error(t, err)
}

func TestVerifyRespTypeRedirectURIScope_RejectsUnknownScope(t *testing.T) {
	c := newClient("c1", "s")
	v := NewDefaultClientValidator(&fakeClientStore{clients: map[string]model.IClient{"c1": c}})
	_, err, _ := v.VerifyRespTypeRedirectURIScope("c1", core.ResponseType_Code, "https://app.example/cb", "admin")
	assert.Error(t, err)
}

func TestVerifyRespTypeRedirectURIScope_MissingClientID(t *testing.T) {
	v := NewDefaultClientValidator(&fakeClientStore{})
	_, err, _ := v.VerifyRespTypeRedirectURIScope("", core.ResponseType_Code, "https://app.example/cb", "read")
	assert.EqualError(t, err, core.Err_invalid_request)
}

// ---------- VerifyCredentialGrantType / GrantTypeScope ----------

func TestVerifyCredentialGrantType_AllowedGrant(t *testing.T) {
	c := newClient("c1", "s", func(c *model.Client) {
		c.Grants = []string{core.GrantType_Client}
	})
	v := NewDefaultClientValidator(&fakeClientStore{clients: map[string]model.IClient{"c1": c}})
	got, err, _ := v.VerifyCredentialGrantType(&model.Credential{Username: "c1", Password: "s"}, core.GrantType_Client)
	assert.NoError(t, err)
	assert.NotNil(t, got)
}

func TestVerifyCredentialGrantType_DisallowedGrant(t *testing.T) {
	c := newClient("c1", "s", func(c *model.Client) {
		c.Grants = []string{core.GrantType_Client}
	})
	v := NewDefaultClientValidator(&fakeClientStore{clients: map[string]model.IClient{"c1": c}})
	_, err, _ := v.VerifyCredentialGrantType(&model.Credential{Username: "c1", Password: "s"}, core.GrantType_AuthorizationCode)
	assert.EqualError(t, err, core.Err_unauthorized_client)
}

func TestVerifyCredentialGrantType_MissingGrantType(t *testing.T) {
	v := NewDefaultClientValidator(&fakeClientStore{})
	_, err, _ := v.VerifyCredentialGrantType(&model.Credential{Username: "c1", Password: "s"}, "")
	assert.EqualError(t, err, core.Err_invalid_request)
}

func TestVerifyCredentialGrantTypeScope_MissingScope(t *testing.T) {
	v := NewDefaultClientValidator(&fakeClientStore{})
	_, err, _ := v.VerifyCredentialGrantTypeScope(&model.Credential{Username: "c1", Password: "s"}, core.GrantType_Client, "")
	assert.EqualError(t, err, core.Err_invalid_request)
}

// ---------- VerifyRedirectURI ----------

func TestVerifyRedirectURI_HappyPath(t *testing.T) {
	c := newClient("c1", "s")
	v := NewDefaultClientValidator(&fakeClientStore{clients: map[string]model.IClient{"c1": c}})
	got, err, _ := v.VerifyRedirectURI("c1", "https://app.example/cb")
	assert.NoError(t, err)
	assert.NotNil(t, got)
}

func TestVerifyRedirectURI_UnknownClient(t *testing.T) {
	v := NewDefaultClientValidator(&fakeClientStore{clients: map[string]model.IClient{}})
	_, err, _ := v.VerifyRedirectURI("ghost", "https://app.example/cb")
	assert.EqualError(t, err, core.Err_invalid_request)
}

func TestVerifyRedirectURI_MissingClientID(t *testing.T) {
	v := NewDefaultClientValidator(&fakeClientStore{})
	_, err, _ := v.VerifyRedirectURI("", "https://app.example/cb")
	assert.EqualError(t, err, core.Err_invalid_request)
}

func TestVerifyRedirectURI_MissingRedirect(t *testing.T) {
	v := NewDefaultClientValidator(&fakeClientStore{})
	_, err, _ := v.VerifyRedirectURI("c1", "")
	assert.EqualError(t, err, core.Err_invalid_request)
}
