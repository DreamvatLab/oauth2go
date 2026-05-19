package oauth2go

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"

	"github.com/DreamvatLab/oauth2go/core"
	"github.com/DreamvatLab/oauth2go/model"
	"github.com/DreamvatLab/oauth2go/security"
	"github.com/DreamvatLab/oauth2go/store"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
)

// =====================================================================
//   fakes / helpers
// =====================================================================

type fakeClientStore struct{ c model.IClient }

func (s *fakeClientStore) GetClient(id string) model.IClient {
	if s.c != nil && s.c.GetID() == id {
		return s.c
	}
	return nil
}

type fakeTokenStore struct {
	Removed []string
	Saved   map[string]*model.TokenInfo
}

func (s *fakeTokenStore) RemoveRefreshToken(rt string) { s.Removed = append(s.Removed, rt) }
func (s *fakeTokenStore) SaveRefreshToken(rt string, info *model.TokenInfo, exp int32) {
	if s.Saved == nil {
		s.Saved = map[string]*model.TokenInfo{}
	}
	s.Saved[rt] = info
}
func (s *fakeTokenStore) GetThenRemoveTokenInfo(rt string) *model.TokenInfo { return nil }

type fakeAuthCodeStore struct {
	Saved map[string]*model.TokenInfo
}

func (s *fakeAuthCodeStore) Save(code string, info *model.TokenInfo) {
	if s.Saved == nil {
		s.Saved = map[string]*model.TokenInfo{}
	}
	s.Saved[code] = info
}
func (s *fakeAuthCodeStore) GetThenRemove(code string) *model.TokenInfo {
	info := s.Saved[code]
	delete(s.Saved, code)
	return info
}

type fakeTokenGenerator struct{ Access string }

func (g *fakeTokenGenerator) GenerateAccessToken(ctx *fasthttp.RequestCtx, grantType string, client model.IClient, scopes []string, username string) (string, error) {
	return g.Access, nil
}
func (g *fakeTokenGenerator) GenerateRefreshToken() string { return "fake-refresh" }

type fakeAuthCodeGenerator struct{ Code string }

func (g *fakeAuthCodeGenerator) Generate() string { return g.Code }

type fakeClaimsGenerator struct{}

func (g *fakeClaimsGenerator) Generate(grantType string, client model.IClient, scopes []string, username string) *map[string]interface{} {
	m := map[string]interface{}{"sub": username}
	return &m
}

// fakeCookieEncryptor passes the value through unchanged so handler tests can
// preset an "authenticated" user via a raw cookie without dealing with
// gorilla/securecookie key material.
type fakeCookieEncryptor struct{}

func (e *fakeCookieEncryptor) Encrypt(name string, value interface{}) (string, error) {
	if s, ok := value.(string); ok {
		return s, nil
	}
	return "", errors.New("only string supported in fake")
}
func (e *fakeCookieEncryptor) Decrypt(name, value string, dst interface{}) error {
	if p, ok := dst.(*string); ok {
		*p = value
		return nil
	}
	return errors.New("only *string supported in fake")
}

func newClient(grants ...string) *model.Client {
	if len(grants) == 0 {
		grants = []string{core.GrantType_AuthorizationCode, core.GrantType_Implicit, core.GrantType_RefreshToken}
	}
	return &model.Client{
		ID:                        "c1",
		Secret:                    "s1",
		AccessTokenExpireSeconds:  3600,
		RefreshTokenExpireSeconds: 7200,
		Grants:                    grants,
		Scopes:                    []string{"read", "write"},
		RedirectUris:              []string{"https://app.example/cb"},
	}
}

func newHost(t *testing.T, c model.IClient) (*TokenHost, *fakeAuthCodeStore, *fakeTokenStore, *fakeTokenGenerator, *fakeAuthCodeGenerator) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	codeStore := &fakeAuthCodeStore{}
	tokStore := &fakeTokenStore{}
	tokGen := &fakeTokenGenerator{Access: "the-access-token"}
	codeGen := &fakeAuthCodeGenerator{Code: "the-code"}

	h := &TokenHost{
		AuthCookieName:         "go.auth",
		PkceRequired:           true,
		PrivateKey:             key,
		ClientStore:            &fakeClientStore{c: c},
		TokenStore:             tokStore,
		AuthorizationCodeStore: codeStore,
		StateStore:             store.NewDefaultStateStore(),
		ClientValidator:        security.NewDefaultClientValidator(&fakeClientStore{c: c}),
		PkceValidator:          security.NewDefaultPkceValidator(),
		ResourceOwnerValidator: security.NewDefaultResourceOwnerValidator(),
		AuthCodeGenerator:      codeGen,
		TokenGenerator:         tokGen,
		ClaimsGenerator:        &fakeClaimsGenerator{},
		CookieEncryptor:        &fakeCookieEncryptor{},
	}
	h.BuildTokenHost()
	return h, codeStore, tokStore, tokGen, codeGen
}

// newAuthorizeCtx builds a *fasthttp.RequestCtx with the supplied query string
// and pretends the user "alice" is already logged in via the auth cookie.
func newAuthorizeCtx(query map[string]string) *fasthttp.RequestCtx {
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod("GET")
	args := fasthttp.AcquireArgs()
	defer fasthttp.ReleaseArgs(args)
	for k, v := range query {
		args.Set(k, v)
	}
	ctx.Request.SetRequestURI("/connect/authorize?" + string(args.QueryString()))
	ctx.Request.Header.SetCookie("go.auth", "alice")
	return ctx
}

func newFormCtx(form map[string]string) *fasthttp.RequestCtx {
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod("POST")
	ctx.Request.Header.SetContentType("application/x-www-form-urlencoded")
	args := fasthttp.AcquireArgs()
	defer fasthttp.ReleaseArgs(args)
	for k, v := range form {
		args.Set(k, v)
	}
	ctx.Request.SetBody(args.QueryString())
	return ctx
}

func location(t *testing.T, ctx *fasthttp.RequestCtx) string {
	t.Helper()
	return string(ctx.Response.Header.Peek("Location"))
}

// =====================================================================
//   C-1: implicit flow returns tokens via URL fragment, not query
// =====================================================================

func TestImplicit_AccessTokenInFragment(t *testing.T) {
	c := newClient(core.GrantType_Implicit)
	h, _, _, _, _ := newHost(t, c)

	ctx := newAuthorizeCtx(map[string]string{
		core.Form_ResponseType: core.ResponseType_Token,
		core.Form_ClientID:     c.GetID(),
		core.Form_RedirectUri:  "https://app.example/cb",
		core.Form_Scope:        "read",
		core.Form_State:        "st-1",
	})

	h.AuthorizeRequestHandler(ctx)

	loc := location(t, ctx)
	assert.True(t, strings.HasPrefix(loc, "https://app.example/cb#"),
		"implicit grant MUST use URL fragment (RFC 6749 §4.2.2), got %q", loc)
	hashIdx := strings.Index(loc, "#")
	queryPart := loc[:hashIdx]
	assert.NotContains(t, queryPart, "?", "no token data in query")
	assert.Contains(t, loc, "access_token=the-access-token")
	assert.Contains(t, loc, "token_type=Bearer")
	assert.Contains(t, loc, "state=st-1")
}

// =====================================================================
//   H-1: PKCE defaults to S256; plain rejected unless opted in; redirect
//        does not echo code_challenge.
// =====================================================================

func TestAuthCode_PkceMethodMissing_DefaultsToS256(t *testing.T) {
	c := newClient(core.GrantType_AuthorizationCode)
	h, codeStore, _, _, _ := newHost(t, c)

	ctx := newAuthorizeCtx(map[string]string{
		core.Form_ResponseType:   core.ResponseType_Code,
		core.Form_ClientID:       c.GetID(),
		core.Form_RedirectUri:    "https://app.example/cb",
		core.Form_Scope:          "read",
		core.Form_State:          "st-1",
		core.Form_CodeChallenge:  "challenge",
		// code_challenge_method intentionally omitted
	})

	h.AuthorizeRequestHandler(ctx)

	saved := codeStore.Saved["the-code"]
	if assert.NotNil(t, saved, "code must be issued; status=%d body=%s", ctx.Response.StatusCode(), ctx.Response.Body()) {
		assert.Equal(t, core.Pkce_S256, saved.CodeChallengeMethod)
	}
}

func TestAuthCode_PkcePlain_RejectedByDefault(t *testing.T) {
	c := newClient(core.GrantType_AuthorizationCode)
	h, _, _, _, _ := newHost(t, c)

	ctx := newAuthorizeCtx(map[string]string{
		core.Form_ResponseType:        core.ResponseType_Code,
		core.Form_ClientID:            c.GetID(),
		core.Form_RedirectUri:         "https://app.example/cb",
		core.Form_Scope:               "read",
		core.Form_State:               "st-1",
		core.Form_CodeChallenge:       "challenge",
		core.Form_CodeChallengeMethod: core.Pkce_Plain,
	})

	h.AuthorizeRequestHandler(ctx)

	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
	body := string(ctx.Response.Body())
	assert.Contains(t, body, core.Err_invalid_request)
	assert.Contains(t, body, "plain")
}

func TestAuthCode_PkcePlain_AllowedWhenAllowPlainPkce(t *testing.T) {
	c := newClient(core.GrantType_AuthorizationCode)
	h, codeStore, _, _, _ := newHost(t, c)
	h.AllowPlainPkce = true

	ctx := newAuthorizeCtx(map[string]string{
		core.Form_ResponseType:        core.ResponseType_Code,
		core.Form_ClientID:            c.GetID(),
		core.Form_RedirectUri:         "https://app.example/cb",
		core.Form_Scope:               "read",
		core.Form_State:               "st-1",
		core.Form_CodeChallenge:       "challenge",
		core.Form_CodeChallengeMethod: core.Pkce_Plain,
	})

	h.AuthorizeRequestHandler(ctx)

	saved := codeStore.Saved["the-code"]
	if assert.NotNil(t, saved, "code must be issued; status=%d body=%s", ctx.Response.StatusCode(), ctx.Response.Body()) {
		assert.Equal(t, core.Pkce_Plain, saved.CodeChallengeMethod)
	}
}

func TestAuthCode_RedirectDoesNotEchoChallenge(t *testing.T) {
	c := newClient(core.GrantType_AuthorizationCode)
	h, _, _, _, _ := newHost(t, c)

	ctx := newAuthorizeCtx(map[string]string{
		core.Form_ResponseType:        core.ResponseType_Code,
		core.Form_ClientID:            c.GetID(),
		core.Form_RedirectUri:         "https://app.example/cb",
		core.Form_Scope:               "read",
		core.Form_State:               "st-1",
		core.Form_CodeChallenge:       "the-challenge-secret",
		core.Form_CodeChallengeMethod: core.Pkce_S256,
	})

	h.AuthorizeRequestHandler(ctx)

	loc := location(t, ctx)
	assert.Contains(t, loc, "code=the-code")
	assert.Contains(t, loc, "state=st-1")
	assert.NotContains(t, loc, "the-challenge-secret",
		"code_challenge must NOT be echoed in the authorization response (RFC 6749 §4.1.2)")
	assert.NotContains(t, loc, core.Form_CodeChallenge)
	assert.NotContains(t, loc, core.Form_CodeChallengeMethod)
}

// =====================================================================
//   H-5: redirect URI with existing query string is appended with '&'
// =====================================================================

func TestAuthCode_RedirectURIWithExistingQueryGetsAmpersand(t *testing.T) {
	c := newClient(core.GrantType_AuthorizationCode)
	// override RedirectUris to include a query string
	c.RedirectUris = []string{"https://app.example/cb?keep=1"}
	h, _, _, _, _ := newHost(t, c)
	h.PkceRequired = false

	ctx := newAuthorizeCtx(map[string]string{
		core.Form_ResponseType: core.ResponseType_Code,
		core.Form_ClientID:     c.GetID(),
		core.Form_RedirectUri:  "https://app.example/cb?keep=1",
		core.Form_Scope:        "read",
		core.Form_State:        "st-1",
	})

	h.AuthorizeRequestHandler(ctx)

	loc := location(t, ctx)
	assert.True(t, strings.HasPrefix(loc, "https://app.example/cb?keep=1&code="),
		"existing query must be preserved with '&' separator, got %q", loc)
	// the redirect URI must NOT contain two '?' separators
	assert.Equal(t, 1, strings.Count(loc, "?"))
}

// =====================================================================
//   M-3: clear_token endpoint writes 200 OK on success
// =====================================================================

func TestClearToken_HappyPath_Writes200(t *testing.T) {
	c := newClient()
	h, _, tokStore, _, _ := newHost(t, c)

	// pre-seed a state that matches the (clientID + ":" + endSessionID) key.
	h.StateStore.Save(c.GetID()+":es-1", "st-1", 60)

	ctx := newFormCtx(map[string]string{
		core.Form_ClientID:     c.GetID(),
		core.Form_ClientSecret: c.GetSecret(),
		core.Form_State:        "st-1",
		core.Form_EndSessionID: "es-1",
		core.Form_RefreshToken: "rt-abc",
	})

	h.ClearTokenRequestHandler(ctx)

	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	assert.Contains(t, tokStore.Removed, "rt-abc")
}

func TestClearToken_RejectsBadState(t *testing.T) {
	c := newClient()
	h, _, _, _, _ := newHost(t, c)
	h.StateStore.Save(c.GetID()+":es-1", "st-1", 60)

	ctx := newFormCtx(map[string]string{
		core.Form_ClientID:     c.GetID(),
		core.Form_ClientSecret: c.GetSecret(),
		core.Form_State:        "wrong",
		core.Form_EndSessionID: "es-1",
		core.Form_RefreshToken: "rt-abc",
	})

	h.ClearTokenRequestHandler(ctx)

	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
}

// =====================================================================
//   /token grants — exercises writeToken and issueTokenByRequestInfo
// =====================================================================

func TestTokenEndpoint_ClientCredentialsGrant_WritesJSONToken(t *testing.T) {
	c := newClient(core.GrantType_Client)
	h, _, _, _, _ := newHost(t, c)

	ctx := newFormCtx(map[string]string{
		core.Form_GrantType:    core.GrantType_Client,
		core.Form_ClientID:     c.GetID(),
		core.Form_ClientSecret: c.GetSecret(),
		core.Form_Scope:        "read",
	})

	h.TokenRequestHandler(ctx)

	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	body := string(ctx.Response.Body())
	assert.Contains(t, body, `"access_token":"the-access-token"`)
	assert.Contains(t, body, `"token_type":"Bearer"`)
	// client_credentials does not issue a refresh token
	assert.NotContains(t, body, `"refresh_token":`)
}

func TestTokenEndpoint_AuthorizationCodeGrant_ExchangesCodeForToken(t *testing.T) {
	c := newClient(core.GrantType_AuthorizationCode, core.GrantType_RefreshToken)
	h, codeStore, tokStore, _, _ := newHost(t, c)
	h.PkceRequired = false

	// pre-seed an authorization code as if /authorize had been called
	codeStore.Save("the-code", &model.TokenInfo{
		ClientID:    c.GetID(),
		Scopes:      "read",
		RedirectUri: "https://app.example/cb",
		Username:    "alice",
	})

	ctx := newFormCtx(map[string]string{
		core.Form_GrantType:    core.GrantType_AuthorizationCode,
		core.Form_ClientID:     c.GetID(),
		core.Form_ClientSecret: c.GetSecret(),
		core.Form_Code:         "the-code",
		core.Form_RedirectUri:  "https://app.example/cb",
	})

	h.TokenRequestHandler(ctx)

	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	body := string(ctx.Response.Body())
	assert.Contains(t, body, `"access_token":"the-access-token"`)
	assert.Contains(t, body, `"refresh_token":"fake-refresh"`)
	assert.NotNil(t, tokStore.Saved["fake-refresh"], "refresh token info must be persisted")
}

// alwaysValidResourceOwner accepts any (user, pass) — used to exercise the
// password grant path.
type alwaysValidResourceOwner struct{}

func (alwaysValidResourceOwner) Verify(u, p string) (bool, error) { return true, nil }

func TestTokenEndpoint_PasswordGrant_HappyPath(t *testing.T) {
	c := newClient(core.GrantType_ResourceOwner)
	h, _, _, _, _ := newHost(t, c)
	h.ResourceOwnerValidator = alwaysValidResourceOwner{}

	ctx := newFormCtx(map[string]string{
		core.Form_GrantType:    core.GrantType_ResourceOwner,
		core.Form_ClientID:     c.GetID(),
		core.Form_ClientSecret: c.GetSecret(),
		core.Form_Scope:        "read",
		core.Form_Username:     "alice",
		core.Form_Password:     "pw",
	})

	h.TokenRequestHandler(ctx)

	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	assert.Contains(t, string(ctx.Response.Body()), `"access_token":"the-access-token"`)
}

func TestTokenEndpoint_PasswordGrant_RejectsBadCredentials(t *testing.T) {
	c := newClient(core.GrantType_ResourceOwner)
	h, _, _, _, _ := newHost(t, c)
	// default validator returns (false, nil) — no resource-owner is ever valid

	ctx := newFormCtx(map[string]string{
		core.Form_GrantType:    core.GrantType_ResourceOwner,
		core.Form_ClientID:     c.GetID(),
		core.Form_ClientSecret: c.GetSecret(),
		core.Form_Scope:        "read",
		core.Form_Username:     "alice",
		core.Form_Password:     "pw",
	})

	h.TokenRequestHandler(ctx)

	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
	assert.Contains(t, string(ctx.Response.Body()), core.Err_invalid_grant)
}

func TestTokenEndpoint_RefreshTokenGrant_RotatesToken(t *testing.T) {
	c := newClient(core.GrantType_AuthorizationCode, core.GrantType_RefreshToken)
	h, _, tokStore, _, _ := newHost(t, c)
	// fakeTokenStore.GetThenRemoveTokenInfo returns nil — swap it for one that
	// actually returns a record, so refresh succeeds.
	tokStore2 := &refreshableTokenStore{
		info: &model.TokenInfo{
			ClientID: c.GetID(),
			Scopes:   "read",
			Username: "alice",
		},
		fakeTokenStore: tokStore,
	}
	h.TokenStore = tokStore2

	ctx := newFormCtx(map[string]string{
		core.Form_GrantType:    core.GrantType_RefreshToken,
		core.Form_ClientID:     c.GetID(),
		core.Form_ClientSecret: c.GetSecret(),
		core.Form_RefreshToken: "old-rt",
	})

	h.TokenRequestHandler(ctx)

	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	body := string(ctx.Response.Body())
	assert.Contains(t, body, `"access_token":"the-access-token"`)
	assert.Contains(t, body, `"refresh_token":"fake-refresh"`)
}

type refreshableTokenStore struct {
	*fakeTokenStore
	info *model.TokenInfo
}

func (s *refreshableTokenStore) GetThenRemoveTokenInfo(rt string) *model.TokenInfo {
	return s.info
}

func TestTokenEndpoint_AuthorizationCodeGrant_PkceMismatchFails(t *testing.T) {
	c := newClient(core.GrantType_AuthorizationCode)
	h, codeStore, _, _, _ := newHost(t, c)

	// stored challenge expects verifier hashing to "stored-challenge"; we'll
	// supply a verifier whose SHA-256 doesn't match.
	codeStore.Save("the-code", &model.TokenInfo{
		ClientID:            c.GetID(),
		Scopes:              "read",
		RedirectUri:         "https://app.example/cb",
		Username:            "alice",
		CodeChallenge:       "stored-challenge-not-matching",
		CodeChallengeMethod: core.Pkce_S256,
	})

	ctx := newFormCtx(map[string]string{
		core.Form_GrantType:    core.GrantType_AuthorizationCode,
		core.Form_ClientID:     c.GetID(),
		core.Form_ClientSecret: c.GetSecret(),
		core.Form_Code:         "the-code",
		core.Form_RedirectUri:  "https://app.example/cb",
		core.Form_CodeVerifier: strings.Repeat("a", 43),
	})

	h.TokenRequestHandler(ctx)

	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
	assert.Contains(t, string(ctx.Response.Body()), core.Err_invalid_grant)
}

// =====================================================================
//   EndSessionRequestHandler — happy path
// =====================================================================

func TestEndSession_HappyPath(t *testing.T) {
	c := newClient()
	h, _, _, _, _ := newHost(t, c)

	ctx := newAuthorizeCtx(map[string]string{
		core.Form_ClientID:    c.GetID(),
		core.Form_RedirectUri: "https://app.example/cb",
		core.Form_State:       "st-end",
	})

	h.EndSessionRequestHandler(ctx)

	assert.Equal(t, fasthttp.StatusFound, ctx.Response.StatusCode())
	loc := location(t, ctx)
	assert.True(t, strings.HasPrefix(loc, "https://app.example/cb?"), "got %q", loc)
	assert.Contains(t, loc, "state=st-end")
	assert.Contains(t, loc, core.Form_EndSessionID+"=")
}

// =====================================================================
//   token endpoint: error response is well-formed JSON (M-7)
// =====================================================================

func TestTokenEndpoint_UnsupportedGrant_ReturnsJSONError(t *testing.T) {
	c := newClient()
	h, _, _, _, _ := newHost(t, c)

	ctx := newFormCtx(map[string]string{
		core.Form_GrantType:    "no-such-grant",
		core.Form_ClientID:     c.GetID(),
		core.Form_ClientSecret: c.GetSecret(),
		core.Form_Scope:        "read",
	})

	h.TokenRequestHandler(ctx)

	body := string(ctx.Response.Body())
	assert.Contains(t, body, `"error":`)
	assert.Contains(t, body, `"error_description":`)
}

// =====================================================================
//   missing state on /authorize is non-fatal (M-1 — warns, does not block)
// =====================================================================

func TestAuthorize_MissingState_StillProceeds(t *testing.T) {
	c := newClient(core.GrantType_Implicit)
	h, _, _, _, _ := newHost(t, c)

	ctx := newAuthorizeCtx(map[string]string{
		core.Form_ResponseType: core.ResponseType_Token,
		core.Form_ClientID:     c.GetID(),
		core.Form_RedirectUri:  "https://app.example/cb",
		core.Form_Scope:        "read",
		// state intentionally omitted
	})

	h.AuthorizeRequestHandler(ctx)

	// status should be 302 (redirect to client) — missing state warns but
	// must not break the flow.
	assert.Equal(t, fasthttp.StatusFound, ctx.Response.StatusCode())
	assert.True(t, strings.HasPrefix(location(t, ctx), "https://app.example/cb#"))
}
