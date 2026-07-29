package oauth2go

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/DreamvatLab/go/xbytes"
	"github.com/DreamvatLab/go/xerr"
	"github.com/DreamvatLab/go/xlog"
	"github.com/DreamvatLab/go/xsecurity"
	"github.com/DreamvatLab/go/xutils"
	"github.com/DreamvatLab/oauth2go/core"
	"github.com/DreamvatLab/oauth2go/model"
	"github.com/DreamvatLab/oauth2go/security"
	"github.com/DreamvatLab/oauth2go/store"
	"github.com/DreamvatLab/oauth2go/token"
	"github.com/pascaldekloe/jwt"
	"github.com/valyala/fasthttp"
)

type (
	ITokenHost interface {
		TokenRequestHandler(ctx *fasthttp.RequestCtx)
		AuthorizeRequestHandler(ctx *fasthttp.RequestCtx)
		EndSessionRequestHandler(ctx *fasthttp.RequestCtx)
		ClearTokenRequestHandler(ctx *fasthttp.RequestCtx)
		// GetOptions() *AuthServerOptions
		// GetCookie(ctx *fasthttp.RequestCtx, name string) string
		// SetCookie(ctx *fasthttp.RequestCtx, key, value string, duration time.Duration)
		// DelCookie(ctx *fasthttp.RequestCtx, key string)
	}

	TokenHostOption func(*TokenHost)

	// AuthServerOptions struct {
	// 	AuthCookieName string
	// 	// SurferCookieName       string
	// 	AuthorizeEndpoint      string
	// 	TokenEndpoint          string
	// 	EndSessionEndpoint     string
	// 	LoginEndpoint          string
	// 	LogoutEndpoint         string
	// 	PkceRequired           bool
	// 	CookieManager          *securecookie.SecureCookie
	// 	PrivateKey             *rsa.PrivateKey
	// 	ClientStore            store.IClientStore
	// 	TokenStore             store.ITokenStore
	// 	AuthorizationCodeStore store.IAuthorizationCodeStore
	// 	StateStore             store.IStateStore
	// 	ClientValidator        security.IClientValidator
	// 	PkceValidator          security.IPkceValidator
	// 	ResourceOwnerValidator security.IResourceOwnerValidator
	// 	AuthCodeGenerator      token.IAuthCodeGenerator
	// 	TokenGenerator         token.ITokenGenerator
	// 	ClaimsGenerator        token.ITokenClaimsGenerator
	// }

	TokenHost struct {
		AuthCookieName         string
		AuthorizeEndpoint      string
		TokenEndpoint          string
		EndSessionEndpoint     string
		LoginEndpoint          string
		LogoutEndpoint         string
		PkceRequired           bool
		AllowPlainPkce         bool
		PrivateKey             *rsa.PrivateKey
		ClientStore            store.IClientStore
		TokenStore             store.ITokenStore
		AuthorizationCodeStore store.IAuthorizationCodeStore
		StateStore             store.IStateStore
		ClientValidator        security.IClientValidator
		PkceValidator          security.IPkceValidator
		ResourceOwnerValidator security.IResourceOwnerValidator
		AuthCodeGenerator      token.IAuthCodeGenerator
		TokenGenerator         token.ITokenGenerator
		ClaimsGenerator        token.ITokenClaimsGenerator
		CookieEncryptor        xsecurity.ICookieEncryptor
	}
)

func (x *TokenHost) BuildTokenHost() {
	if x.ClientStore == nil {
		xlog.Fatal("ClientStore cannot be nil")
	}
	if x.TokenStore == nil {
		xlog.Fatal("TokenStore cannot be nil")
	}
	if x.PrivateKey == nil {
		xlog.Fatal("PrivateKey cannot be nil")
	}
	if x.ClaimsGenerator == nil {
		xlog.Fatal("ClaimsGenerator cannot be nil")
	}
	if x.CookieEncryptor == nil {
		xlog.Fatal("CookieEncryptor cannot be nil")
	}
	// if x.CookieProtector == nil {
	// 	xlog.Fatal("CookieManager cannot be nil")
	// }
	if x.AuthCookieName == "" {
		x.AuthCookieName = "go.auth"
	}
	if x.AuthorizeEndpoint == "" {
		x.AuthorizeEndpoint = "/connect/authorize"
	}
	if x.TokenEndpoint == "" {
		x.TokenEndpoint = "/connect/token"
	}
	if x.EndSessionEndpoint == "" {
		x.EndSessionEndpoint = "/connect/endsession"
	}
	if x.LoginEndpoint == "" {
		x.LoginEndpoint = "/account/login"
	}
	if x.LogoutEndpoint == "" {
		x.LogoutEndpoint = "/account/logout"
	}

	if x.AuthorizationCodeStore == nil {
		x.AuthorizationCodeStore = store.NewDefaultAuthorizationCodeStore(180)
	}
	if x.StateStore == nil {
		x.StateStore = store.NewDefaultStateStore()
	}
	if x.ClientValidator == nil {
		x.ClientValidator = security.NewDefaultClientValidator(x.ClientStore)
	}
	if x.AuthCodeGenerator == nil {
		x.AuthCodeGenerator = token.NewDefaultAuthCodeGenerator()
	}
	if x.PkceValidator == nil {
		x.PkceValidator = security.NewDefaultPkceValidator()
	}
	if x.TokenGenerator == nil {
		x.TokenGenerator = token.NewDefaultTokenGenerator(
			x.PrivateKey,
			jwt.PS256,
			x.ClaimsGenerator,
		)
	}
	if x.ResourceOwnerValidator == nil {
		x.ResourceOwnerValidator = security.NewDefaultResourceOwnerValidator()
	}
}

func (x *TokenHost) GetAuthCookieName() string {
	return x.AuthCookieName
}

func (x *TokenHost) GetAuthorizeEndpoint() string {
	return x.AuthorizeEndpoint

}
func (x *TokenHost) GetTokenEndpoint() string {
	return x.TokenEndpoint

}
func (x *TokenHost) GetEndSessionEndpoint() string {
	return x.EndSessionEndpoint

}
func (x *TokenHost) GetLoginEndpoint() string {
	return x.LoginEndpoint
}
func (x *TokenHost) GetLogoutEndpoint() string {
	return x.LogoutEndpoint
}
func (x *TokenHost) GetPrivateKey() *rsa.PrivateKey {
	return x.PrivateKey
}

// AuthorizeRequestHandler handle authorize request
func (x *TokenHost) AuthorizeRequestHandler(ctx *fasthttp.RequestCtx) {
	respType := xbytes.BytesToStr(ctx.FormValue(core.Form_ResponseType))
	clientID := xbytes.BytesToStr(ctx.FormValue(core.Form_ClientID))
	redirectURI := xbytes.BytesToStr(ctx.FormValue(core.Form_RedirectUri))
	scopesStr := xbytes.BytesToStr(ctx.FormValue(core.Form_Scope))
	state := xbytes.BytesToStr(ctx.FormValue(core.Form_State))
	// surferID := x.getSurferID(ctx)

	// verify client
	client, err, errDesc := x.ClientValidator.VerifyRespTypeRedirectURIScope(
		clientID,
		respType,
		redirectURI,
		scopesStr,
	)
	if err != nil {
		x.writeError(ctx, http.StatusBadRequest, err, errDesc)
		return
	}

	// RFC 6749 §10.12: 'state' is RECOMMENDED for CSRF protection. Warn (don't block)
	// when missing so operators can spot non-compliant clients.
	if state == "" {
		xlog.Warnf("/authorize request missing 'state' parameter (client_id=%s)", clientID)
	}

	username := x.getEncryptedCookie(ctx, x.AuthCookieName)
	if username == "" {
		returnURL := xbytes.BytesToStr(ctx.URI().RequestURI())
		targetURL := core.AppendQuery(x.LoginEndpoint,
			[2]string{core.Form_ReturnUrl, returnURL},
		)
		core.Redirect(ctx, targetURL)
		return
	}

	switch respType {
	case core.ResponseType_Code:
		x.AuthorizationCodeRequestHandler(ctx, client, respType, scopesStr, redirectURI, state, username)
	case core.ResponseType_Token:
		x.ImplicitTokenRequestHandler(ctx, client, respType, scopesStr, redirectURI, state, username)
	}
}

// AuthorizationCodeRequestHandler handle authorize code request
func (x *TokenHost) AuthorizationCodeRequestHandler(ctx *fasthttp.RequestCtx, client model.IClient, respType, scopesStr, redirectURI, state, username string) {
	var code string
	// pkce check
	if !x.PkceRequired {
		// pkce not required, just issue code
		code = x.AuthCodeGenerator.Generate()
		x.AuthorizationCodeStore.Save(
			code,
			&model.TokenInfo{
				ClientID:    client.GetID(),
				Scopes:      scopesStr,
				RedirectUri: redirectURI,
				Username:    username,
			},
		)
		targetURL := core.AppendQuery(redirectURI,
			[2]string{core.Form_Code, code},
			[2]string{core.Form_State, state},
		)
		core.Redirect(ctx, targetURL)
		return
	}

	// pkce required
	codeChallenge := xbytes.BytesToStr(ctx.FormValue(core.Form_CodeChallenge))

	if codeChallenge == "" {
		// client didn't provide pkce challenge, write error
		err := errors.New(core.Err_invalid_request)
		errDesc := errors.New("code challenge is required")
		xlog.Warn(errDesc.Error())
		x.writeError(ctx, http.StatusBadRequest, err, errDesc)
		return
	}

	// client provided pkce challenge
	codeChallengeMethod := xbytes.BytesToStr(ctx.FormValue(core.Form_CodeChallengeMethod))
	if codeChallengeMethod == "" {
		// secure default per OAuth 2.1 — plain is effectively no PKCE
		codeChallengeMethod = core.Pkce_S256
	} else if codeChallengeMethod == core.Pkce_Plain {
		if !x.AllowPlainPkce {
			err := errors.New(core.Err_invalid_request)
			errDesc := errors.New("code_challenge_method 'plain' is not allowed, use 'S256'")
			xlog.Warn(errDesc.Error())
			x.writeError(ctx, http.StatusBadRequest, err, errDesc)
			return
		}
	} else if codeChallengeMethod != core.Pkce_S256 {
		err := errors.New(core.Err_invalid_request)
		errDesc := errors.New("transform algorithm not supported")
		xlog.Warn(errDesc.Error())
		x.writeError(ctx, http.StatusBadRequest, err, errDesc)
		return
	}

	// issue authorization code
	code = x.AuthCodeGenerator.Generate()
	x.AuthorizationCodeStore.Save(
		code,
		&model.TokenInfo{
			ClientID:            client.GetID(),
			Scopes:              scopesStr,
			RedirectUri:         redirectURI,
			Username:            username,
			CodeChallenge:       codeChallenge,
			CodeChallengeMethod: codeChallengeMethod,
		},
	)

	// RFC 6749 §4.1.2: authorization response carries only 'code' and 'state'.
	// Echoing code_challenge/code_challenge_method to the client leaks them into
	// access logs and Referer headers with no benefit.
	targetURL := core.AppendQuery(redirectURI,
		[2]string{core.Form_Code, code},
		[2]string{core.Form_State, state},
	)
	core.Redirect(ctx, targetURL)
}

// AuthorizationCodeRequestHandler handle implicit token request
func (x *TokenHost) ImplicitTokenRequestHandler(ctx *fasthttp.RequestCtx, client model.IClient, respType, scopesStr, redirectURI, state, username string) {
	// user already logged in, issue token
	token, err := x.TokenGenerator.GenerateAccessToken(
		ctx,
		core.GrantType_Implicit,
		client,
		strings.Split(scopesStr, core.Seperator_Scope),
		username,
	)
	if err != nil {
		x.writeError(ctx, http.StatusBadRequest, errors.New(core.Err_server_error), err)
		return
	}

	// RFC 6749 §4.2.2: implicit flow MUST return token in URL fragment, not query.
	// Fragments are not sent to servers, kept out of access logs and Referer headers.
	targetURL := core.AppendFragment(redirectURI,
		[2]string{core.Form_AccessToken, token},
		[2]string{core.Form_TokenType, core.Form_TokenTypeBearer},
		[2]string{core.Form_ExpiresIn, fmt.Sprintf("%d", client.GetAccessTokenExpireSeconds())},
		[2]string{core.Form_Scope, scopesStr},
		[2]string{core.Form_State, state},
	)

	core.Redirect(ctx, targetURL)
}

// TokenRequestHandler handle token request
func (x *TokenHost) TokenRequestHandler(ctx *fasthttp.RequestCtx) {
	// get parametes from request
	var grantTypeStr = xbytes.BytesToStr(ctx.FormValue(core.Form_GrantType))
	var scopesStr = xbytes.BytesToStr(ctx.FormValue(core.Form_Scope))

	credentials, err, errDesc := x.ClientValidator.ExractClientCredentials(ctx)
	if err != nil {
		x.writeError(ctx, http.StatusBadRequest, err, errDesc)
		return
	}

	// verify client
	var client model.IClient
	if grantTypeStr == core.GrantType_AuthorizationCode || grantTypeStr == core.GrantType_RefreshToken {
		// auth code & refresh grant doesn't require post scopes
		client, err, errDesc = x.ClientValidator.VerifyCredentialGrantType(credentials, grantTypeStr)
	} else {
		// other scopes must post scopes
		client, err, errDesc = x.ClientValidator.VerifyCredentialGrantTypeScope(credentials, grantTypeStr, scopesStr)
	}

	if err != nil {
		var httpStatusCode int
		if err.Error() == core.Err_invalid_client {
			httpStatusCode = http.StatusUnauthorized
		} else {
			httpStatusCode = http.StatusBadRequest
		}
		x.writeError(ctx, httpStatusCode, err, errDesc)
		return
	}

	switch grantTypeStr {
	case core.GrantType_Client:
		x.handleClientCredentialsTokenRequest(ctx, client, scopesStr)
	case core.GrantType_AuthorizationCode:
		x.handleAuthorizationCodeTokenRequest(ctx, client)
	case core.GrantType_ResourceOwner:
		x.handleResourceOwnerTokenRequest(ctx, client, scopesStr)
	case core.GrantType_RefreshToken:
		x.handleRefreshTokenRequest(ctx, client)
	default:
		xlog.Warn(core.Err_unsupported_grant_type + ":" + grantTypeStr)
		x.writeError(ctx, http.StatusBadRequest, errors.New(core.Err_unsupported_grant_type), nil)
	}
}

// EndSessionRequestHandler handle end session request
func (x *TokenHost) EndSessionRequestHandler(ctx *fasthttp.RequestCtx) {
	clientID := xbytes.BytesToStr(ctx.FormValue(core.Form_ClientID))
	redirectURI := xbytes.BytesToStr(ctx.FormValue(core.Form_RedirectUri))
	// verify client
	_, err, errDesc := x.ClientValidator.VerifyRedirectURI(
		clientID,
		redirectURI,
	)
	if err != nil {
		x.writeError(ctx, http.StatusBadRequest, err, errDesc)
		return
	}

	// save client state for clear token verification
	state := xbytes.BytesToStr(ctx.FormValue(core.Form_State))
	endSessionID := core.GenerateID()
	if state != "" {
		x.StateStore.Save(clientID+":"+endSessionID, state, 60)
	}

	// delete login cookie
	ctx.Response.Header.DelClientCookie(x.AuthCookieName)
	c := fasthttp.AcquireCookie()
	defer fasthttp.ReleaseCookie(c)
	c.SetKey(x.AuthCookieName)
	c.SetExpire(fasthttp.CookieExpireDelete)
	c.SetPath("/")
	ctx.Response.Header.SetCookie(c)

	// redirect to client
	targetURL := core.AppendQuery(redirectURI,
		[2]string{core.Form_State, state},
		[2]string{core.Form_EndSessionID, endSessionID},
	)
	core.Redirect(ctx, targetURL)
}

// ClearTokenHandler handle clear token request
func (x *TokenHost) ClearTokenRequestHandler(ctx *fasthttp.RequestCtx) {
	state := xbytes.BytesToStr(ctx.FormValue(core.Form_State))
	if state == "" {
		x.writeError(ctx, http.StatusBadRequest, errors.New("missing state"), nil)
		return
	}
	endSessionID := xbytes.BytesToStr(ctx.FormValue(core.Form_EndSessionID))
	if endSessionID == "" {
		x.writeError(ctx, http.StatusBadRequest, errors.New("missing es_id"), nil)
		return
	}
	oldRefreshToken := xbytes.BytesToStr(ctx.FormValue(core.Form_RefreshToken))
	if oldRefreshToken == "" {
		x.writeError(ctx, http.StatusBadRequest, errors.New("missing refresh token"), nil)
		return
	}

	credential := &model.Credential{
		Username: xbytes.BytesToStr(ctx.FormValue(core.Form_ClientID)),
		Password: xbytes.BytesToStr(ctx.FormValue(core.Form_ClientSecret)),
	}

	// verify client
	_, err, errDesc := x.ClientValidator.VerifyCredential(credential)
	if err != nil {
		x.writeError(ctx, http.StatusBadRequest, err, errDesc)
		return
	}

	// verify state (constant-time to avoid leaking how much of the value matched)
	storedState := x.StateStore.GetThenRemove(credential.Username + ":" + endSessionID)
	if storedState == "" || !core.FixedTimeCompare(storedState, state) {
		x.writeError(ctx, http.StatusBadRequest, errors.New("invalid state"), nil)
		return
	}

	// remove refresh token
	x.TokenStore.RemoveRefreshToken(oldRefreshToken)

	// signal success explicitly so callers can distinguish "cleared" from "middleware ate it"
	ctx.SetStatusCode(http.StatusOK)
}

func (x *TokenHost) getEncryptedCookie(ctx *fasthttp.RequestCtx, name string) string {
	r := xbytes.BytesToStr(ctx.Request.Header.Cookie(name))

	if r != "" {
		err := x.CookieEncryptor.Decrypt(name, r, &r)
		xerr.LogError(err)
	}

	return r
	// encryptedCookie := xbytes.BytesToStr(ctx.Request.Header.Cookie(name))
	// if encryptedCookie == "" {
	// 	return ""
	// }

	// var r string
	// err := x.CookieProtector.Decode(name, encryptedCookie, &r)

	// if xerr.LogError(err) {
	// 	return ""
	// }

	// return r
}

// func (x *TokenHost) SetCookie(ctx *fasthttp.RequestCtx, key, value string, options ...func(*http.Cookie)) {
// if encryptedCookie, err := x.CookieProtector.Encode(key, value); err == nil {
// 	authCookie := fasthttp.AcquireCookie()
// 	defer func() {
// 		fasthttp.ReleaseCookie(authCookie)
// 	}()
// 	authCookie.SetKey(key)
// 	authCookie.SetValue(encryptedCookie)
// 	authCookie.SetSecure(true)
// 	authCookie.SetPath("/")
// 	authCookie.SetHTTPOnly(true)
// 	if duration > 0 {
// 		authCookie.SetExpire(time.Now().Add(duration))
// 	}
// 	ctx.Response.Header.SetCookie(authCookie)
// } else {
// 	xerr.LogError(err)
// }
// }

// func (x *TokenHost) DelCookie(ctx *fasthttp.RequestCtx, key string) {
// 	ctx.Response.Header.DelClientCookie(key)
// 	// ctx.Response.Header.DelCookie(key)

// 	// authCookie := fasthttp.AcquireCookie()
// 	// defer func() {
// 	// 	fasthttp.ReleaseCookie(authCookie)
// 	// }()
// 	// authCookie.SetKey(key)
// 	// authCookie.SetSecure(true)
// 	// authCookie.SetPath("/")
// 	// authCookie.SetHTTPOnly(true)
// 	// authCookie.SetExpire(fasthttp.CookieExpireDelete)
// 	// ctx.Response.Header.SetCookie(authCookie)
// }

// func (x *TokenHost) GetOptions() *AuthServerOptions {
// 	return x.Options
// }

// handleClientCredentialsTokenRequest handle client credentials token request
func (x *TokenHost) handleClientCredentialsTokenRequest(ctx *fasthttp.RequestCtx, client model.IClient, scopesStr string) {
	// issue token directly
	token, err := x.TokenGenerator.GenerateAccessToken(
		ctx,
		core.GrantType_Client,
		client,
		strings.Split(scopesStr, core.Seperator_Scope),
		client.GetID(),
	)
	if err != nil {
		x.writeError(ctx, http.StatusBadRequest, errors.New(core.Err_server_error), err)
		return
	}

	x.writeToken(ctx, token, scopesStr, client.GetAccessTokenExpireSeconds(), "")
}

// handleAuthorizationCodeTokenRequest handle authorization code token request
func (x *TokenHost) handleAuthorizationCodeTokenRequest(ctx *fasthttp.RequestCtx, client model.IClient) {
	// exchange token by using auhorization code
	code := xbytes.BytesToStr(ctx.FormValue(core.Form_Code))
	// clientID := xbytes.BytesToStr(ctx.FormValue(core.Form_ClientID))
	redirectUri := xbytes.BytesToStr(ctx.FormValue(core.Form_RedirectUri))

	tokenInfo := x.AuthorizationCodeStore.GetThenRemove(code)
	if tokenInfo == nil {
		err := errors.New(core.Err_invalid_request)
		errDesc := errors.New("invalid authorization code")
		xlog.Warn(errDesc.Error())
		x.writeError(ctx, http.StatusBadRequest, err, errDesc)
		return
	}

	// if client.GetID() != clientID || clientID != tokenInfo.ClientID {
	if client.GetID() != tokenInfo.ClientID {
		err := errors.New(core.Err_invalid_request)
		errDesc := errors.New("client id mismatch")
		xlog.Warnf("client id doesn't match detected: original '%s', current '%s'", tokenInfo.ClientID, client.GetID())
		xlog.Warn(errDesc.Error())
		x.writeError(ctx, http.StatusBadRequest, err, errDesc)
		return
	}

	if redirectUri != tokenInfo.RedirectUri {
		err := errors.New(core.Err_invalid_request)
		errDesc := errors.New("redirect URI mismatch")
		xlog.Warnf("Redirect URI mismatch detected: original '%s', current '%s'", tokenInfo.RedirectUri, redirectUri)
		x.writeError(ctx, http.StatusBadRequest, err, errDesc)
		return
	}

	// pkce check
	if !x.PkceRequired {
		// issue token
		x.issueTokenByRequestInfo(ctx, core.GrantType_AuthorizationCode, client, tokenInfo)
		return
	}

	codeVierifier := xbytes.BytesToStr(ctx.FormValue(core.Form_CodeVerifier))
	if codeVierifier == "" {
		// client didn't provide code verifier, write error
		err := errors.New(core.Err_invalid_request)
		errDesc := errors.New("code verifier is missing")
		xlog.Warn(errDesc.Error())
		x.writeError(ctx, http.StatusBadRequest, err, errDesc)
		return
	}

	if !x.PkceValidator.Verify(codeVierifier, tokenInfo.CodeChallenge, tokenInfo.CodeChallengeMethod) {
		err := errors.New(core.Err_invalid_grant)
		errDesc := errors.New("code verifier is invalid")
		xlog.Warn(errDesc.Error())
		x.writeError(ctx, http.StatusBadRequest, err, errDesc)
		return
	}

	oldRefreshToken := xbytes.BytesToStr(ctx.FormValue(core.Form_RefreshToken))
	if oldRefreshToken != "" {
		// received old refresh token, revoke it
		x.TokenStore.RemoveRefreshToken(oldRefreshToken)
	}

	// issue token
	x.issueTokenByRequestInfo(ctx, core.GrantType_AuthorizationCode, client, tokenInfo)
}

// handleResourceOwnerTokenRequest handle resource owner token request
func (x *TokenHost) handleResourceOwnerTokenRequest(ctx *fasthttp.RequestCtx, client model.IClient, scopesStr string) {
	// verify username & password
	username := xbytes.BytesToStr(ctx.FormValue(core.Form_Username))
	password := xbytes.BytesToStr(ctx.FormValue(core.Form_Password))
	success, err := x.ResourceOwnerValidator.Verify(username, password)
	if err != nil {
		errID := xutils.GenerateStringID()
		xlog.Errorf("%s: %+v", errID, err)

		errBrief := xerr.New("internel error")
		errDesc := xerr.New(errID)
		x.writeError(ctx, http.StatusInternalServerError, errBrief, errDesc)
		return
	}

	if success {
		// pass, issue token
		x.issueTokenByRequestInfo(ctx, core.GrantType_AuthorizationCode, client, &model.TokenInfo{
			ClientID: client.GetID(),
			Scopes:   scopesStr,
			Username: username,
		})
	} else {
		err := errors.New(core.Err_invalid_grant)
		errDesc := errors.New("username password doesn't match")
		xlog.Warn(errDesc.Error())
		x.writeError(ctx, http.StatusBadRequest, err, errDesc)
	}
}

// handleRefreshTokenRequest handle refresh token request
func (x *TokenHost) handleRefreshTokenRequest(ctx *fasthttp.RequestCtx, client model.IClient) {
	refreshToken := xbytes.BytesToStr(ctx.FormValue(core.Form_RefreshToken))
	if refreshToken == "" {
		err := errors.New(core.Err_invalid_request)
		errDesc := errors.New("refresh token is missing")
		xlog.Warn(errDesc.Error())
		x.writeError(ctx, http.StatusBadRequest, err, errDesc)
		return
	}

	var tokenInfo = x.TokenStore.GetThenRemoveTokenInfo(refreshToken)
	if tokenInfo == nil {
		err := errors.New(core.Err_invalid_grant)
		errDesc := errors.New("refresh token is invalid or expired or revoked")
		xlog.Warn(errDesc.Error())
		x.writeError(ctx, http.StatusBadRequest, err, errDesc)
		return
	}

	if client.GetID() != tokenInfo.ClientID {
		err := errors.New(core.Err_invalid_request)
		errDesc := fmt.Errorf("client id doesn't match, original: '%s', current: '%s'", tokenInfo.ClientID, client.GetID())
		xlog.Warn(errDesc.Error())
		x.writeError(ctx, http.StatusBadRequest, err, errDesc)
		return
	}

	// issue token
	x.issueTokenByRequestInfo(ctx, core.GrantType_RefreshToken, client, tokenInfo)
}

// issueTokenByRequestInfo issue access token and refresh token
func (x *TokenHost) issueTokenByRequestInfo(ctx *fasthttp.RequestCtx, grantType string, client model.IClient, tokenInfo *model.TokenInfo) {
	// issue token
	token, err := x.TokenGenerator.GenerateAccessToken(
		ctx,
		grantType,
		client,
		strings.Split(tokenInfo.Scopes, core.Seperator_Scope),
		tokenInfo.Username,
	)
	if err != nil {
		x.writeError(ctx, http.StatusBadRequest, errors.New(core.Err_server_error), err)
		return
	}

	allowRefresh := false
	for _, grant := range client.GetGrants() {
		if grant == core.GrantType_RefreshToken {
			allowRefresh = true
			break
		}
	}
	if allowRefresh {
		// allowed to use refresh token
		var refreshToken = x.TokenGenerator.GenerateRefreshToken()
		x.TokenStore.SaveRefreshToken(refreshToken, tokenInfo, client.GetRefreshTokenExpireSeconds())
		x.writeToken(ctx, token, tokenInfo.Scopes, client.GetAccessTokenExpireSeconds(), refreshToken)
	} else {
		// not allowed to use refresh token
		x.writeToken(ctx, token, tokenInfo.Scopes, client.GetAccessTokenExpireSeconds(), "")
	}
}

// WriteTokenHandler
func (x *TokenHost) writeToken(ctx *fasthttp.RequestCtx, token, scopesStr string, expireSeconds int32, refreshToken string) {
	ctx.SetContentType(core.ContentType_Json)
	ctx.Response.Header.Add(core.Header_CacheControl, core.Header_CacheControl_Value)
	ctx.Response.Header.Add(core.Header_Pragma, core.Header_Pragma_Value)

	payload := map[string]interface{}{
		core.Form_AccessToken: token,
		core.Form_ExpiresIn:   expireSeconds,
		core.Form_Scope:       scopesStr,
		core.Form_TokenType:   core.Form_TokenTypeBearer,
	}
	if refreshToken != "" {
		payload[core.Form_RefreshToken] = refreshToken
	}

	body, err := json.Marshal(payload)
	if err != nil {
		xlog.Error(err)
		ctx.SetStatusCode(http.StatusInternalServerError)
		return
	}
	ctx.Write(body)
}

// writeError handle error
func (x *TokenHost) writeError(ctx *fasthttp.RequestCtx, statusCode int, err, errDesc error) {
	if errDesc == nil {
		errDesc = err
	}

	ctx.SetStatusCode(statusCode)
	ctx.SetContentType(core.ContentType_Json)
	ctx.Response.Header.Add(core.Header_CacheControl, core.Header_CacheControl_Value)
	ctx.Response.Header.Add(core.Header_Pragma, core.Header_Pragma_Value)

	body, mErr := json.Marshal(map[string]string{
		"error":             err.Error(),
		"error_description": errDesc.Error(),
	})
	if mErr != nil {
		xlog.Error(mErr)
		return
	}
	ctx.Write(body)
}

// // getSurferID get surfer id
// func (x *TokenHost) getSurferID(ctx *fasthttp.RequestCtx) (surferID string) {
// 	surferID = x.GetCookie(ctx, x.Options.SurferCookieName)
// 	if surferID == "" {
// 		surferID = core.GenerateID()
// 		x.SetCookie(ctx, x.Options.SurferCookieName, surferID, 8784*time.Hour)
// 	}
// 	return
// }
