package core

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/DreamvatLab/go/xbytes"
	"github.com/DreamvatLab/go/xsync"
	"github.com/sony/sonyflake"
	"github.com/valyala/fasthttp"
)

const (
	Header_Authorization          = "Authorization"
	Header_CacheControl           = "Cache-Control"
	Header_CacheControl_Value     = "no-store"
	Header_Pragma                 = "Pragma"
	Header_Pragma_Value           = "no-cache"
	ContentType_Json              = "application/json;charset=UTF-8"
	ContentType_Html              = "text/html;charset=utf-8"
	Claim_Role                    = "role"
	Claim_Name                    = "name"
	Claim_Audience                = "aud"
	Claim_Issuer                  = "iss"
	Claim_Subject                 = "sub"
	Claim_Expire                  = "exp"
	Claim_IssueAt                 = "iat"
	Claim_NotValidBefore          = "nbf"
	Claim_Scope                   = "scope"
	Claim_RefreshTokenExpire      = "rexp"
	Claim_Email                   = "email"
	Claim_Level                   = "level"
	Claim_Status                  = "status"
	Form_GrantType                = "grant_type"
	Form_ClientID                 = "client_id"
	Form_ClientSecret             = "client_secret"
	Form_RedirectUri              = "redirect_uri"
	Form_ReturnUrl                = "returnUrl"
	Form_State                    = "state"
	Form_EndSessionID             = "es_id"
	Form_Scope                    = "scope"
	Form_Code                     = "code"
	Form_Username                 = "username"
	Form_Password                 = "password"
	Form_ResponseType             = "response_type"
	Form_AccessToken              = "access_token"
	Form_RefreshToken             = "refresh_token"
	Form_TokenType                = "token_type"
	Form_TokenTypeBearer          = "Bearer"
	Form_ExpiresIn                = "expires_in"
	Form_CodeChallenge            = "code_challenge"
	Form_CodeChallengeMethod      = "code_challenge_method"
	Form_CodeVerifier             = "code_verifier"
	ResponseType_Token            = "token"
	ResponseType_Code             = "code"
	GrantType_Client              = "client_credentials"
	GrantType_AuthorizationCode   = "authorization_code"
	GrantType_Implicit            = "implicit"
	GrantType_ResourceOwner       = "password"
	GrantType_RefreshToken        = "refresh_token"
	Format_Token1                 = "{\"" + Form_AccessToken + "\":\"%s\",\"" + Form_ExpiresIn + "\":\"%d\",\"" + Form_Scope + "\":\"%s\",\"" + Form_TokenType + "\":\"" + Form_TokenTypeBearer + "\"}"
	Format_Token2                 = "{\"" + Form_AccessToken + "\":\"%s\",\"" + Form_RefreshToken + "\":\"%s\",\"" + Form_ExpiresIn + "\":\"%d\",\"" + Form_Scope + "\":\"%s\",\"" + Form_TokenType + "\":\"" + Form_TokenTypeBearer + "\"}"
	Format_Error                  = "{\"error\":\"%s\", \"error_description\":\"%s\"}"
	Msg_Success                   = ""
	Err_invalid_request           = "invalid_request"
	Err_invalid_client            = "invalid_client"
	Err_invalid_grant             = "invalid_grant"
	Err_unauthorized_client       = "unauthorized_client"
	Err_unsupported_grant_type    = "unsupported_grant_type"
	Err_unsupported_response_type = "unsupported_response_type"
	Err_invalid_scope             = "invalid_scope"
	Err_access_denied             = "access_denied"
	Err_description               = "error_description"
	Err_uri                       = "error_uri"
	Err_server_error              = "server_error"
	Pkce_Plain                    = "plain"
	Pkce_S256                     = "S256"
	Config_OAuth_PkceRequired     = "OAuth:PkceRequired"
	Token_Access                  = "access_token"
	Token_Refresh                 = "refresh_token"
	Token_ExpiresAt               = "expires_at"
	UtcTimesamp                   = "yyyy-MM-ddTHH:mm:ss.0000000+00:00"
	Seperator_Scope               = " "
	Seperators_Auth               = ":"
)

var (
	_idGenerator *sonyflake.Sonyflake
	// _secureCookie *securecookie.SecureCookie
	_bytesPool = xsync.NewSyncBytesPool(64)
)

func init() {
	// hashKey := xbytes.StrToBytes("JGQUQERAY5xPNVkliVMgGpVjLmjk2VDFAcP2gTI70Dw=")
	// blockKey := xbytes.StrToBytes("6MHdT1pG22lXjFcZzobwlQ==")
	// _secureCookie = securecookie.New(hashKey, blockKey)
	_idGenerator = sonyflake.NewSonyflake(sonyflake.Settings{})
}

// ToSHA256Base64URL computes the SHA-256 hash of the input string
// and encodes the result in Base64 URL format without padding.
// This function is used in PKCE to generate the code_challenge.
func ToSHA256Base64URL(in string) string {
	h := sha256.New()
	h.Write(xbytes.StrToBytes(in))
	r := h.Sum(nil)

	return base64.RawURLEncoding.EncodeToString(r)
}

// GenerateID _
func GenerateID() string {
	a, _ := _idGenerator.NextID()
	return fmt.Sprintf("%x", a)
}

func Redirect(ctx *fasthttp.RequestCtx, url string) {
	ctx.Response.Header.Add("Location", url)
	ctx.Response.SetStatusCode(fasthttp.StatusFound)
}

// func GetCookie(ctx *fasthttp.RequestCtx, key string) string {
// 	encryptedCookie := xbytes.BytesToStr(ctx.Request.Header.Cookie(key))
// 	if encryptedCookie == "" {
// 		return ""
// 	}

// 	var r string
// 	err := _secureCookie.Decode(key, encryptedCookie, &r)

// 	if xerr.LogError(err) {
// 		return ""
// 	}

// 	return r
// }

// func SetCookie(ctx *fasthttp.RequestCtx, key, value string, duration time.Duration) {
// 	if encryptedCookie, err := _secureCookie.Encode(key, value); err == nil {
// 		authCookie := fasthttp.AcquireCookie()
// 		authCookie.SetKey(key)
// 		authCookie.SetValue(encryptedCookie)
// 		authCookie.SetSecure(true)
// 		authCookie.SetPath("/")
// 		authCookie.SetHTTPOnly(true)
// 		if duration > 0 {
// 			authCookie.SetExpire(time.Now().Add(duration))
// 		}
// 		ctx.Response.Header.SetCookie(authCookie)
// 		defer fasthttp.ReleaseCookie(authCookie)
// 	} else {
// 		xerr.LogError(err)
// 	}
// }

func Random64String() string {
	randomNumber := _bytesPool.GetBytes()
	rand.Read(*randomNumber)
	defer func() {
		_bytesPool.PutBytes(randomNumber)
	}()

	return base64.RawURLEncoding.EncodeToString(*randomNumber)
}
