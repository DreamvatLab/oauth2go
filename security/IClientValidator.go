package security

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/DreamvatLab/go/xbytes"
	"github.com/DreamvatLab/go/xerr"
	"github.com/DreamvatLab/go/xlog"
	"github.com/DreamvatLab/oauth2go/core"
	"github.com/DreamvatLab/oauth2go/model"
	"github.com/DreamvatLab/oauth2go/store"
	"github.com/valyala/fasthttp"
)

type IClientValidator interface {
	// ExractClientCredentials extract client credential from request
	ExractClientCredentials(ctx *fasthttp.RequestCtx) (*model.Credential, error, error)
	// VerifyCredential verify client id & secret
	VerifyCredential(credential *model.Credential) (model.IClient, error, error)
	// VerifyCredentialGrantType verify client id, secret & grant type
	VerifyCredentialGrantType(credential *model.Credential, grantType string) (model.IClient, error, error)
	// VerifyCredentialGrantTypeScope verify client id, secret, grant type & scopes
	VerifyCredentialGrantTypeScope(credential *model.Credential, grantType, scopesStr string) (model.IClient, error, error)
	// VerifyRespTypeRedirectURIScope verify client, response type, scopes, redirect uri
	VerifyRespTypeRedirectURIScope(clientID, responseType, redirectURI, scopesStr string) (model.IClient, error, error)
	// VerifyRedirectURI verify client id, redirect uri
	VerifyRedirectURI(clientID, logoutRedirectURI string) (model.IClient, error, error)
}

func NewDefaultClientValidator(clientStore store.IClientStore) IClientValidator {
	return &DefaultClientValidator{
		ClientStore: clientStore,
	}
}

type DefaultClientValidator struct {
	ClientStore store.IClientStore
}

// ExractClientCredentials extract client credential from request
func (x *DefaultClientValidator) ExractClientCredentials(ctx *fasthttp.RequestCtx) (r *model.Credential, err, errDesc error) {
	r, err, errDesc = x.exractClientCredentialsFromHeader(ctx)
	if err == nil {
		return
	}

	r, err, errDesc = x.exractClientCredentialsFromBody(ctx)
	if err != nil {
		xlog.Warn(errDesc.Error())
	}

	return
}

func (x *DefaultClientValidator) exractClientCredentialsFromHeader(ctx *fasthttp.RequestCtx) (r *model.Credential, err, errDesc error) {
	authorzation := xbytes.BytesToStr(ctx.Request.Header.Peek(core.Header_Authorization))
	if authorzation == "" {
		err = errors.New(core.Err_invalid_request)
		errDesc = errors.New("no authorization header")
		return
	}

	authArray := strings.Split(authorzation, core.Seperator_Scope)
	if len(authArray) != 2 || authArray[1] == "" {
		err = errors.New(core.Err_invalid_request)
		errDesc = errors.New("invalid authorization header format")
		return
	}

	authBytes, err := base64.StdEncoding.DecodeString(authArray[1]) // has padding, do not use RawURLEncoding
	if xerr.LogError(err) {
		return
	}
	authStr := xbytes.BytesToStr(authBytes)
	authArray = strings.Split(authStr, core.Seperators_Auth)

	if len(authArray) != 2 || authArray[0] == "" || authArray[1] == "" {
		err = errors.New(core.Err_invalid_request)
		errDesc = errors.New("invalid authorization header segments length")
		xlog.Warn(errDesc.Error())
		return
	}

	r = &model.Credential{
		Username: authArray[0],
		Password: authArray[1],
	}
	return
}

func (x *DefaultClientValidator) exractClientCredentialsFromBody(ctx *fasthttp.RequestCtx) (r *model.Credential, err error, errDesc error) {
	id := xbytes.BytesToStr(ctx.FormValue(core.Form_ClientID))

	if id == "" {
		err = errors.New(core.Err_invalid_request)
		errDesc = errors.New("client id is missing")
		return
	}

	secret := xbytes.BytesToStr(ctx.FormValue(core.Form_ClientSecret))
	if secret == "" {
		err = errors.New(core.Err_invalid_request)
		errDesc = errors.New("client secret is missing")
		return
	}

	r = &model.Credential{
		Username: id,
		Password: secret,
	}
	return
}

// VerifyCredential verify client id & secret
func (x *DefaultClientValidator) VerifyCredential(credential *model.Credential) (model.IClient, error, error) {
	client := x.ClientStore.GetClient(credential.Username)

	if client == nil {
		err := errors.New(core.Err_invalid_client)
		errDesc := fmt.Errorf("client '%s' does not exist", credential.Username)
		xlog.Warn(errDesc.Error())
		return nil, err, errDesc
	}

	// Didn't provide Secret, but client is public
	if credential.Password == "" && client.GetIsPublic() {
		// allow public clients to skip secret validation
		return client, nil, nil
	}

	// Check if the secret matches the client secret
	if credential.Password != client.GetSecret() {
		err := errors.New(core.Err_invalid_client)
		errDesc := fmt.Errorf("password for client '%s' is incorrect", credential.Username)
		xlog.Warn(errDesc.Error())
		xlog.Debugf("%s secret: %s, provided secret: %s", client.GetID(), client.GetSecret(), credential.Password)
		return nil, err, errDesc
	}

	return client, nil, nil
}

// VerifyCredentialGrantType verify client id, secret & grant type
func (x *DefaultClientValidator) VerifyCredentialGrantType(credential *model.Credential, grantType string) (model.IClient, error, error) {
	if grantType == "" {
		err := errors.New(core.Err_invalid_request)
		errDesc := errors.New("invalid client")
		xlog.Warn(errDesc.Error())
		return nil, err, errDesc
	}

	client, err, errDesc := x.VerifyCredential(credential)
	if err != nil {
		return nil, err, errDesc
	}

	err, errDesc = x.validateGrants(client, grantType)
	if err != nil {
		return nil, err, errDesc
	}

	return client, nil, nil

}

// VerifyCredentialGrantTypeScope verify client id, secret, grant type & scopes
func (x *DefaultClientValidator) VerifyCredentialGrantTypeScope(credential *model.Credential, grantType, scopesStr string) (model.IClient, error, error) {
	if scopesStr == "" {
		err := errors.New(core.Err_invalid_request)
		errDesc := errors.New("scope is missing")
		xlog.Warn(errDesc.Error())
		return nil, err, errDesc
	}

	client, err, errDesc := x.VerifyCredentialGrantType(credential, grantType)
	if err != nil {
		return nil, err, errDesc
	}

	err, errDesc = x.validateScopes(client, scopesStr)
	if err != nil {
		return nil, err, errDesc
	}

	return client, nil, nil
}

// VerifyRespTypeRedirectURIScope verify client id & secret, response type, scopes, redirect uri
func (x *DefaultClientValidator) VerifyRespTypeRedirectURIScope(clientID, responseType, redirectURI, scopesStr string) (model.IClient, error, error) {
	if clientID == "" {
		err := errors.New(core.Err_invalid_request)
		errDesc := errors.New("client id is missing")
		xlog.Warn(errDesc.Error())
		return nil, err, errDesc
	}

	if responseType == "" {
		err := errors.New(core.Err_invalid_request)
		errDesc := errors.New("response type is missing")
		xlog.Warn(errDesc.Error())
		return nil, err, errDesc
	}

	if redirectURI == "" {
		err := errors.New(core.Err_invalid_request)
		errDesc := errors.New("redirect uri is missing")
		xlog.Warn(errDesc.Error())
		return nil, err, errDesc
	}

	if scopesStr == "" {
		err := errors.New(core.Err_invalid_request)
		errDesc := errors.New("scope is missing")
		xlog.Warn(errDesc.Error())
		return nil, err, errDesc
	}

	client := x.ClientStore.GetClient(clientID)

	if client == nil {
		err := errors.New(core.Err_invalid_request)
		errDesc := errors.New("client not exists")
		xlog.Warn(errDesc.Error())
		return nil, err, errDesc
	}

	err, errDesc := x.validateRedirectUris(client, redirectURI)
	if err != nil {
		return nil, err, errDesc
	}

	err, errDesc = x.validateScopes(client, scopesStr)
	if err != nil {
		return nil, err, errDesc
	}

	err, errDesc = x.validateResponseType(client, responseType)
	if err != nil {
		return nil, err, errDesc
	}

	return client, nil, nil
}

// VerifyRespTypeRedirectURIScope verify client id & redirect uri
func (x *DefaultClientValidator) VerifyRedirectURI(clientID, redirectURI string) (model.IClient, error, error) {
	if clientID == "" {
		err := errors.New(core.Err_invalid_request)
		errDesc := errors.New("client id is missing")
		xlog.Warn(errDesc.Error())
		return nil, err, errDesc
	}

	if redirectURI == "" {
		err := errors.New(core.Err_invalid_request)
		errDesc := errors.New("redirect uri is missing")
		xlog.Warn(errDesc.Error())
		return nil, err, errDesc
	}

	client := x.ClientStore.GetClient(clientID)

	if client == nil {
		err := errors.New(core.Err_invalid_request)
		errDesc := errors.New("client not exists")
		xlog.Warn(errDesc.Error())
		return nil, err, errDesc
	}

	err, errDesc := x.validateRedirectUris(client, redirectURI)
	if err != nil {
		return nil, err, errDesc
	}

	return client, nil, nil
}

// validateGrants _
func (x *DefaultClientValidator) validateGrants(client model.IClient, grantType string) (error, error) {
	allowedGrants := client.GetGrants()
	if len(allowedGrants) > 0 {
		for _, allowedGrant := range allowedGrants {
			if allowedGrant == grantType {
				return nil, nil
			}
		}
	}

	err := errors.New(core.Err_unauthorized_client)
	errDesc := fmt.Errorf("'%s' grant is not allowed for '%s'", grantType, client.GetID())
	xlog.Warn(errDesc.Error())
	return err, errDesc
}

// validateScopes _
func (x *DefaultClientValidator) validateScopes(client model.IClient, scopesStr string) (error, error) {
	allowedScopes := client.GetScopes()
	if len(allowedScopes) > 0 {
		requestedScopeArray := strings.Split(scopesStr, core.Seperator_Scope)

		for _, requestedScope := range requestedScopeArray {
			if !isScopeAllowed(requestedScope, allowedScopes) {
				err := errors.New(core.Err_unauthorized_client)
				errDesc := fmt.Errorf("'%s' is not allowed for scope '%s'", client.GetID(), requestedScope)
				xlog.Warn(errDesc.Error())
				return err, errDesc
			}
		}

		return nil, nil
	}

	err := errors.New(core.Err_unauthorized_client)
	errDesc := fmt.Errorf("'%s' has no allowed scopes", client.GetID())
	xlog.Warn(errDesc.Error())
	return err, errDesc
}

func isScopeAllowed(requestedScope string, allowedScopes []string) bool {
	for _, allowedScope := range allowedScopes {
		if allowedScope == requestedScope {
			return true
		}
	}
	return false
}

// validateRedirectUris _
func (x *DefaultClientValidator) validateRedirectUris(client model.IClient, redirectURI string) (error, error) {
	allowedrUris := client.GetRedirectUris()
	if len(allowedrUris) > 0 {
		for _, allowedrUri := range allowedrUris {
			if allowedrUri == redirectURI {
				return nil, nil
			}
		}
	}

	err := errors.New(core.Err_unauthorized_client)
	errDesc := fmt.Errorf("'%s' redirect uri is is not allowed for '%s'", redirectURI, client.GetID())
	xlog.Warn(errDesc.Error())
	return err, errDesc
}

// validateResponseType _
func (x *DefaultClientValidator) validateResponseType(client model.IClient, responseType string) (error, error) {
	if responseType == core.ResponseType_Code {
		return x.validateGrants(client, core.GrantType_AuthorizationCode)
	} else if responseType == core.ResponseType_Token {
		return x.validateGrants(client, core.GrantType_Implicit)
	}

	err := errors.New(core.Err_unauthorized_client)
	errDesc := fmt.Errorf("'%s' response type is is not allowed for '%s'", responseType, client.GetID())
	xlog.Warn(errDesc.Error())
	return err, errDesc
}
