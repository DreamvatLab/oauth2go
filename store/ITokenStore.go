package store

import (
	"github.com/DreamvatLab/oauth2go/model"
)

type ITokenStore interface {
	RemoveRefreshToken(refreshToken string)
	SaveRefreshToken(refreshToken string, requestInfo *model.TokenInfo, expireSeconds int32)
	GetThenRemoveTokenInfo(refreshToken string) *model.TokenInfo
}
