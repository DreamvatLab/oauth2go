package oauth2go

import (
	"context"
	"net/http"
	"time"

	"github.com/DreamvatLab/go/xerr"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

type ClientCredential struct {
	Config      *clientcredentials.Config
	AccessToken *oauth2.Token
}

func (x *ClientCredential) Token() (*oauth2.Token, error) {
	var err error

	if x.AccessToken == nil || time.Now().UTC().After(x.AccessToken.Expiry) {
		// Request a new token if there is no token or the token has expired
		x.AccessToken, err = x.Config.Token(context.Background())
		if err != nil {
			return x.AccessToken, xerr.WithStack(err)
		}
	}

	return x.AccessToken, xerr.WithStack(err)
}

func (x *ClientCredential) Client(context context.Context) *http.Client {
	tokenSource := oauth2.ReuseTokenSource(x.AccessToken, x)
	return oauth2.NewClient(context, tokenSource)
}
