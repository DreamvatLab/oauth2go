package oauth2go

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/DreamvatLab/go/xconfig"
	"github.com/stretchr/testify/assert"
)

var (
	_cc *ClientCredential
)

func init() {
	http.DefaultClient.Transport = &http.Transport{
		Proxy: func(*http.Request) (*url.URL, error) {
			return url.Parse("http://localhost:8888")
		},
	}
	// configs.json is an integration-test fixture (not committed). When it's
	// missing, leave _cc nil and let the integration tests skip rather than
	// panicking at package init — which would block all OTHER tests in this
	// package from running.
	if _, err := os.Stat("configs.json"); err != nil {
		return
	}
	cp := xconfig.NewJsonConfigProvider()
	cp.GetStruct("OAuth", &_cc)
}

func TestClientCredential_Token(t *testing.T) {
	if _cc == nil {
		t.Skip("configs.json not present — integration test skipped")
	}
	token, err := _cc.Token()
	assert.NoError(t, err)
	t.Log(token)
}

func TestClientCredential_Client(t *testing.T) {
	if _cc == nil {
		t.Skip("configs.json not present — integration test skipped")
	}
	httpClient := _cc.Client(context.Background())
	_, err := httpClient.Get("https://di.dreamvat.com/posts/new")
	assert.NoError(t, err)
	t1 := _cc.AccessToken

	_, err = httpClient.Get("https://di.dreamvat.com/posts/new")
	assert.NoError(t, err)
	t2 := _cc.AccessToken

	assert.Equal(t, t1.AccessToken, t2.AccessToken)

	time.Sleep(5 * time.Second)

	_, err = httpClient.Get("https://di.dreamvat.com/posts/new")
	assert.NoError(t, err)
	t3 := _cc.AccessToken
	assert.NotEqual(t, t1.AccessToken, t3.AccessToken)
}
