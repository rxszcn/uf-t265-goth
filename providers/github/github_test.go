package github_test

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync/atomic"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/github"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := githubProvider()
	a.Equal(provider.ClientKey, os.Getenv("GITHUB_KEY"))
	a.Equal(provider.Secret, os.Getenv("GITHUB_SECRET"))
	a.Equal(provider.CallbackURL, "/foo")
}

func Test_NewCustomisedURL(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := urlCustomisedURLProvider()
	session, err := p.BeginAuth("test_state")
	s := session.(*github.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "http://authURL")
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	a.Implements((*goth.Provider)(nil), githubProvider())
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := githubProvider()
	session, err := provider.BeginAuth("test_state")
	s := session.(*github.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "github.com/login/oauth/authorize")
	a.Contains(s.AuthURL, fmt.Sprintf("client_id=%s", os.Getenv("GITHUB_KEY")))
	a.Contains(s.AuthURL, "state=test_state")
	a.Contains(s.AuthURL, "scope=user")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := githubProvider()

	s, err := provider.UnmarshalSession(`{"AuthURL":"http://github.com/auth_url","AccessToken":"1234567890"}`)
	a.NoError(err)
	session := s.(*github.Session)
	a.Equal(session.AuthURL, "http://github.com/auth_url")
	a.Equal(session.AccessToken, "1234567890")
}

func githubProvider() *github.Provider {
	return github.New(os.Getenv("GITHUB_KEY"), os.Getenv("GITHUB_SECRET"), "/foo", "user")
}

func urlCustomisedURLProvider() *github.Provider {
	return github.NewCustomisedURL(os.Getenv("GITHUB_KEY"), os.Getenv("GITHUB_SECRET"), "/foo", "http://authURL", "http://tokenURL", "http://profileURL", "http://emailURL")
}

// rejectedRoundTripper counts requests and refuses them. Nothing may travel
// through it: a provider without a refresh endpoint must stay offline.
type rejectedRoundTripper struct {
	count int32
}

func (r *rejectedRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	atomic.AddInt32(&r.count, 1)
	return nil, errors.New("no refresh request is expected")
}

func swapDefaultClient(counter *rejectedRoundTripper) func() {
	original := http.DefaultClient
	http.DefaultClient = &http.Client{Transport: counter}
	return func() { http.DefaultClient = original }
}

func Test_RefreshTokenUnsupported(t *testing.T) {
	a := assert.New(t)

	counter := &rejectedRoundTripper{}
	defer swapDefaultClient(counter)()

	p := githubProvider()

	token, err := p.RefreshToken("some-refresh-token")

	a.EqualError(err, "Refresh token is not provided by github")
	a.Nil(token)
	a.Equal(int32(0), atomic.LoadInt32(&counter.count), "an unsupported refresh must not reach the network")
}
