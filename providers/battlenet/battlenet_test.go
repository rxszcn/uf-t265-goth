package battlenet_test

import (
	"errors"
	"net/http"
	"os"
	"sync/atomic"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/battlenet"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("BATTLENET_KEY"))
	a.Equal(p.Secret, os.Getenv("BATTLENET_SECRET"))
	a.Equal(p.CallbackURL, "/foo")
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	a.Implements((*goth.Provider)(nil), provider())
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()
	session, err := p.BeginAuth("test_state")
	s := session.(*battlenet.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "us.battle.net/oauth/authorize")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://us.battle.net/oauth/authorize","AccessToken":"1234567890"}`)
	a.NoError(err)

	s := session.(*battlenet.Session)
	a.Equal(s.AuthURL, "https://us.battle.net/oauth/authorize")
	a.Equal(s.AccessToken, "1234567890")
}

func provider() *battlenet.Provider {
	return battlenet.New(os.Getenv("BATTLENET_KEY"), os.Getenv("BATTLENET_SECRET"), "/foo")
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

func Test_RefreshTokenIssuesNoRequest(t *testing.T) {
	a := assert.New(t)

	counter := &rejectedRoundTripper{}
	defer swapDefaultClient(counter)()

	p := provider()

	token, err := p.RefreshToken("some-refresh-token")

	a.NoError(err)
	a.Nil(token)
	a.Equal(int32(0), atomic.LoadInt32(&counter.count), "a provider without a refresh endpoint must not reach the network")
}
