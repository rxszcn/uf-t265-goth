package auth0_test

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/auth0"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("AUTH0_KEY"))
	a.Equal(p.Secret, os.Getenv("AUTH0_SECRET"))
	a.Equal(p.Domain, os.Getenv("AUTH0_DOMAIN"))
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
	s := session.(*auth0.Session)
	a.NoError(err)
	expectedAuthURL := "https://" + os.Getenv("AUTH0_DOMAIN") + "/authorize"
	a.Contains(s.AuthURL, expectedAuthURL)
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	sessionResp := `{"AuthURL":"https://` + p.Domain + `/oauth/authorize","AccessToken":"1234567890"}`
	session, err := p.UnmarshalSession(sessionResp)
	a.NoError(err)

	s := session.(*auth0.Session)
	expectedAuthURL := "https://" + os.Getenv("AUTH0_DOMAIN") + "/oauth/authorize"
	a.Equal(s.AuthURL, expectedAuthURL)
	a.Equal(s.AccessToken, "1234567890")
}

func Test_FetchUser(t *testing.T) {
	// t.Parallel()
	a := assert.New(t)

	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	sampleResp := `{
  		"email_verified": false,
  		"email": "test.account@userinfo.com",
  		"clientID": "q2hnj2iu...",
  		"updated_at": "2016-12-05T15:15:40.545Z",
  		"name": "test.account@userinfo.com",
  		"picture": "https://s.gravatar.com/avatar/dummy.png",
  		"user_id": "auth0|58454...",
  		"nickname": "test.account",
  		"identities": [
  		  {
      			"user_id": "58454...",
      			"provider": "auth0",
      			"connection": "Username-Password-Authentication",
      			"isSocial": false
    		}],
  		"created_at": "2016-12-05T11:16:59.640Z",
  		"sub": "auth0|58454..."
	}`

	httpmock.RegisterResponder("GET", "https://"+os.Getenv("AUTH0_DOMAIN")+"/userinfo", httpmock.NewStringResponder(200, sampleResp))

	p := provider()
	session, _ := p.BeginAuth("test_state")
	s := session.(*auth0.Session)
	s.AccessToken = "token"
	u, err := p.FetchUser(s)
	a.Nil(err)
	a.Equal(u.Email, "test.account@userinfo.com")
	a.Equal(u.UserID, "auth0|58454...")
	a.Equal(u.NickName, "test.account")
	a.Equal(u.Name, "test.account@userinfo.com")
	a.Equal("token", u.AccessToken)

}

func provider() *auth0.Provider {
	return auth0.New(os.Getenv("AUTH0_KEY"), os.Getenv("AUTH0_SECRET"), "/foo", os.Getenv("AUTH0_DOMAIN"))
}

// fakeRoundTripper sends every request to the loopback token endpoint while
// counting how many requests pass through it.
type fakeRoundTripper struct {
	loopback string
	count    int32
}

func (f *fakeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	atomic.AddInt32(&f.count, 1)
	req.URL.Scheme = "http"
	req.URL.Host = f.loopback
	return http.DefaultTransport.RoundTrip(req)
}

// rejectingRoundTripper stands in for the process default client: it counts
// requests and refuses them, so any refresh that bypasses the injected client
// shows up as a non-zero count instead of touching the network.
type rejectingRoundTripper struct {
	count int32
}

func (r *rejectingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	atomic.AddInt32(&r.count, 1)
	return nil, errors.New("process default client must not be used to refresh tokens")
}

func newLoopbackTokenServer(t *testing.T, status int, body string) (*httptest.Server, *int32) {
	t.Helper()
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func swapDefaultClient(counter *rejectingRoundTripper) func() {
	original := http.DefaultClient
	http.DefaultClient = &http.Client{Transport: counter}
	return func() { http.DefaultClient = original }
}

func Test_RefreshTokenUsesInjectedClient(t *testing.T) {
	a := assert.New(t)

	srv, loopbackHits := newLoopbackTokenServer(t, http.StatusOK,
		`{"access_token":"refreshed-access-token","token_type":"Bearer","refresh_token":"refreshed-refresh-token","expires_in":3600}`)

	injected := &fakeRoundTripper{loopback: strings.TrimPrefix(srv.URL, "http://")}
	rejected := &rejectingRoundTripper{}
	defer swapDefaultClient(rejected)()

	p := provider()
	p.HTTPClient = &http.Client{Transport: injected}

	token, err := p.RefreshToken("existing-refresh-token")

	// Routing is asserted before the token is inspected so that a refresh which
	// ignores the injected client fails on the count, not on a nil token.
	a.Equal(int32(1), atomic.LoadInt32(&injected.count), "injected client should carry the refresh request")
	a.Equal(int32(1), atomic.LoadInt32(loopbackHits), "loopback token endpoint should be hit once")
	a.Equal(int32(0), atomic.LoadInt32(&rejected.count), "refresh must not use the process default client")

	a.NoError(err)
	if !a.NotNil(token, "refresh should return a token") {
		return
	}
	a.Equal("refreshed-access-token", token.AccessToken)
}

func Test_RefreshTokenFailurePath(t *testing.T) {
	a := assert.New(t)

	srv, loopbackHits := newLoopbackTokenServer(t, http.StatusBadRequest, `{"error":"invalid_grant"}`)

	injected := &fakeRoundTripper{loopback: strings.TrimPrefix(srv.URL, "http://")}
	rejected := &rejectingRoundTripper{}
	defer swapDefaultClient(rejected)()

	p := provider()
	p.HTTPClient = &http.Client{Transport: injected}

	token, err := p.RefreshToken("stale-refresh-token")

	a.Error(err)
	a.Nil(token)

	// oauth2 retries once with the alternative client-auth style when the token
	// endpoint rejects the first attempt, so the failure path may issue more
	// than one request. Every one of them must still travel through the
	// injected client.
	injectedCount := atomic.LoadInt32(&injected.count)
	a.GreaterOrEqual(injectedCount, int32(1))
	a.Equal(injectedCount, atomic.LoadInt32(loopbackHits))
	a.Equal(int32(0), atomic.LoadInt32(&rejected.count), "failed refresh must not fall back to the process default client")
}
