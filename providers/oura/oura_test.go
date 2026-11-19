package oura_test

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/oura"
	"github.com/stretchr/testify/assert"
)

func provider() *oura.Provider {
	return oura.New(os.Getenv("OURA_KEY"), os.Getenv("OURA_SECRET"), "/foo", "user")
}

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("OURA_KEY"))
	a.Equal(p.Secret, os.Getenv("OURA_SECRET"))
	a.Equal(p.CallbackURL, "/foo")
}

func Test_ImplementsProvider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	a.Implements((*goth.Provider)(nil), provider())
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.BeginAuth("test_state")
	s := session.(*oura.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "https://cloud.ouraring.com/oauth/authorize")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://cloud.ouraring.com/oauth/authorize","AccessToken":"1234567890","UserID":"abc"}`)
	a.NoError(err)

	s := session.(*oura.Session)
	a.Equal(s.AuthURL, "https://cloud.ouraring.com/oauth/authorize")
	a.Equal(s.AccessToken, "1234567890")
	a.Equal(s.UserID, "abc")
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
