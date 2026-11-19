package openidConnect

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/markbates/goth"
	"github.com/stretchr/testify/assert"
)

var (
	server *httptest.Server
)

func init() {
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// return the value of Google's setup at https://accounts.google.com/.well-known/openid-configuration
		fmt.Fprintln(w, "{ \"issuer\": \"https://accounts.google.com\", \"authorization_endpoint\": \"https://accounts.google.com/o/oauth2/v2/auth\", \"token_endpoint\": \"https://www.googleapis.com/oauth2/v4/token\", \"userinfo_endpoint\": \"https://www.googleapis.com/oauth2/v3/userinfo\", \"revocation_endpoint\": \"https://accounts.google.com/o/oauth2/revoke\", \"jwks_uri\": \"https://www.googleapis.com/oauth2/v3/certs\", \"response_types_supported\": [ \"code\", \"token\", \"id_token\", \"code token\", \"code id_token\", \"token id_token\", \"code token id_token\", \"none\" ], \"subject_types_supported\": [ \"public\" ], \"id_token_signing_alg_values_supported\": [ \"RS256\" ], \"scopes_supported\": [ \"openid\", \"email\", \"profile\" ], \"token_endpoint_auth_methods_supported\": [ \"client_secret_post\", \"client_secret_basic\" ], \"claims_supported\": [ \"aud\", \"email\", \"email_verified\", \"exp\", \"family_name\", \"given_name\", \"iat\", \"iss\", \"locale\", \"name\", \"picture\", \"sub\" ], \"code_challenge_methods_supported\": [ \"plain\", \"S256\" ] }")
	}))
}

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := openidConnectProvider()
	a.Equal(os.Getenv("OPENID_CONNECT_KEY"), provider.ClientKey)
	a.Equal(os.Getenv("OPENID_CONNECT_SECRET"), provider.Secret)
	a.Equal("http://localhost/foo", provider.CallbackURL)

	a.Equal("https://accounts.google.com", provider.OpenIDConfig.Issuer)
	a.Equal("https://accounts.google.com/o/oauth2/v2/auth", provider.OpenIDConfig.AuthEndpoint)
	a.Equal("https://www.googleapis.com/oauth2/v4/token", provider.OpenIDConfig.TokenEndpoint)
	a.Equal("https://www.googleapis.com/oauth2/v3/userinfo", provider.OpenIDConfig.UserInfoEndpoint)
}

func Test_NewCustomisedURL(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider, _ := NewCustomisedURL(
		os.Getenv("OPENID_CONNECT_KEY"),
		os.Getenv("OPENID_CONNECT_SECRET"),
		"http://localhost/foo",
		"https://accounts.google.com/o/oauth2/v2/auth",
		"https://www.googleapis.com/oauth2/v4/token",
		"https://accounts.google.com",
		"https://www.googleapis.com/oauth2/v3/userinfo",
		"",
		server.URL,
	)
	a.Equal(os.Getenv("OPENID_CONNECT_KEY"), provider.ClientKey)
	a.Equal(os.Getenv("OPENID_CONNECT_SECRET"), provider.Secret)
	a.Equal("http://localhost/foo", provider.CallbackURL)

	a.Equal("https://accounts.google.com", provider.OpenIDConfig.Issuer)
	a.Equal("https://accounts.google.com/o/oauth2/v2/auth", provider.OpenIDConfig.AuthEndpoint)
	a.Equal("https://www.googleapis.com/oauth2/v4/token", provider.OpenIDConfig.TokenEndpoint)
	a.Equal("https://www.googleapis.com/oauth2/v3/userinfo", provider.OpenIDConfig.UserInfoEndpoint)
	a.Equal("", provider.OpenIDConfig.EndSessionEndpoint)
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := openidConnectProvider()
	session, err := provider.BeginAuth("test_state")
	s := session.(*Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "https://accounts.google.com/o/oauth2/v2/auth")
	a.Contains(s.AuthURL, fmt.Sprintf("client_id=%s", os.Getenv("OPENID_CONNECT_KEY")))
	a.Contains(s.AuthURL, "state=test_state")
	a.Contains(s.AuthURL, "redirect_uri=http%3A%2F%2Flocalhost%2Ffoo")
	a.Contains(s.AuthURL, "scope=openid")
}

func Test_BeginAuth_AuthCodeOptions(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := openidConnectProvider()
	provider.SetAuthCodeOptions(map[string]string{"domain_hint": "test_domain.com", "prompt": "none"})
	session, err := provider.BeginAuth("test_state")
	s := session.(*Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "https://accounts.google.com/o/oauth2/v2/auth")
	a.Contains(s.AuthURL, fmt.Sprintf("client_id=%s", os.Getenv("OPENID_CONNECT_KEY")))
	a.Contains(s.AuthURL, "state=test_state")
	a.Contains(s.AuthURL, "redirect_uri=http%3A%2F%2Flocalhost%2Ffoo")
	a.Contains(s.AuthURL, "scope=openid")
	a.Contains(s.AuthURL, "domain_hint=test_domain.com")
	a.Contains(s.AuthURL, "prompt=none")
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	a.Implements((*goth.Provider)(nil), openidConnectProvider())
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := openidConnectProvider()

	s, err := provider.UnmarshalSession(`{"AuthURL":"https://accounts.google.com/o/oauth2/v2/auth","AccessToken":"1234567890","IDToken":"abc"}`)
	a.NoError(err)
	session := s.(*Session)
	a.Equal("https://accounts.google.com/o/oauth2/v2/auth", session.AuthURL)
	a.Equal("1234567890", session.AccessToken)
	a.Equal("abc", session.IDToken)
}

func openidConnectProvider() *Provider {
	provider, _ := New(os.Getenv("OPENID_CONNECT_KEY"), os.Getenv("OPENID_CONNECT_SECRET"), "http://localhost/foo", server.URL)
	return provider
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

	// The provider is built before the default client is swapped out, because
	// openidConnectProvider performs its auto-discovery request on construction.
	p := openidConnectProvider()

	injected := &fakeRoundTripper{loopback: strings.TrimPrefix(srv.URL, "http://")}
	rejected := &rejectingRoundTripper{}
	defer swapDefaultClient(rejected)()

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

	// The provider is built before the default client is swapped out, because
	// openidConnectProvider performs its auto-discovery request on construction.
	p := openidConnectProvider()

	injected := &fakeRoundTripper{loopback: strings.TrimPrefix(srv.URL, "http://")}
	rejected := &rejectingRoundTripper{}
	defer swapDefaultClient(rejected)()

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
