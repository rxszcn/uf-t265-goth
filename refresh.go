package goth

import (
	"net/http"

	"golang.org/x/oauth2"
)

// RefreshAccessToken exchanges refreshToken for a new access token using the
// provider's oauth2 configuration and HTTP client.
//
// It is the single shared implementation of the provider RefreshToken logic.
// Providers that only differ in where their oauth2 configuration and HTTP
// client live delegate here, so that a client injected into a provider is
// always the client that performs the outgoing token request.
//
// The client is routed through ContextForClient, which is how oauth2 picks up
// a custom *http.Client. HTTPClientWithFallBack keeps the historical behaviour
// of providers whose client is nil: the process default client is used.
//
// A failed token retrieval returns a nil token and the error unchanged, which
// matches the behaviour providers had when the logic was copied into each
// package.
func RefreshAccessToken(config *oauth2.Config, client *http.Client, refreshToken string) (*oauth2.Token, error) {
	token := &oauth2.Token{RefreshToken: refreshToken}
	ts := config.TokenSource(ContextForClient(HTTPClientWithFallBack(client)), token)
	newToken, err := ts.Token()
	if err != nil {
		return nil, err
	}
	return newToken, nil
}
