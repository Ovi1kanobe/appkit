package identity

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// ServiceClient returns an HTTP client that calls another AppKit application
// as this one. Each request carries an access token that Rauthy issued to
// this application's client through the client credentials grant, addressed
// to target, the other application's Rauthy client ID, and renewed before it
// expires. The other application's service routes accept the token because
// target is in their audience, and grant the permissions its policy lists for
// this application's client ID.
//
// Rauthy must allow it: this application's client is confidential, has the
// client_credentials flow, and lists target under its allowed resources.
// A token request that Rauthy refuses fails the call with its error.
func (s *Sessions) ServiceClient(target string) (*http.Client, error) {
	if strings.TrimSpace(s.config.ClientSecret) == "" {
		return nil, errors.New("identity: service calls need a client secret; the client must be confidential")
	}
	if strings.TrimSpace(target) == "" {
		return nil, errors.New("identity: service calls need the target's client ID")
	}
	credentials := clientcredentials.Config{
		ClientID:       s.config.ClientID,
		ClientSecret:   s.config.ClientSecret,
		TokenURL:       s.verifier.provider.Endpoint().TokenURL,
		AuthStyle:      oauth2.AuthStyleInParams, // Rauthy reads the secret from the form, not basic auth.
		EndpointParams: url.Values{"resource": {target}},
	}
	// Token requests use the provider client, which refuses redirects and times
	// out; the calls themselves are bounded by their request contexts.
	tokens := credentials.TokenSource(oidc.ClientContext(context.Background(), s.verifier.httpClient))
	return &http.Client{Transport: &oauth2.Transport{Source: tokens}}, nil
}
