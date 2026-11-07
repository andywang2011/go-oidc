package oidc

import (
	"context"
	"errors"
	"strings"
)

const (
	// IssuerGoogle is the Google OIDC issuer.
	// Doc: https://developers.google.com/identity/openid-connect/openid-connect
	IssuerGoogle = "https://accounts.google.com"

	// IssuerApple is the Apple Sign In OIDC issuer.
	// Doc: https://developer.apple.com/documentation/signinwithapple/sign-in-with-apple-rest-api
	IssuerApple = "https://appleid.apple.com"
)

var defaultScopes = []string{"openid", "profile", "email"}

// ClientSecretProvider supplies a dynamic OAuth client_secret (for example Apple ES256 JWT).
type ClientSecretProvider interface {
	// ClientSecret returns a client_secret valid at request time.
	ClientSecret(ctx context.Context) (string, error)
}

// Config holds OIDC client settings for the authorization code flow with PKCE.
type Config struct {
	// ClientID is the OAuth 2.0 client identifier.
	ClientID string
	// ClientSecret is the static client secret; leave empty for public PKCE clients.
	ClientSecret string
	// Issuer is the OIDC issuer URL (used for discovery and ID token validation).
	Issuer string
	// RedirectURI is the registered OAuth redirect URI.
	RedirectURI string
	// Scopes requested during authorization; defaults to openid, profile, email when empty.
	Scopes []string
	// TenantID is the Azure AD tenant for Microsoft preset (defaults to "common" when empty).
	TenantID string
	// HTTPClient performs discovery, JWKS, and token HTTP calls; nil uses http.DefaultClient.
	HTTPClient HTTPDoer
	// ClientSecretProvider supplies client_secret when ClientSecret is empty (Apple Sign In).
	ClientSecretProvider ClientSecretProvider
	// DiscoveryURL overrides the well-known configuration URL (for httptest).
	DiscoveryURL string
}

// ConfigDefault returns a Config with default scopes.
func ConfigDefault() Config {
	return Config{Scopes: append([]string(nil), defaultScopes...)}
}

// Validate checks required fields for NewClient.
func (c Config) Validate() error {
	if strings.TrimSpace(c.ClientID) == "" {
		return errors.New("oidc client id is not set")
	}
	if strings.TrimSpace(c.Issuer) == "" && strings.TrimSpace(c.DiscoveryURL) == "" {
		return errors.New("oidc issuer or discovery url is not set")
	}
	if strings.TrimSpace(c.RedirectURI) == "" {
		return errors.New("oidc redirect uri is not set")
	}
	return nil
}

func (c Config) resolvedScopes() []string {
	if len(c.Scopes) == 0 {
		return append([]string(nil), defaultScopes...)
	}
	return append([]string(nil), c.Scopes...)
}

func (c Config) discoveryEndpoint() string {
	if strings.TrimSpace(c.DiscoveryURL) != "" {
		return strings.TrimSpace(c.DiscoveryURL)
	}
	return strings.TrimRight(c.Issuer, "/") + "/.well-known/openid-configuration"
}
