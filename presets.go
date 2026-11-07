package oidc

import "fmt"

// NewGoogle returns a client preset for Google OIDC.
func NewGoogle(cfg Config) (Client, error) {
	cfg.Issuer = IssuerGoogle
	return NewClient(cfg)
}

// NewOkta returns a client preset for Okta; Issuer must be the authorization server issuer URL.
func NewOkta(cfg Config) (Client, error) {
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("oidc: okta issuer is required")
	}
	return NewClient(cfg)
}

// NewMicrosoft returns a client preset for Microsoft identity platform (Azure AD v2).
func NewMicrosoft(cfg Config) (Client, error) {
	tenant := cfg.TenantID
	if tenant == "" {
		tenant = "common"
	}
	cfg.Issuer = fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", tenant)
	return NewClient(cfg)
}

// NewApple returns a client preset for Sign in with Apple.
// When ClientSecret is empty, ClientSecretProvider must supply the ES256 client_secret JWT.
func NewApple(cfg Config) (Client, error) {
	cfg.Issuer = IssuerApple
	if cfg.ClientSecret == "" && cfg.ClientSecretProvider == nil {
		return nil, fmt.Errorf("oidc: apple requires client secret or client secret provider")
	}
	return NewClient(cfg)
}
