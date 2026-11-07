package oidc

import "context"

// Claims holds standard OIDC ID token profile claims used by this library.
type Claims struct {
	// Sub is the subject identifier.
	Sub string
	// Email is the user's email address when present in the token.
	Email string
	// Name is the user's display name when present in the token.
	Name string
	// Picture is a profile picture URL when present in the token.
	Picture string
	// EmailVerified indicates whether the email address was verified by the IdP.
	EmailVerified bool
}

// Client performs OIDC authorization code flow operations with PKCE.
type Client interface {
	// AuthURL builds the authorization endpoint URL with state, nonce, and PKCE challenge.
	// ctx bounds the discovery request when the document is not cached yet.
	AuthURL(ctx context.Context, state, nonce, codeChallenge string) (string, error)
	// Exchange trades an authorization code for tokens using the PKCE code verifier.
	Exchange(ctx context.Context, code, codeVerifier string) (idToken string, accessToken string, err error)
	// VerifyIDToken validates the raw ID token signature and claims, requiring a non-empty nonce that matches the token.
	VerifyIDToken(ctx context.Context, raw string, nonce string) (*Claims, error)
}
