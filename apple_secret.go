package oidc

import (
	"context"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AppleClientSecretParams holds inputs for generating an Apple Sign In client_secret JWT.
type AppleClientSecretParams struct {
	// TeamID is the Apple Developer team identifier.
	TeamID string
	// ClientID is the Services ID (client identifier).
	ClientID string
	// KeyID is the Sign in with Apple key identifier.
	KeyID string
	// PrivateKeyPEM is the ES256 private key in PEM format.
	PrivateKeyPEM []byte
	// TTL is how long the generated client_secret JWT remains valid; defaults to 5 minutes when zero.
	TTL time.Duration
}

// AppleClientSecretGenerator signs Apple client_secret JWTs (ES256).
// Production callers should use a real private key; tests may inject a signer via NewAppleClientSecretGeneratorWithSigner.
type AppleClientSecretGenerator struct {
	params AppleClientSecretParams
	signer func(params AppleClientSecretParams) (string, error)
}

// NewAppleClientSecretGenerator creates a generator that signs ES256 JWTs from PEM private keys.
func NewAppleClientSecretGenerator(params AppleClientSecretParams) *AppleClientSecretGenerator {
	return &AppleClientSecretGenerator{
		params: params,
		signer: signAppleClientSecret,
	}
}

// NewAppleClientSecretGeneratorWithSigner creates a generator with a custom signer (for tests).
func NewAppleClientSecretGeneratorWithSigner(params AppleClientSecretParams, signer func(AppleClientSecretParams) (string, error)) *AppleClientSecretGenerator {
	return &AppleClientSecretGenerator{params: params, signer: signer}
}

// ClientSecret implements ClientSecretProvider.
func (g *AppleClientSecretGenerator) ClientSecret(ctx context.Context) (string, error) {
	if g.signer == nil {
		return signAppleClientSecret(g.params)
	}
	return g.signer(g.params)
}

func signAppleClientSecret(params AppleClientSecretParams) (string, error) {
	key, err := jwt.ParseECPrivateKeyFromPEM(params.PrivateKeyPEM)
	if err != nil {
		return "", err
	}
	ttl := params.TTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	now := time.Now()
	claims := jwt.RegisteredClaims{
		Issuer:    params.TeamID,
		Subject:   params.ClientID,
		Audience:  jwt.ClaimStrings{IssuerApple},
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		IssuedAt:  jwt.NewNumericDate(now),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = params.KeyID
	return token.SignedString(key)
}
