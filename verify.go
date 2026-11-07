package oidc

import (
	"context"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

type idTokenClaims struct {
	jwt.RegisteredClaims
	Email         string `json:"email"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	EmailVerified bool   `json:"email_verified"`
	Nonce         string `json:"nonce"`
}

func verifyIDToken(ctx context.Context, httpClient HTTPDoer, jwksURI, clientID, expectedIssuer, raw, nonce string) (*Claims, error) {
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}))
	unverified, _, err := parser.ParseUnverified(raw, &idTokenClaims{})
	if err != nil {
		return nil, fmt.Errorf("oidc: parse id token: %w", err)
	}
	kid, ok := unverified.Header["kid"].(string)
	if !ok || kid == "" {
		return nil, fmt.Errorf("oidc: id token missing kid header")
	}

	pub, err := lookupPublicKey(ctx, httpClient, jwksURI, kid)
	if err != nil {
		return nil, err
	}

	token, err := jwt.ParseWithClaims(raw, &idTokenClaims{}, func(t *jwt.Token) (interface{}, error) {
		return pub, nil
	}, jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}))
	if err != nil {
		return nil, fmt.Errorf("oidc: verify id token: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("oidc: id token invalid")
	}

	claims, ok := token.Claims.(*idTokenClaims)
	if !ok {
		return nil, fmt.Errorf("oidc: unexpected claims type")
	}

	if expectedIssuer != "" && claims.Issuer != expectedIssuer {
		return nil, fmt.Errorf("oidc: issuer mismatch")
	}
	if !audienceContains(claims.Audience, clientID) {
		return nil, fmt.Errorf("oidc: audience mismatch")
	}
	if claims.Nonce != "" && nonce != "" && claims.Nonce != nonce {
		return nil, fmt.Errorf("oidc: nonce mismatch")
	}
	if nonce != "" && claims.Nonce == "" {
		return nil, fmt.Errorf("oidc: nonce required but not present in token")
	}

	return &Claims{
		Sub:           claims.Subject,
		Email:         claims.Email,
		Name:          claims.Name,
		Picture:       claims.Picture,
		EmailVerified: claims.EmailVerified,
	}, nil
}

func audienceContains(aud jwt.ClaimStrings, clientID string) bool {
	for _, a := range aud {
		if a == clientID {
			return true
		}
	}
	return false
}

func normalizeIssuer(issuer string) string {
	return strings.TrimRight(strings.TrimSpace(issuer), "/")
}
