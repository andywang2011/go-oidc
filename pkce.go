package oidc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

const (
	codeVerifierMinLen = 43
	codeVerifierMaxLen = 128
)

// GenerateCodeVerifier returns a cryptographically random PKCE code verifier (43–128 characters).
func GenerateCodeVerifier() (string, error) {
	// 32 bytes -> 43 chars base64url without padding
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("oidc: generate code verifier: %w", err)
	}
	verifier := base64.RawURLEncoding.EncodeToString(b)
	if len(verifier) < codeVerifierMinLen || len(verifier) > codeVerifierMaxLen {
		return "", errors.New("oidc: generated code verifier length out of range")
	}
	return verifier, nil
}

// CodeChallengeS256 returns the PKCE S256 code challenge for the given verifier.
func CodeChallengeS256(codeVerifier string) (string, error) {
	if l := len(codeVerifier); l < codeVerifierMinLen || l > codeVerifierMaxLen {
		return "", fmt.Errorf("oidc: code verifier length must be between %d and %d", codeVerifierMinLen, codeVerifierMaxLen)
	}
	sum := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}
