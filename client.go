package oidc

import (
	"context"
	"crypto"
	"fmt"
	"net/url"
	"strings"
	"sync"
)

type oidcClient struct {
	cfg        Config
	httpClient HTTPDoer

	mu        sync.Mutex
	discovery *openIDConfiguration
	jwks      *jwksCache
}

// NewClient creates an OIDC client from Config after validation.
func NewClient(cfg Config) (Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &oidcClient{
		cfg:        cfg,
		httpClient: resolveHTTPClient(cfg.HTTPClient),
		jwks:       newJWKSCache(cfg.JWKSCacheTTL, nil),
	}, nil
}

func (c *oidcClient) loadDiscovery(ctx context.Context) (*openIDConfiguration, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.discovery != nil {
		return c.discovery, nil
	}
	doc, err := fetchDiscovery(ctx, c.httpClient, c.cfg.discoveryEndpoint())
	if err != nil {
		return nil, err
	}
	if c.cfg.Issuer != "" {
		expected := normalizeIssuer(c.cfg.Issuer)
		if normalizeIssuer(doc.Issuer) != expected {
			return nil, fmt.Errorf("oidc: discovery issuer mismatch")
		}
	}
	c.discovery = doc
	return doc, nil
}

func (c *oidcClient) expectedIssuer(doc *openIDConfiguration) string {
	if c.cfg.Issuer != "" {
		return normalizeIssuer(c.cfg.Issuer)
	}
	return normalizeIssuer(doc.Issuer)
}

// AuthURL builds the authorization endpoint URL with PKCE S256 parameters.
func (c *oidcClient) AuthURL(ctx context.Context, state, nonce, codeChallenge string) (string, error) {
	if strings.TrimSpace(state) == "" {
		return "", fmt.Errorf("oidc: state is required")
	}
	if strings.TrimSpace(nonce) == "" {
		return "", fmt.Errorf("oidc: nonce is required")
	}
	if strings.TrimSpace(codeChallenge) == "" {
		return "", fmt.Errorf("oidc: code challenge is required")
	}

	doc, err := c.loadDiscovery(ctx)
	if err != nil {
		return "", err
	}

	q := url.Values{}
	q.Set("client_id", c.cfg.ClientID)
	q.Set("response_type", "code")
	q.Set("scope", strings.Join(c.cfg.resolvedScopes(), " "))
	q.Set("redirect_uri", c.cfg.RedirectURI)
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")

	u, err := url.Parse(doc.AuthorizationEndpoint)
	if err != nil {
		return "", fmt.Errorf("oidc: authorization endpoint: %w", err)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// Exchange trades the authorization code for ID and access tokens.
func (c *oidcClient) Exchange(ctx context.Context, code, codeVerifier string) (string, string, error) {
	if strings.TrimSpace(code) == "" {
		return "", "", fmt.Errorf("oidc: code is required")
	}
	if strings.TrimSpace(codeVerifier) == "" {
		return "", "", fmt.Errorf("oidc: code verifier is required")
	}
	doc, err := c.loadDiscovery(ctx)
	if err != nil {
		return "", "", err
	}
	return exchangeCode(ctx, c.httpClient, doc.TokenEndpoint, c.cfg, code, codeVerifier)
}

// VerifyIDToken validates the ID token using cached JWKS from discovery. The expected nonce is required.
func (c *oidcClient) VerifyIDToken(ctx context.Context, raw, nonce string) (*Claims, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("oidc: id token is required")
	}
	doc, err := c.loadDiscovery(ctx)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(nonce) == "" {
		return nil, ErrNonceRequired
	}
	lookup := func(ctx context.Context, kid string) (crypto.PublicKey, error) {
		return c.jwks.lookup(ctx, c.httpClient, doc.JWKSURI, kid)
	}
	return verifyIDToken(ctx, lookup, c.cfg.ClientID, c.expectedIssuer(doc), raw, nonce)
}
