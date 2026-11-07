package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// openIDConfiguration is the OIDC discovery document.
// Doc: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
type openIDConfiguration struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

func fetchDiscovery(ctx context.Context, httpClient HTTPDoer, url string) (*openIDConfiguration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("oidc: discovery request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := resolveHTTPClient(httpClient).Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc: discovery fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("oidc: discovery status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var doc openIDConfiguration
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("oidc: discovery decode: %w", err)
	}
	if doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" || doc.JWKSURI == "" {
		return nil, fmt.Errorf("oidc: discovery document missing required endpoints")
	}
	return &doc, nil
}
