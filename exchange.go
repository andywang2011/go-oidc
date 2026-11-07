package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

func exchangeCode(
	ctx context.Context,
	httpClient HTTPDoer,
	tokenEndpoint string,
	cfg Config,
	code, codeVerifier string,
) (idToken, accessToken string, err error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", cfg.RedirectURI)
	form.Set("client_id", cfg.ClientID)
	form.Set("code_verifier", codeVerifier)

	secret, err := resolveClientSecret(ctx, cfg)
	if err != nil {
		return "", "", err
	}
	if secret != "" {
		form.Set("client_secret", secret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", "", fmt.Errorf("oidc: token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := resolveHTTPClient(httpClient).Do(req)
	if err != nil {
		return "", "", fmt.Errorf("oidc: token exchange: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", "", fmt.Errorf("oidc: read token response: %w", err)
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", "", fmt.Errorf("oidc: decode token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		if tr.Error != "" {
			return "", "", fmt.Errorf("oidc: token error %s: %s", tr.Error, tr.ErrorDesc)
		}
		return "", "", fmt.Errorf("oidc: token status %d", resp.StatusCode)
	}
	if tr.IDToken == "" {
		return "", "", fmt.Errorf("oidc: token response missing id_token")
	}
	return tr.IDToken, tr.AccessToken, nil
}

func resolveClientSecret(ctx context.Context, cfg Config) (string, error) {
	if strings.TrimSpace(cfg.ClientSecret) != "" {
		return cfg.ClientSecret, nil
	}
	if cfg.ClientSecretProvider != nil {
		secret, err := cfg.ClientSecretProvider.ClientSecret(ctx)
		if err != nil {
			return "", fmt.Errorf("oidc: client secret provider: %w", err)
		}
		return secret, nil
	}
	return "", nil
}
