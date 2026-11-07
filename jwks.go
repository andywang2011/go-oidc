package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
)

type jwksDocument struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func fetchJWKS(ctx context.Context, httpClient HTTPDoer, jwksURI string) (map[string]crypto.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("oidc: jwks request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := resolveHTTPClient(httpClient).Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc: jwks fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("oidc: jwks status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var doc jwksDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("oidc: jwks decode: %w", err)
	}

	keys := make(map[string]crypto.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kid == "" {
			continue
		}
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pub, err := jwkToPublicKey(k)
		if err != nil {
			return nil, err
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("oidc: jwks contains no usable signing keys")
	}
	return keys, nil
}

func jwkToPublicKey(k jwkKey) (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		return rsaPublicKeyFromJWK(k.N, k.E)
	case "EC":
		return ecPublicKeyFromJWK(k.Crv, k.X, k.Y)
	default:
		return nil, fmt.Errorf("oidc: unsupported jwk kty %q", k.Kty)
	}
}

func rsaPublicKeyFromJWK(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		nBytes, err = base64.URLEncoding.DecodeString(nB64)
		if err != nil {
			return nil, fmt.Errorf("oidc: decode rsa n: %w", err)
		}
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		eBytes, err = base64.URLEncoding.DecodeString(eB64)
		if err != nil {
			return nil, fmt.Errorf("oidc: decode rsa e: %w", err)
		}
	}
	var eInt int
	for _, b := range eBytes {
		eInt = eInt<<8 + int(b)
	}
	if eInt == 0 {
		return nil, fmt.Errorf("oidc: invalid rsa exponent")
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: eInt,
	}, nil
}

func ecPublicKeyFromJWK(crv, xB64, yB64 string) (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("oidc: unsupported ec curve %q", crv)
	}
	x, err := decodeCoordinate(xB64)
	if err != nil {
		return nil, fmt.Errorf("oidc: decode ec x: %w", err)
	}
	y, err := decodeCoordinate(yB64)
	if err != nil {
		return nil, fmt.Errorf("oidc: decode ec y: %w", err)
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

func decodeCoordinate(b64 string) (*big.Int, error) {
	raw, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		raw, err = base64.URLEncoding.DecodeString(b64)
		if err != nil {
			return nil, err
		}
	}
	return new(big.Int).SetBytes(raw), nil
}

func lookupPublicKey(ctx context.Context, httpClient HTTPDoer, jwksURI, kid string) (crypto.PublicKey, error) {
	keys, err := fetchJWKS(ctx, httpClient, jwksURI)
	if err != nil {
		return nil, err
	}
	key, ok := keys[kid]
	if !ok {
		return nil, fmt.Errorf("oidc: jwks key %q not found", kid)
	}
	return key, nil
}
