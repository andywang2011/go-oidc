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
	"sync"
	"time"
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

	body, err := readLimited(resp.Body, maxResponseBytes)
	if err != nil {
		return nil, fmt.Errorf("oidc: jwks read: %w", err)
	}
	var doc jwksDocument
	if err := json.Unmarshal(body, &doc); err != nil {
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
	x, err := decodeCoordinateBytes(xB64)
	if err != nil {
		return nil, fmt.Errorf("oidc: decode ec x: %w", err)
	}
	y, err := decodeCoordinateBytes(yB64)
	if err != nil {
		return nil, fmt.Errorf("oidc: decode ec y: %w", err)
	}
	byteLen := (curve.Params().BitSize + 7) / 8
	if len(x) > byteLen || len(y) > byteLen {
		return nil, fmt.Errorf("oidc: ec coordinate too large for %s", crv)
	}
	uncompressed := make([]byte, 1+2*byteLen)
	uncompressed[0] = 0x04
	copy(uncompressed[1+byteLen-len(x):1+byteLen], x)
	copy(uncompressed[1+2*byteLen-len(y):], y)
	pub, err := ecdsa.ParseUncompressedPublicKey(curve, uncompressed)
	if err != nil {
		return nil, fmt.Errorf("oidc: parse ec public key: %w", err)
	}
	return pub, nil
}

func decodeCoordinateBytes(b64 string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		raw, err = base64.URLEncoding.DecodeString(b64)
		if err != nil {
			return nil, err
		}
	}
	return raw, nil
}

// jwksCache caches JWKS keys with a TTL and refreshes once on unknown kid.
type jwksCache struct {
	mu        sync.Mutex
	ttl       time.Duration
	now       func() time.Time
	keys      map[string]crypto.PublicKey
	fetchedAt time.Time
}

func newJWKSCache(ttl time.Duration, now func() time.Time) *jwksCache {
	if ttl <= 0 {
		ttl = DefaultJWKSCacheTTL
	}
	if now == nil {
		now = time.Now
	}
	return &jwksCache{ttl: ttl, now: now}
}

func (c *jwksCache) fresh() bool {
	return c.keys != nil && c.now().Sub(c.fetchedAt) < c.ttl
}

// lookup returns the key for kid. A stale cache is refreshed first; an unknown
// kid against a fresh cache triggers exactly one forced refresh.
func (c *jwksCache) lookup(ctx context.Context, httpClient HTTPDoer, jwksURI, kid string) (crypto.PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	refreshed := false
	if !c.fresh() {
		if err := c.refreshLocked(ctx, httpClient, jwksURI); err != nil {
			return nil, err
		}
		refreshed = true
	}
	if key, ok := c.keys[kid]; ok {
		return key, nil
	}
	if !refreshed {
		if err := c.refreshLocked(ctx, httpClient, jwksURI); err != nil {
			return nil, err
		}
		if key, ok := c.keys[kid]; ok {
			return key, nil
		}
	}
	return nil, fmt.Errorf("oidc: jwks key %q not found", kid)
}

func (c *jwksCache) refreshLocked(ctx context.Context, httpClient HTTPDoer, jwksURI string) error {
	keys, err := fetchJWKS(ctx, httpClient, jwksURI)
	if err != nil {
		return err
	}
	c.keys = keys
	c.fetchedAt = c.now()
	return nil
}
