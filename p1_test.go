package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestResolveHTTPClientDefaultTimeout(t *testing.T) {
	c, ok := resolveHTTPClient(nil).(*http.Client)
	if !ok {
		t.Fatal("expected *http.Client")
	}
	if c == http.DefaultClient {
		t.Fatal("must not use http.DefaultClient")
	}
	if c.Timeout != 10*time.Second {
		t.Fatalf("timeout = %v", c.Timeout)
	}
	custom := &http.Client{}
	if resolveHTTPClient(custom) != HTTPDoer(custom) {
		t.Fatal("custom client must be preserved")
	}
}

func TestReadLimited(t *testing.T) {
	if _, err := readLimited(strings.NewReader("abcd"), 3); err == nil {
		t.Fatal("expected size error")
	}
	b, err := readLimited(strings.NewReader("abc"), 3)
	if err != nil || string(b) != "abc" {
		t.Fatalf("b=%q err=%v", b, err)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func TestReadLimitedReadError(t *testing.T) {
	if _, err := readLimited(errReader{}, 10); err == nil {
		t.Fatal("expected read error")
	}
}

func oversizedServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"pad":"`))
		chunk := []byte(strings.Repeat("a", 1<<20))
		for i := 0; i < 5; i++ {
			_, _ = w.Write(chunk)
		}
		_, _ = w.Write([]byte(`"}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestFetchDiscoveryBodyTooLarge(t *testing.T) {
	srv := oversizedServer(t)
	_, err := fetchDiscovery(context.Background(), srv.Client(), srv.URL)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err = %v", err)
	}
}

func TestFetchJWKSBodyTooLarge(t *testing.T) {
	srv := oversizedServer(t)
	_, err := fetchJWKS(context.Background(), srv.Client(), srv.URL)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err = %v", err)
	}
}

func TestFetchJWKSNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()
	if _, err := fetchJWKS(context.Background(), srv.Client(), srv.URL); err == nil {
		t.Fatal("expected error")
	}
	if _, err := fetchDiscovery(context.Background(), srv.Client(), srv.URL); err == nil {
		t.Fatal("expected error")
	}
}

// jwksEnv serves a mutable JWKS and counts fetches.
type jwksEnv struct {
	srv   *httptest.Server
	keys  atomic.Value // map[string]*rsa.PrivateKey
	calls atomic.Int32
}

func newJWKSEnv(t *testing.T, initial map[string]*rsa.PrivateKey) *jwksEnv {
	t.Helper()
	e := &jwksEnv{}
	e.keys.Store(initial)
	e.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.calls.Add(1)
		var list []map[string]string
		for kid, k := range e.keys.Load().(map[string]*rsa.PrivateKey) {
			list = append(list, map[string]string{
				"kty": "RSA", "kid": kid, "use": "sig",
				"n": base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
			})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": list})
	}))
	t.Cleanup(e.srv.Close)
	return e
}

func genKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestJWKSCacheHitAndTTL(t *testing.T) {
	env := newJWKSEnv(t, map[string]*rsa.PrivateKey{"k1": genKey(t)})
	now := time.Unix(1000, 0)
	cache := newJWKSCache(time.Minute, func() time.Time { return now })
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if _, err := cache.lookup(ctx, env.srv.Client(), env.srv.URL, "k1"); err != nil {
			t.Fatal(err)
		}
	}
	if got := env.calls.Load(); got != 1 {
		t.Fatalf("fetches = %d, want 1 (cached)", got)
	}

	now = now.Add(2 * time.Minute)
	if _, err := cache.lookup(ctx, env.srv.Client(), env.srv.URL, "k1"); err != nil {
		t.Fatal(err)
	}
	if got := env.calls.Load(); got != 2 {
		t.Fatalf("fetches = %d, want 2 after TTL", got)
	}
}

func TestJWKSCacheRefreshOnceOnUnknownKid(t *testing.T) {
	env := newJWKSEnv(t, map[string]*rsa.PrivateKey{"k1": genKey(t)})
	cache := newJWKSCache(time.Hour, nil)
	ctx := context.Background()

	if _, err := cache.lookup(ctx, env.srv.Client(), env.srv.URL, "k1"); err != nil {
		t.Fatal(err)
	}
	// Rotate: k2 appears.
	env.keys.Store(map[string]*rsa.PrivateKey{"k1": genKey(t), "k2": genKey(t)})
	if _, err := cache.lookup(ctx, env.srv.Client(), env.srv.URL, "k2"); err != nil {
		t.Fatalf("rotated key: %v", err)
	}
	if got := env.calls.Load(); got != 2 {
		t.Fatalf("fetches = %d, want 2", got)
	}

	// Truly unknown kid: exactly one extra refresh, then error.
	before := env.calls.Load()
	if _, err := cache.lookup(ctx, env.srv.Client(), env.srv.URL, "nope"); err == nil {
		t.Fatal("expected not found")
	}
	if got := env.calls.Load() - before; got != 1 {
		t.Fatalf("refreshes for unknown kid = %d, want 1", got)
	}
}

func TestJWKSCacheColdUnknownKidSingleFetch(t *testing.T) {
	env := newJWKSEnv(t, map[string]*rsa.PrivateKey{"k1": genKey(t)})
	cache := newJWKSCache(time.Hour, nil)
	if _, err := cache.lookup(context.Background(), env.srv.Client(), env.srv.URL, "x"); err == nil {
		t.Fatal("expected error")
	}
	if got := env.calls.Load(); got != 1 {
		t.Fatalf("fetches = %d, want 1 on cold cache", got)
	}
}

func TestJWKSCacheFetchErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "x", http.StatusBadGateway)
	}))
	defer srv.Close()
	cache := newJWKSCache(0, nil)
	if cache.ttl != DefaultJWKSCacheTTL {
		t.Fatalf("ttl = %v", cache.ttl)
	}
	if _, err := cache.lookup(context.Background(), srv.Client(), srv.URL, "k"); err == nil {
		t.Fatal("expected error on cold fetch")
	}

	// Stale-cache refresh failure and unknown-kid refresh failure.
	env := newJWKSEnv(t, map[string]*rsa.PrivateKey{"k1": genKey(t)})
	c2 := newJWKSCache(time.Hour, nil)
	if _, err := c2.lookup(context.Background(), env.srv.Client(), env.srv.URL, "k1"); err != nil {
		t.Fatal(err)
	}
	if _, err := c2.lookup(context.Background(), srv.Client(), srv.URL, "unknown"); err == nil {
		t.Fatal("expected refresh error")
	}
}

func TestVerifyIDTokenUsesJWKSCache(t *testing.T) {
	env := newTestOIDCEnv(t)
	defer env.close()
	var jwksCalls atomic.Int32
	inner := env.server.Config.Handler
	env.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/jwks" {
			jwksCalls.Add(1)
		}
		inner.ServeHTTP(w, r)
	})
	client := env.newClient(t, nil)
	raw, err := env.signIDToken("u", "n1", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := client.VerifyIDToken(context.Background(), raw, "n1"); err != nil {
			t.Fatal(err)
		}
	}
	if got := jwksCalls.Load(); got != 1 {
		t.Fatalf("jwks fetches = %d, want 1", got)
	}
}

func TestVerifyIDTokenNonceRequired(t *testing.T) {
	env := newTestOIDCEnv(t)
	defer env.close()
	client := env.newClient(t, nil)

	raw, err := env.signIDToken("u", "n1", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"", "   "} {
		if _, err := client.VerifyIDToken(context.Background(), raw, n); !errors.Is(err, ErrNonceRequired) {
			t.Fatalf("nonce %q: err = %v", n, err)
		}
	}

	noNonce, err := env.signIDToken("u", "", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.VerifyIDToken(context.Background(), noNonce, "n1"); err == nil ||
		!strings.Contains(err.Error(), "nonce required") {
		t.Fatalf("err = %v", err)
	}
}

func TestVerifyIDTokenInternalNonceRequired(t *testing.T) {
	_, err := verifyIDToken(context.Background(), nil, "c", "iss", "raw", "")
	if !errors.Is(err, ErrNonceRequired) {
		t.Fatalf("err = %v", err)
	}
}

func TestAuthURLHonorsContext(t *testing.T) {
	env := newTestOIDCEnv(t)
	defer env.close()
	client := env.newClient(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.AuthURL(ctx, "s", "n", "c"); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestAuthURLValidation(t *testing.T) {
	env := newTestOIDCEnv(t)
	defer env.close()
	client := env.newClient(t, nil)
	ctx := context.Background()
	for _, args := range [][3]string{{"", "n", "c"}, {"s", "", "c"}, {"s", "n", ""}} {
		if _, err := client.AuthURL(ctx, args[0], args[1], args[2]); err == nil {
			t.Fatalf("args %v: expected error", args)
		}
	}
}

func TestConfigValidateNegativeJWKSTTL(t *testing.T) {
	cfg := Config{ClientID: "c", Issuer: "https://i", RedirectURI: "https://r", JWKSCacheTTL: -1}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error")
	}
}
