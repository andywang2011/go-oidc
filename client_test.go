package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type testOIDCEnv struct {
	server   *httptest.Server
	issuer   string
	clientID string
	rsaKey   *rsa.PrivateKey
	kid      string
}

func newTestOIDCEnv(t *testing.T) *testOIDCEnv {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	env := &testOIDCEnv{
		clientID: "test-client",
		rsaKey:   key,
		kid:      "test-kid",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		doc := openIDConfiguration{
			Issuer:                env.issuer,
			AuthorizationEndpoint: env.server.URL + "/authorize",
			TokenEndpoint:         env.server.URL + "/token",
			JWKSURI:               env.server.URL + "/jwks",
		}
		_ = json.NewEncoder(w).Encode(doc)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
		payload := map[string]interface{}{
			"keys": []map[string]string{
				{"kty": "RSA", "kid": env.kid, "use": "sig", "alg": "RS256", "n": n, "e": e},
			},
		}
		_ = json.NewEncoder(w).Encode(payload)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if r.Form.Get("grant_type") != "authorization_code" {
			http.Error(w, "invalid grant", http.StatusBadRequest)
			return
		}
		if r.Form.Get("client_id") != env.clientID {
			http.Error(w, "invalid client", http.StatusUnauthorized)
			return
		}
		if r.Form.Get("code_verifier") == "" {
			http.Error(w, "missing verifier", http.StatusBadRequest)
			return
		}
		if secret := r.Form.Get("client_secret"); secret != "" && secret != "static-secret" && secret != "apple-jwt-secret" {
			http.Error(w, "bad secret", http.StatusUnauthorized)
			return
		}
		idToken, err := env.signIDToken("user-1", "nonce-abc", time.Now().Add(time.Hour))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(tokenResponse{
			AccessToken: "access-token",
			IDToken:     idToken,
			TokenType:   "Bearer",
		})
	})

	env.server = httptest.NewServer(mux)
	env.issuer = env.server.URL
	return env
}

func (e *testOIDCEnv) close() {
	e.server.Close()
}

func (e *testOIDCEnv) signIDToken(sub, nonce string, exp time.Time) (string, error) {
	claims := idTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    e.issuer,
			Subject:   sub,
			Audience:  jwt.ClaimStrings{e.clientID},
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Email:         "user@example.com",
		Name:          "Test User",
		Picture:       "https://example.com/p.png",
		EmailVerified: true,
		Nonce:         nonce,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = e.kid
	return token.SignedString(e.rsaKey)
}

func (e *testOIDCEnv) newClient(t *testing.T, extra func(*Config)) Client {
	t.Helper()
	cfg := Config{
		ClientID:     e.clientID,
		ClientSecret: "static-secret",
		Issuer:       e.issuer,
		RedirectURI:  "https://app/callback",
		HTTPClient:   e.server.Client(),
	}
	if extra != nil {
		extra(&cfg)
	}
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}

func TestClientAuthURLExchangeVerify(t *testing.T) {
	env := newTestOIDCEnv(t)
	defer env.close()
	client := env.newClient(t, nil)

	verifier, err := GenerateCodeVerifier()
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := CodeChallengeS256(verifier)
	if err != nil {
		t.Fatal(err)
	}

	authURL, err := client.AuthURL(context.Background(), "state-1", "nonce-abc", challenge)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("code_challenge") != challenge || q.Get("code_challenge_method") != "S256" {
		t.Fatalf("pkce params missing: %v", q)
	}
	if q.Get("nonce") != "nonce-abc" {
		t.Fatal("nonce missing")
	}

	ctx := context.Background()
	idToken, accessToken, err := client.Exchange(ctx, "auth-code", verifier)
	if err != nil {
		t.Fatal(err)
	}
	if accessToken != "access-token" {
		t.Fatalf("access token: %q", accessToken)
	}

	claims, err := client.VerifyIDToken(ctx, idToken, "nonce-abc")
	if err != nil {
		t.Fatal(err)
	}
	if claims.Sub != "user-1" || claims.Email != "user@example.com" || !claims.EmailVerified {
		t.Fatalf("claims: %+v", claims)
	}
}

func TestVerifyIDTokenNonceMismatch(t *testing.T) {
	env := newTestOIDCEnv(t)
	defer env.close()
	client := env.newClient(t, nil)

	raw, err := env.signIDToken("user-1", "expected", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.VerifyIDToken(context.Background(), raw, "wrong"); err == nil {
		t.Fatal("expected nonce mismatch")
	}
}

func TestVerifyIDTokenExpired(t *testing.T) {
	env := newTestOIDCEnv(t)
	defer env.close()
	client := env.newClient(t, nil)

	raw, err := env.signIDToken("user-1", "nonce-abc", time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.VerifyIDToken(context.Background(), raw, "nonce-abc"); err == nil {
		t.Fatal("expected expired token error")
	}
}

func TestExchangeUsesClientSecretProvider(t *testing.T) {
	env := newTestOIDCEnv(t)
	defer env.close()
	provider := &fakeClientSecretProvider{secret: "apple-jwt-secret"}
	client := env.newClient(t, func(c *Config) {
		c.ClientSecret = ""
		c.ClientSecretProvider = provider
	})

	verifier, _ := GenerateCodeVerifier()
	_, _, err := client.Exchange(context.Background(), "auth-code", verifier)
	if err != nil {
		t.Fatal(err)
	}
	if provider.calls != 1 {
		t.Fatalf("provider calls: %d", provider.calls)
	}
}

func TestDiscoveryIssuerMismatch(t *testing.T) {
	env := newTestOIDCEnv(t)
	defer env.close()
	cfg := Config{
		ClientID:     env.clientID,
		Issuer:       "https://wrong-issuer.example",
		RedirectURI:  "https://app/callback",
		HTTPClient:   env.server.Client(),
		DiscoveryURL: env.server.URL + "/.well-known/openid-configuration",
	}
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.AuthURL(context.Background(), "s", "n", "challenge"); err == nil || !strings.Contains(err.Error(), "issuer mismatch") {
		t.Fatalf("expected issuer mismatch, got %v", err)
	}
}

func TestAppleClientSecretGeneratorWithSigner(t *testing.T) {
	gen := NewAppleClientSecretGeneratorWithSigner(AppleClientSecretParams{
		TeamID:   "TEAM",
		ClientID: "client",
		KeyID:    "KEY",
	}, func(p AppleClientSecretParams) (string, error) {
		return "signed-secret", nil
	})
	secret, err := gen.ClientSecret(context.Background())
	if err != nil || secret != "signed-secret" {
		t.Fatalf("secret=%q err=%v", secret, err)
	}
}
