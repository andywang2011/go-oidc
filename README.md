# go-oidc

OpenID Connect authorization-code client with PKCE, discovery, JWKS verification, and provider presets.

## Install

```bash
go get github.com/andywang2011/go-oidc@v0.1.0
```

## Quick start

```go
key, err := rsa.GenerateKey(rand.Reader, 2048)
if err != nil {
	panic(err)
}
clientID := "demo-client"
var issuer string
mux := http.NewServeMux()
mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
	_ = json.NewEncoder(w).Encode(map[string]string{
		"issuer":                 issuer,
		"authorization_endpoint": issuer + "/authorize",
		"token_endpoint":         issuer + "/token",
		"jwks_uri":               issuer + "/jwks",
	})
})
mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
	_ = json.NewEncoder(w).Encode(map[string]any{
		"keys": []map[string]string{
			{"kty": "RSA", "kid": "kid-1", "use": "sig", "alg": "RS256", "n": n, "e": e},
		},
	})
})
mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	claims := jwt.MapClaims{
		"iss": issuer, "sub": "user-1", "aud": clientID,
		"exp": time.Now().Add(time.Hour).Unix(),
		"nonce": "nonce-1",
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "kid-1"
	idToken, _ := tok.SignedString(key)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"access_token": "access", "id_token": idToken, "token_type": "Bearer",
	})
})
srv := httptest.NewServer(mux)
defer srv.Close()
issuer = srv.URL

client, err := oidc.NewClient(oidc.Config{
	ClientID:     clientID,
	ClientSecret: "secret",
	Issuer:       issuer,
	RedirectURI:  "https://app.example/callback",
	HTTPClient:   srv.Client(),
})
if err != nil {
	panic(err)
}

verifier, _ := oidc.GenerateCodeVerifier()
challenge, _ := oidc.CodeChallengeS256(verifier)
_, err = client.AuthURL("state-1", "nonce-1", challenge)
if err != nil {
	panic(err)
}

_, accessToken, err := client.Exchange(context.Background(), "auth-code", verifier)
if err != nil {
	panic(err)
}
fmt.Println(accessToken)
```

## Examples

```bash
cd examples
go run .
```

## License

MIT — see [LICENSE](LICENSE).
