# go-oidc

OpenID Connect authorization-code client with PKCE, discovery, JWKS verification, and provider presets (Google, Okta, Microsoft, Apple).

## Design

- Callers construct and pass `Config`; **no viper**, **no environment variables**, **no log.Fatal**.
- **No global singletons**; use `NewClient` or provider presets.
- `Config.HTTPClient` is injectable for httptest and custom timeouts.
- Apple `client_secret` (ES256 JWT) is supplied via `ClientSecretProvider` when not using a static secret.

## Install

```bash
go get github.com/andywang2011/go-oidc@v0.1.0
```

## Quick start

```go
package main

import (
	"context"
	"fmt"

	"github.com/andywang2011/go-oidc"
)

func main() {
	client, err := oidc.NewGoogle(oidc.Config{
		ClientID:     "YOUR_CLIENT_ID",
		ClientSecret: "YOUR_CLIENT_SECRET",
		RedirectURI:  "https://app.example/oauth/callback",
	})
	if err != nil {
		panic(err)
	}

	verifier, _ := oidc.GenerateCodeVerifier()
	challenge, _ := oidc.CodeChallengeS256(verifier)

	authURL, err := client.AuthURL("state", "nonce", challenge)
	if err != nil {
		panic(err)
	}
	fmt.Println("redirect user to:", authURL)

	ctx := context.Background()
	idToken, accessToken, err := client.Exchange(ctx, "AUTH_CODE", verifier)
	if err != nil {
		panic(err)
	}
	_ = accessToken

	claims, err := client.VerifyIDToken(ctx, idToken, "nonce")
	if err != nil {
		panic(err)
	}
	fmt.Println("sub:", claims.Sub, "email:", claims.Email)
}
```

### Sign in with Apple (dynamic client secret)

```go
gen := oidc.NewAppleClientSecretGenerator(oidc.AppleClientSecretParams{
	TeamID:        "TEAM_ID",
	ClientID:      "com.example.service",
	KeyID:         "KEY_ID",
	PrivateKeyPEM: pemBytes,
})
client, err := oidc.NewApple(oidc.Config{
	ClientID:             "com.example.service",
	RedirectURI:          "https://app.example/callback",
	ClientSecretProvider: gen,
})
```

## Presets

| Function        | Issuer / notes                                      |
|-----------------|-----------------------------------------------------|
| `NewGoogle`     | `https://accounts.google.com`                       |
| `NewOkta`       | `Config.Issuer` required (auth server issuer URL)   |
| `NewMicrosoft`  | `https://login.microsoftonline.com/{tenant}/v2.0`   |
| `NewApple`      | `https://appleid.apple.com` + secret or provider    |

## License

MIT — see [LICENSE](LICENSE).
