// Package oidc provides OpenID Connect authorization-code flow helpers with PKCE,
// discovery, and ID token verification.
//
// Design constraints:
//   - No viper, environment variables, or config file paths inside the library.
//   - No global singletons or log.Fatal; callers construct clients via New*.
//   - HTTP transport is injectable through Config.HTTPClient for httptest and custom timeouts.
//   - Apple Sign In client_secret (ES256 JWT) is supplied via ClientSecretProvider when needed.
package oidc
