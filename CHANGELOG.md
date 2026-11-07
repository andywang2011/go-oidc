# Changelog

## [Unreleased]

## [0.2.0] - 2026-11-07

### Breaking

- See repository diff for API changes in this release (secure defaults, renamed packages where applicable, context-aware constructors).

### Security

- Hardened defaults: TLS, timeouts, body limits, PII redaction where logging applies.

### Fixed

- Bug fixes from the v0.2.0 hardening pass.

### Changed

- CI uses go-version-file; added race, staticcheck, govulncheck, golangci-lint (gosec).



- **BREAKING:** `Client.AuthURL` now takes `ctx` as its first argument.
- `VerifyIDToken` requires a non-empty nonce and a nonce claim in the ID token (`ErrNonceRequired`).
- JWKS keys are cached with a TTL (`Config.JWKSCacheTTL`, default 1h); an unknown `kid` triggers one refresh.
- Discovery and JWKS responses are limited to 4 MiB.
- Default HTTP client uses a 10s timeout instead of `http.DefaultClient`.

## [0.1.0]

- Initial release: PKCE helpers, OIDC discovery, JWKS ID token verification, token exchange.
- Provider presets: Google, Okta, Microsoft, Apple with `ClientSecretProvider` for Apple ES256 JWT.
