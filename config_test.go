package oidc

import "testing"

func TestConfigValidate(t *testing.T) {
	base := Config{
		ClientID:    "client",
		Issuer:      "https://issuer.example",
		RedirectURI: "https://app/callback",
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid config: %v", err)
	}

	cases := []struct {
		name string
		cfg  Config
	}{
		{"missing client id", func() Config { c := base; c.ClientID = ""; return c }()},
		{"missing issuer and discovery", func() Config { c := base; c.Issuer = ""; return c }()},
		{"missing redirect", func() Config { c := base; c.RedirectURI = ""; return c }()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.cfg.Validate(); err == nil {
				t.Fatal("expected error")
			}
		})
	}

	discoveryOnly := Config{
		ClientID:     "client",
		DiscoveryURL: "https://issuer.example/.well-known/openid-configuration",
		RedirectURI:  "https://app/callback",
	}
	if err := discoveryOnly.Validate(); err != nil {
		t.Fatalf("discovery url only: %v", err)
	}
}

func TestConfigDefaultScopes(t *testing.T) {
	cfg := ConfigDefault()
	scopes := cfg.resolvedScopes()
	if len(scopes) != 3 || scopes[0] != "openid" {
		t.Fatalf("unexpected scopes: %v", scopes)
	}
}
