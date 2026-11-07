package oidc

import "testing"

func TestPresetsRequireFields(t *testing.T) {
	base := Config{
		ClientID:    "id",
		RedirectURI: "https://app/cb",
	}

	if _, err := NewOkta(base); err == nil {
		t.Fatal("okta requires issuer")
	}
	if _, err := NewApple(base); err == nil {
		t.Fatal("apple requires secret or provider")
	}

	oktaCfg := base
	oktaCfg.Issuer = "https://dev.okta.com/oauth2/default"
	if _, err := NewOkta(oktaCfg); err != nil {
		t.Fatalf("okta preset validate: %v", err)
	}

	if _, err := NewGoogle(base); err != nil {
		t.Fatalf("google preset validate: %v", err)
	}

	msCfg := base
	msCfg.TenantID = "tenant-1"
	if _, err := NewMicrosoft(msCfg); err != nil {
		t.Fatalf("microsoft preset: %v", err)
	}
}
