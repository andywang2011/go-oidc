package oidc

import "testing"

func TestPKCEVerifierAndChallenge(t *testing.T) {
	verifier, err := GenerateCodeVerifier()
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := CodeChallengeS256(verifier)
	if err != nil {
		t.Fatal(err)
	}
	if challenge == verifier {
		t.Fatal("challenge must differ from verifier")
	}
	if _, err := CodeChallengeS256("short"); err == nil {
		t.Fatal("expected error for short verifier")
	}
}
