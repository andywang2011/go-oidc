package main

import (
	"fmt"

	"github.com/andywang2011/go-oidc"
)

func main() {
	verifier, err := oidc.GenerateCodeVerifier()
	if err != nil {
		panic(err)
	}
	challenge, err := oidc.CodeChallengeS256(verifier)
	if err != nil {
		panic(err)
	}
	fmt.Println("verifier length:", len(verifier))
	fmt.Println("challenge length:", len(challenge))
}
