package oidc

import "context"

type fakeClientSecretProvider struct {
	secret string
	err    error
	calls  int
}

func (f *fakeClientSecretProvider) ClientSecret(ctx context.Context) (string, error) {
	f.calls++
	if f.err != nil {
		return "", f.err
	}
	return f.secret, nil
}
