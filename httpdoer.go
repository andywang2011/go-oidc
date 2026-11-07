package oidc

import "net/http"

// HTTPDoer performs HTTP requests; *http.Client satisfies this interface.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

func resolveHTTPClient(c HTTPDoer) HTTPDoer {
	if c != nil {
		return c
	}
	return http.DefaultClient
}
