package oidc

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	// DefaultHTTPTimeout is the timeout of the HTTP client used when Config.HTTPClient is nil.
	DefaultHTTPTimeout = 10 * time.Second

	// maxResponseBytes caps discovery and JWKS response bodies (4 MiB).
	maxResponseBytes = 4 << 20
)

// HTTPDoer performs HTTP requests; *http.Client satisfies this interface.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// defaultHTTPClient is shared by clients that do not configure HTTPClient.
// It is never mutated after init.
var defaultHTTPClient HTTPDoer = &http.Client{Timeout: DefaultHTTPTimeout}

func resolveHTTPClient(c HTTPDoer) HTTPDoer {
	if c != nil {
		return c
	}
	return defaultHTTPClient
}

// readLimited reads at most limit bytes and fails when the body is larger.
func readLimited(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("response body exceeds %d bytes", limit)
	}
	return data, nil
}
