package github

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	analyze "github.com/maksemen2/trustmod/internal/model"
	"github.com/maksemen2/trustmod/internal/provider"
)

func TestAuthenticatedCacheScopeUsesTokenFingerprint(t *testing.T) {
	a := NewClient(analyze.Options{GitHubToken: "token-a", NoCache: true}.WithDefaults())
	b := NewClient(analyze.Options{GitHubToken: "token-b", NoCache: true}.WithDefaults())
	if a.http.CacheScope == "" || b.http.CacheScope == "" {
		t.Fatal("expected authenticated clients to set cache scope")
	}
	if a.http.CacheScope == b.http.CacheScope {
		t.Fatalf("cache scopes should differ for different tokens: %q", a.http.CacheScope)
	}
	if strings.Contains(a.http.CacheScope, "token-a") || strings.Contains(b.http.CacheScope, "token-b") {
		t.Fatalf("cache scope must not contain token material: %q %q", a.http.CacheScope, b.http.CacheScope)
	}
}

func TestRepoGraphQLClassifiesRateLimitError(t *testing.T) {
	c := NewClient(analyze.Options{NoCache: true}.WithDefaults())
	c.http.Client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"errors":[{"message":"API rate limit exceeded for user"}]}`)),
		}, nil
	})

	_, _, status, err := c.RepoGraphQL(context.Background(), "owner", "repo")
	if err == nil {
		t.Fatal("expected GraphQL rate-limit error")
	}
	if status != analyze.ProviderStatusRateLimited {
		t.Fatalf("status = %q, want %q", status, analyze.ProviderStatusRateLimited)
	}
	if !provider.IsHTTPStatus(err, http.StatusTooManyRequests) {
		t.Fatalf("expected HTTP 429 status error, got %T %v", err, err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
