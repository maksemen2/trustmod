package github

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"strings"

	analyze "github.com/maksemen2/trustmod/internal/model"
	"github.com/maksemen2/trustmod/internal/provider"
)

type Client struct {
	http  *provider.HTTPClient
	token string
}

func NewClient(opts analyze.Options) *Client {
	c := provider.NewHTTPClient("github", opts)
	token := strings.TrimSpace(opts.GitHubToken)
	if token == "" {
		token = os.Getenv("TRUSTMOD_GITHUB_TOKEN")
	}
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}
	if token != "" {
		c.CacheScope = "auth:" + tokenFingerprint(token)
		base := c.Client.Transport
		if base == nil {
			base = http.DefaultTransport
		}
		c.Client.Transport = tokenTransport{token: token, base: base}
	}
	return &Client{http: c, token: token}
}

type tokenTransport struct {
	token string
	base  http.RoundTripper
}

func (t tokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+t.token)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	return t.base.RoundTrip(req)
}

func (c *Client) Repo(ctx context.Context, owner, repo string) (repoResponse, bool, string, error) {
	var resp repoResponse
	u := "https://api.github.com/repos/" + strings.Trim(owner, "/") + "/" + strings.Trim(repo, "/")
	cached, status, err := c.http.DoJSON(ctx, "GET", u, nil, &resp)
	return resp, cached, status, err
}

func (c *Client) HasToken() bool {
	return strings.TrimSpace(c.token) != ""
}

func (c *Client) RepoGraphQL(ctx context.Context, owner, repo string) (repoResponse, bool, string, error) {
	var resp graphqlRepoResponse
	body := map[string]any{
		"query": `query($owner: String!, $name: String!) {
  repository(owner: $owner, name: $name) {
    nameWithOwner
    url
    isArchived
    archivedAt
    stargazerCount
    pushedAt
    licenseInfo {
      spdxId
      name
    }
  }
}`,
		"variables": map[string]string{
			"owner": strings.Trim(owner, "/"),
			"name":  strings.Trim(repo, "/"),
		},
	}
	cached, status, err := c.http.DoJSON(ctx, "POST", "https://api.github.com/graphql", body, &resp)
	if err != nil {
		return repoResponse{}, cached, status, err
	}
	if len(resp.Errors) > 0 {
		msg := resp.Errors[0].Message
		if graphqlNotFound(msg) {
			return repoResponse{}, cached, analyze.ProviderStatusUnavailable, &provider.HTTPStatusError{Code: 404, Status: "404 Not Found", Body: msg}
		}
		if graphqlRateLimited(msg) {
			return repoResponse{}, cached, analyze.ProviderStatusRateLimited, &provider.HTTPStatusError{Code: http.StatusTooManyRequests, Status: "429 Too Many Requests", Body: msg}
		}
		return repoResponse{}, cached, analyze.ProviderStatusUnavailable, fmt.Errorf("github graphql: %s", msg)
	}
	if resp.Data.Repository == nil {
		return repoResponse{}, cached, analyze.ProviderStatusUnavailable, &provider.HTTPStatusError{Code: 404, Status: "404 Not Found", Body: "github graphql repository not found"}
	}
	return graphQLRepoToREST(*resp.Data.Repository), cached, status, nil
}

func graphQLRepoToREST(repo graphqlRepository) repoResponse {
	out := repoResponse{
		FullName:        repo.NameWithOwner,
		HTMLURL:         repo.URL,
		Archived:        repo.IsArchived,
		ArchivedAt:      repo.ArchivedAt,
		StargazersCount: repo.StargazerCount,
		PushedAt:        repo.PushedAt,
	}
	if repo.LicenseInfo != nil {
		out.License = &repoLicense{SPDXID: repo.LicenseInfo.SPDXID, Name: repo.LicenseInfo.Name}
	}
	return out
}

func graphqlNotFound(msg string) bool {
	lower := strings.ToLower(msg)
	return strings.Contains(lower, "could not resolve to a repository") || strings.Contains(lower, "not found")
}

func graphqlRateLimited(msg string) bool {
	lower := strings.ToLower(msg)
	return strings.Contains(lower, "rate limit") || strings.Contains(lower, "rate-limit") || strings.Contains(lower, "secondary rate limit")
}

func tokenFingerprint(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:8])
}
