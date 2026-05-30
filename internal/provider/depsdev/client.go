package depsdev

import (
	"context"
	"net/url"

	analyze "github.com/maksemen2/trustmod/internal/model"
	"github.com/maksemen2/trustmod/internal/provider"
)

type Client struct {
	http *provider.HTTPClient
}

func NewClient(opts analyze.Options) *Client {
	return &Client{http: provider.NewHTTPClient("deps.dev", opts)}
}

func (c *Client) Version(ctx context.Context, modulePath, version string) (versionResponse, bool, string, error) {
	var resp versionResponse
	u := "https://api.deps.dev/v3alpha/systems/go/packages/" + url.PathEscape(modulePath) + "/versions/" + url.PathEscape(version)
	cached, status, err := c.http.DoJSON(ctx, "GET", u, nil, &resp)
	return resp, cached, status, err
}
