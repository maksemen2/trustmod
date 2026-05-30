package scorecard

import (
	"context"
	"strings"

	analyze "github.com/maksemen2/trustmod/internal/model"
	"github.com/maksemen2/trustmod/internal/provider"
)

type Client struct {
	http *provider.HTTPClient
}

func NewClient(opts analyze.Options) *Client {
	return &Client{http: provider.NewHTTPClient("scorecard", opts)}
}

func (c *Client) Project(ctx context.Context, repoURI string) (response, bool, string, error) {
	var resp response
	u := "https://api.scorecard.dev/projects/" + strings.Trim(repoURI, "/")
	cached, status, err := c.http.DoJSON(ctx, "GET", u, nil, &resp)
	return resp, cached, status, err
}
