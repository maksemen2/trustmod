package osv

import (
	"context"

	analyze "github.com/maksemen2/trustmod/internal/model"
	"github.com/maksemen2/trustmod/internal/provider"
)

type Client struct {
	http     *provider.HTTPClient
	endpoint string
}

func NewClient(opts analyze.Options) *Client {
	return &Client{http: provider.NewHTTPClient("osv", opts), endpoint: "https://api.osv.dev/v1/querybatch"}
}

func (c *Client) QueryBatch(ctx context.Context, modules []analyze.ModuleReport) (batchResponse, bool, string, error) {
	req := batchRequest{Queries: make([]query, 0, len(modules))}
	for i := range modules {
		m := modules[i]
		req.Queries = append(req.Queries, query{
			Package: packageSpec{Ecosystem: "Go", Name: m.ModulePath},
			Version: m.SelectedVersion,
		})
	}
	var resp batchResponse
	endpoint := c.endpoint
	if endpoint == "" {
		endpoint = "https://api.osv.dev/v1/querybatch"
	}
	cached, status, err := c.http.DoJSON(ctx, "POST", endpoint, req, &resp)
	return resp, cached, status, err
}
