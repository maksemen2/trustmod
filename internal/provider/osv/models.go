package osv

type batchRequest struct {
	Queries []query `json:"queries"`
}

type query struct {
	Package packageSpec `json:"package"`
	Version string      `json:"version,omitempty"`
}

type packageSpec struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

type batchResponse struct {
	Results []queryResult `json:"results"`
}

type queryResult struct {
	Vulns []vulnerability `json:"vulns"`
}

type vulnerability struct {
	ID               string                 `json:"id"`
	Summary          string                 `json:"summary"`
	Details          string                 `json:"details"`
	Aliases          []string               `json:"aliases"`
	Modified         string                 `json:"modified"`
	DatabaseSpecific map[string]interface{} `json:"database_specific"`
	References       []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
}
