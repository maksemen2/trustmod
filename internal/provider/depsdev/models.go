package depsdev

type versionResponse struct {
	VersionKey struct {
		System  string `json:"system"`
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"versionKey"`
	Licenses []string `json:"licenses"`
	Links    []struct {
		Label string `json:"label"`
		URL   string `json:"url"`
	} `json:"links"`
	AdvisoryKeys []struct {
		ID string `json:"id"`
	} `json:"advisoryKeys"`
}
