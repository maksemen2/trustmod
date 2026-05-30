package model

import "time"

type Options struct {
	TrustmodVersion    string
	WorkingDir         string
	ConfigPath         string
	PolicyPath         string
	BaselinePath       string
	CustomRulesPath    string
	CacheDir           string
	CacheTTL           time.Duration
	NoCache            bool
	Profile            string
	PolicyFailOn       []string
	Offline            bool
	AllowPrivateRemote bool
	IncludeTests       bool
	IncludeTools       bool
	Tags               string
	RunGovulncheck     bool
	GovulncheckPath    string
	GovulncheckTimeout time.Duration
	GitHubToken        string
	DisabledProviders  map[string]bool
	StrictData         bool
	NoColor            bool
	Verbose            bool
	Debug              bool
	Concurrency        int
	Timeout            time.Duration
	HTTPGate           chan struct{} `json:"-" yaml:"-"`
	KeepTemp           bool
}

type DiffOptions struct {
	Path             string
	Base             string
	Head             string
	Deep             bool
	OnlyNew          bool
	ChangedFilesOnly bool
	KeepTemp         bool
}

type CompareOptions struct {
	Modules             []string
	UseCase             string
	Latest              bool
	IncludeCapabilities bool
}

func (o Options) WithDefaults() Options {
	if o.WorkingDir == "" {
		o.WorkingDir = "."
	}
	if o.Profile == "" {
		o.Profile = "backend-service"
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 8
	}
	if o.Timeout <= 0 {
		o.Timeout = 20 * time.Second
	}
	if o.GovulncheckTimeout <= 0 {
		o.GovulncheckTimeout = 2 * time.Minute
	}
	if o.CacheTTL <= 0 {
		o.CacheTTL = 24 * time.Hour
	}
	if o.HTTPGate == nil {
		o.HTTPGate = make(chan struct{}, o.Concurrency)
	}
	if o.TrustmodVersion == "" {
		o.TrustmodVersion = "dev"
	}
	return o
}
