package analyze

import (
	"github.com/maksemen2/trustmod/internal/model"
	"github.com/maksemen2/trustmod/internal/provider"
	"github.com/maksemen2/trustmod/internal/provider/depsdev"
	ghprovider "github.com/maksemen2/trustmod/internal/provider/github"
	"github.com/maksemen2/trustmod/internal/provider/govulncheck"
	"github.com/maksemen2/trustmod/internal/provider/osv"
	"github.com/maksemen2/trustmod/internal/provider/scorecard"
)

type ProviderFactory func(Options) []provider.Provider

func DefaultProviderFactory(opts Options) []provider.Provider {
	providers := []provider.Provider{
		osv.New(opts),
		depsdev.New(opts),
		ghprovider.New(opts),
		scorecard.New(opts),
	}
	if opts.RunGovulncheck {
		providers = append(providers, govulncheck.New(opts))
	}
	return providers
}

func providerIncluded(providers []provider.Provider, name string) bool {
	name = model.NormalizeProviderName(name)
	for _, p := range providers {
		if model.NormalizeProviderName(p.Name()) == name {
			return true
		}
	}
	return false
}
