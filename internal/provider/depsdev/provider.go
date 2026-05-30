package depsdev

import (
	"context"
	"strings"
	"time"

	"github.com/maksemen2/trustmod/internal/collect"
	"github.com/maksemen2/trustmod/internal/findings"
	analyze "github.com/maksemen2/trustmod/internal/model"
	"github.com/maksemen2/trustmod/internal/provider"
)

type Provider struct {
	client *Client
}

func New(opts analyze.Options) *Provider {
	return &Provider{client: NewClient(opts)}
}

func (p *Provider) Name() string { return "deps.dev" }

func (p *Provider) Enrich(ctx context.Context, req provider.Request) (provider.Result, error) {
	now := time.Now().UTC()
	res := provider.Result{
		Status:  analyze.ProviderStatus{Name: p.Name(), Enabled: true, Status: analyze.ProviderStatusOK, FetchedAt: &now, Source: "https://api.deps.dev", Queried: len(req.Modules)},
		Modules: map[string]provider.ModuleUpdate{},
	}
	if len(req.Modules) == 0 {
		res.Status.Status = analyze.ProviderStatusSkippedNoPublicModules
		return res, nil
	}
	eligible := make([]analyze.ModuleReport, 0, len(req.Modules))
	for i := range req.Modules {
		mod := req.Modules[i]
		if mod.SelectedVersion == "" || mod.SelectedVersion == "(devel)" {
			continue
		}
		eligible = append(eligible, mod)
	}
	res.Status.Queried = len(eligible)
	if len(eligible) == 0 {
		res.Status.Status = analyze.ProviderStatusSkippedNoEligibleVersions
		res.Status.Skipped = len(req.Modules)
		res.Status.ErrorSummary = "no modules with selected versions for deps.dev lookup"
		return res, nil
	}
	type item struct {
		mod analyze.ModuleReport
		ok  bool
		provider.JobResult
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	items := collect.ParallelMap(ctx, eligible, provider.Concurrency(req.Options), func(ctx context.Context, _ int, mod analyze.ModuleReport) item {
		if err := ctx.Err(); err != nil {
			return item{mod: mod, JobResult: provider.JobResult{Status: analyze.ProviderStatusCancelled, Err: err}}
		}
		resp, cached, status, err := p.client.Version(ctx, mod.ModulePath, mod.SelectedVersion)
		out := item{mod: mod, JobResult: provider.JobResult{Cached: cached, Status: status, Err: err}}
		if err == nil {
			out.ok = true
			update := provider.ModuleUpdate{ModulePath: mod.ModulePath, Version: mod.SelectedVersion}
			update.Licenses = normalizeLicenses(resp.Licenses)
			for _, link := range resp.Links {
				if strings.EqualFold(link.Label, "SOURCE_REPO") || strings.Contains(strings.ToLower(link.Label), "source") {
					update.Repository = link.URL
				}
			}
			for _, adv := range resp.AdvisoryKeys {
				f := findings.New("TM-SEC-002", mod.ModulePath, mod.SelectedVersion, "deps.dev")
				f = findings.WithStableID(f, f.Code, mod.ModulePath, mod.SelectedVersion, "advisory", adv.ID)
				f.Evidence = []string{"deps.dev advisory: " + adv.ID}
				f.References = []string{adv.ID}
				update.Findings = append(update.Findings, f)
			}
			out.Updates = []provider.ModuleUpdate{update}
		} else if status == analyze.ProviderStatusRateLimited {
			cancel()
		}
		return out
	})
	successes := 0
	for i := range items {
		item := &items[i]
		if !provider.MergeJobResult(&res, item.JobResult, "") {
			continue
		}
		successes++
		update := item.Updates[0]
		if len(update.Licenses) == 0 && update.Repository == "" && len(update.Findings) == 0 {
			delete(res.Modules, item.mod.ModulePath)
		}
	}
	provider.FinalizeSuccessStatus(&res, successes)
	return res, nil
}

func normalizeLicenses(in []string) []string {
	out := make([]string, 0, len(in))
	for _, l := range in {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		out = append(out, l)
	}
	return collect.UniqueBy(out, func(v string) string { return v })
}
