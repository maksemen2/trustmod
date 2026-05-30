package osv

import (
	"context"
	"strings"
	"time"

	"github.com/maksemen2/trustmod/internal/collect"
	"github.com/maksemen2/trustmod/internal/findings"
	analyze "github.com/maksemen2/trustmod/internal/model"
	"github.com/maksemen2/trustmod/internal/provider"
)

const maxQueryBatchSize = 100

type Provider struct {
	client *Client
}

func New(opts analyze.Options) *Provider {
	return &Provider{client: NewClient(opts)}
}

func (p *Provider) Name() string { return "osv" }

func (p *Provider) Enrich(ctx context.Context, req provider.Request) (provider.Result, error) {
	now := time.Now().UTC()
	result := provider.Result{
		Status:  analyze.ProviderStatus{Name: p.Name(), Enabled: true, Status: analyze.ProviderStatusOK, FetchedAt: &now, Source: "https://api.osv.dev", Queried: len(req.Modules)},
		Modules: map[string]provider.ModuleUpdate{},
	}
	if len(req.Modules) == 0 {
		result.Status.Status = analyze.ProviderStatusSkippedNoPublicModules
		return result, nil
	}
	eligible := make([]analyze.ModuleReport, 0, len(req.Modules))
	for i := range req.Modules {
		mod := req.Modules[i]
		if mod.SelectedVersion == "" || mod.SelectedVersion == "(devel)" {
			continue
		}
		eligible = append(eligible, mod)
	}
	result.Status.Queried = len(eligible)
	if len(eligible) == 0 {
		result.Status.Status = analyze.ProviderStatusSkippedNoEligibleVersions
		result.Status.Skipped = len(req.Modules)
		result.Status.ErrorSummary = "no modules with selected versions for OSV lookup"
		return result, nil
	}
	type chunkResult struct {
		modules []analyze.ModuleReport
		resp    batchResponse
		provider.JobResult
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	chunks := collect.Chunks(eligible, maxQueryBatchSize)
	results := collect.ParallelMap(ctx, chunks, provider.Concurrency(req.Options), func(ctx context.Context, _ int, modules []analyze.ModuleReport) chunkResult {
		if err := ctx.Err(); err != nil {
			return chunkResult{modules: modules, JobResult: provider.JobResult{Status: analyze.ProviderStatusCancelled, Err: err}}
		}
		resp, cached, status, err := p.client.QueryBatch(ctx, modules)
		out := chunkResult{modules: modules, resp: resp, JobResult: provider.JobResult{Cached: cached, Status: status, Err: err}}
		if err != nil && status == analyze.ProviderStatusRateLimited {
			cancel()
		}
		return out
	})
	successes := 0
	for i := range results {
		chunk := &results[i]
		if !provider.MergeJobResult(&result, chunk.JobResult, "") {
			continue
		}
		successes++
		mergeBatchResponse(&result, chunk.modules, chunk.resp)
	}
	provider.FinalizeSuccessStatus(&result, successes)
	return result, nil
}

func mergeBatchResponse(result *provider.Result, modules []analyze.ModuleReport, resp batchResponse) {
	limit := min(len(resp.Results), len(modules))
	for i := 0; i < limit; i++ {
		qr := resp.Results[i]
		mod := modules[i]
		if len(qr.Vulns) == 0 {
			continue
		}
		update := provider.ModuleUpdate{ModulePath: mod.ModulePath, Version: mod.SelectedVersion}
		sec := mod.Security
		for _, vuln := range qr.Vulns {
			f := findings.New("TM-SEC-002", mod.ModulePath, mod.SelectedVersion, "osv")
			f = findings.WithStableID(f, f.Code, mod.ModulePath, mod.SelectedVersion, "advisory", vuln.ID)
			if vuln.Summary != "" {
				f.Description = vuln.Summary
			} else if vuln.Details != "" {
				f.Description = firstSentence(vuln.Details)
			}
			f.Evidence = []string{"OSV advisory: " + vuln.ID}
			f.References = append(f.References, vuln.ID)
			f.References = append(f.References, vuln.Aliases...)
			for _, ref := range vuln.References {
				if ref.URL != "" {
					f.References = append(f.References, ref.URL)
				}
			}
			update.Findings = append(update.Findings, f)
			sec.KnownVulnerabilities++
		}
		update.Security = &sec
		result.Modules[mod.ModulePath] = update
	}
}

func firstSentence(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, ". "); i > 0 {
		return s[:i+1]
	}
	if len(s) > 240 {
		return s[:240] + "..."
	}
	return s
}
