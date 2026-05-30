package scorecard

import (
	"context"
	"strings"
	"time"

	"github.com/maksemen2/trustmod/internal/collect"
	"github.com/maksemen2/trustmod/internal/findings"
	"github.com/maksemen2/trustmod/internal/githubrepo"
	analyze "github.com/maksemen2/trustmod/internal/model"
	"github.com/maksemen2/trustmod/internal/provider"
)

type Provider struct {
	client *Client
}

func New(opts analyze.Options) *Provider {
	return &Provider{client: NewClient(opts)}
}

func (p *Provider) Name() string { return "scorecard" }

func (p *Provider) Enrich(ctx context.Context, req provider.Request) (provider.Result, error) {
	now := time.Now().UTC()
	res := provider.Result{
		Status:  analyze.ProviderStatus{Name: p.Name(), Enabled: true, Status: analyze.ProviderStatusOK, FetchedAt: &now, Source: "https://api.scorecard.dev"},
		Modules: map[string]provider.ModuleUpdate{},
	}
	groups, skipped := collect.GroupBy(req.Modules, func(mod analyze.ModuleReport) (string, bool) {
		repoURI, ok := githubrepo.URI(mod.ModulePath)
		if !ok {
			return "", false
		}
		return repoURI, true
	})
	res.Status.Skipped = skipped
	res.Status.Queried = len(groups)
	if len(groups) == 0 {
		if len(req.Modules) == 0 {
			res.Status.Status = analyze.ProviderStatusSkippedNoPublicModules
		} else {
			res.Status.Status = analyze.ProviderStatusSkippedUnsupportedHost
			res.Status.ErrorSummary = "no supported GitHub repository URIs in provider request"
		}
		return res, nil
	}
	type jobResult struct {
		group collect.Group[string, analyze.ModuleReport]
		provider.JobResult
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := collect.ParallelMap(ctx, groups, provider.Concurrency(req.Options), func(ctx context.Context, _ int, group collect.Group[string, analyze.ModuleReport]) jobResult {
		if err := ctx.Err(); err != nil {
			return jobResult{group: group, JobResult: provider.JobResult{Status: analyze.ProviderStatusCancelled, Err: err}}
		}
		resp, cached, status, err := p.client.Project(ctx, group.Key)
		out := jobResult{group: group, JobResult: provider.JobResult{Cached: cached, Status: status, Err: err}}
		if err != nil {
			if status == analyze.ProviderStatusRateLimited {
				cancel()
			}
			return out
		}
		score := resp.Score
		for i := range group.Items {
			mod := group.Items[i]
			update := provider.ModuleUpdate{ModulePath: mod.ModulePath, Version: mod.SelectedVersion, Maintenance: &analyze.MaintenanceSignals{ScorecardScore: &score}}
			for _, check := range resp.Checks {
				if shouldEmitMaintainedFinding(resp.Score, check.Name, check.Score) {
					f := findings.New("TM-MNT-005", mod.ModulePath, mod.SelectedVersion, "scorecard")
					f.Evidence = []string{"OpenSSF Scorecard Maintained score: " + formatScore(check.Score), check.Reason}
					update.Findings = append(update.Findings, f)
				}
			}
			out.Updates = append(out.Updates, update)
		}
		return out
	})
	successes := 0
	for i := range results {
		result := &results[i]
		if result.Err != nil && provider.IsHTTPStatus(result.Err, 404) {
			res.Status.Cached = res.Status.Cached || result.Cached
			res.Status.Skipped += len(result.group.Items)
			continue
		}
		if provider.MergeJobResult(&res, result.JobResult, "") {
			successes++
		}
	}
	provider.FinalizeSuccessStatus(&res, successes)
	if successes == 0 && res.Status.Status == analyze.ProviderStatusOK && res.Status.Skipped > 0 {
		res.Status.Status = analyze.ProviderStatusSkippedNoProviderData
		res.Status.ErrorSummary = "scorecard has no precomputed data for queried GitHub repository URIs"
	}
	return res, nil
}

func shouldEmitMaintainedFinding(overallScore float64, checkName string, checkScore float64) bool {
	if !strings.EqualFold(checkName, "Maintained") {
		return false
	}
	if checkScore < 0 || checkScore >= 5 {
		return false
	}
	// A low Maintained check is common for small stable libraries. Treat it as
	// review-worthy only when the aggregate Scorecard result is also low.
	return overallScore > 0 && overallScore < 5
}
