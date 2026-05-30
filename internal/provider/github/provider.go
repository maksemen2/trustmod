package github

import (
	"context"
	"strconv"
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

func (p *Provider) Name() string { return "github" }

func (p *Provider) Enrich(ctx context.Context, req provider.Request) (provider.Result, error) {
	now := time.Now().UTC()
	res := provider.Result{
		Status:  analyze.ProviderStatus{Name: p.Name(), Enabled: true, Status: analyze.ProviderStatusOK, FetchedAt: &now, Source: "https://api.github.com"},
		Modules: map[string]provider.ModuleUpdate{},
	}
	type repoKey struct {
		owner string
		repo  string
	}
	groups, skipped := collect.GroupBy(req.Modules, func(mod analyze.ModuleReport) (repoKey, bool) {
		repo, ok := githubrepo.FromModule(mod.ModulePath)
		if !ok {
			return repoKey{}, false
		}
		return repoKey{owner: repo.Owner, repo: repo.Name}, true
	})
	res.Status.Skipped = skipped
	res.Status.Queried = len(groups)
	if len(groups) == 0 {
		if len(req.Modules) == 0 {
			res.Status.Status = analyze.ProviderStatusSkippedNoPublicModules
		} else {
			res.Status.Status = analyze.ProviderStatusSkippedUnsupportedHost
			res.Status.ErrorSummary = "no github.com module paths in provider request"
		}
		return res, nil
	}
	type jobResult struct {
		group collect.Group[repoKey, analyze.ModuleReport]
		provider.JobResult
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := collect.ParallelMap(ctx, groups, provider.Concurrency(req.Options), func(ctx context.Context, _ int, group collect.Group[repoKey, analyze.ModuleReport]) jobResult {
		if err := ctx.Err(); err != nil {
			return jobResult{group: group, JobResult: provider.JobResult{Status: analyze.ProviderStatusCancelled, Err: err}}
		}
		resp, cached, status, archiveDateMissingReason, err := p.fetchRepo(ctx, group.Key.owner, group.Key.repo)
		out := jobResult{group: group, JobResult: provider.JobResult{Cached: cached, Status: status, Err: err}}
		if err != nil {
			if status == analyze.ProviderStatusRateLimited {
				cancel()
			}
			return out
		}
		for i := range group.Items {
			mod := group.Items[i]
			update := provider.ModuleUpdate{ModulePath: mod.ModulePath, Version: mod.SelectedVersion, Repository: resp.HTMLURL, SourceHost: "github.com"}
			stars := resp.StargazersCount
			update.Adoption = &analyze.AdoptionSignals{Stars: &stars}
			update.Maintenance = &analyze.MaintenanceSignals{RepositoryArchived: resp.Archived, RepositoryArchivedAt: resp.ArchivedAt, LastCommitAt: resp.PushedAt, Stars: &stars}
			if resp.License != nil && resp.License.SPDXID != "" && resp.License.SPDXID != "NOASSERTION" {
				update.Licenses = []string{resp.License.SPDXID}
			}
			if resp.Archived {
				f := findings.New("TM-MNT-001", mod.ModulePath, mod.SelectedVersion, "github")
				f.Evidence = []string{archivedEvidence(resp.HTMLURL, resp.ArchivedAt, now, archiveDateMissingReason)}
				update.Findings = append(update.Findings, f)
			}
			if resp.PushedAt != nil && time.Since(*resp.PushedAt) > 730*24*time.Hour {
				f := findings.New("TM-MNT-002", mod.ModulePath, mod.SelectedVersion, "github")
				f.Evidence = []string{"GitHub repository last pushed at " + resp.PushedAt.Format(time.RFC3339)}
				update.Findings = append(update.Findings, f)
			}
			out.Updates = append(out.Updates, update)
		}
		return out
	})
	successes := 0
	for i := range results {
		result := &results[i]
		if result.Err != nil && provider.IsHTTPStatus(result.Err, 404) && res.Status.Status == analyze.ProviderStatusOK {
			res.Status.Cached = res.Status.Cached || result.Cached
			res.Status.Status = result.Status
			res.Status.ErrorSummary = "repository metadata unavailable for " + result.group.Key.owner + "/" + result.group.Key.repo
			for i := range result.group.Items {
				mod := result.group.Items[i]
				update := provider.ModuleUpdate{ModulePath: mod.ModulePath, Version: mod.SelectedVersion}
				f := findings.New("TM-ID-004", mod.ModulePath, mod.SelectedVersion, "github")
				f.Evidence = []string{"GitHub repository not found: " + result.group.Key.owner + "/" + result.group.Key.repo}
				update.Findings = append(update.Findings, f)
				res.Modules[mod.ModulePath] = update
			}
			continue
		}
		if provider.MergeJobResult(&res, result.JobResult, "; set TRUSTMOD_GITHUB_TOKEN or GITHUB_TOKEN to raise GitHub API limits") {
			successes++
		}
	}
	provider.FinalizeSuccessStatus(&res, successes)
	return res, nil
}

func (p *Provider) fetchRepo(ctx context.Context, owner, repo string) (repoResponse, bool, string, string, error) {
	if !p.client.HasToken() {
		resp, cached, status, err := p.client.Repo(ctx, owner, repo)
		return resp, cached, status, "no GitHub token configured", err
	}
	resp, cached, status, err := p.client.RepoGraphQL(ctx, owner, repo)
	if err == nil {
		return resp, cached, status, "", nil
	}
	graphStatus, graphErr := status, err
	resp, restCached, restStatus, restErr := p.client.Repo(ctx, owner, repo)
	if restErr != nil {
		return repoResponse{}, cached || restCached, restStatus, "", restErr
	}
	return resp, cached || restCached, restStatus, archiveDateFallbackReason(graphStatus, graphErr), nil
}

func archivedEvidence(repoURL string, archivedAt *time.Time, now time.Time, missingReason string) string {
	if archivedAt == nil {
		msg := "GitHub repository is archived; archive date unavailable"
		if strings.TrimSpace(missingReason) != "" {
			msg += " (" + missingReason + ")"
		}
		return msg + ": " + repoURL
	}
	return "GitHub repository archived at " + archivedAt.UTC().Format(time.RFC3339) + " (" + daysAgo(*archivedAt, now) + " ago): " + repoURL
}

func archiveDateFallbackReason(status string, err error) string {
	if err == nil {
		return ""
	}
	if status == analyze.ProviderStatusRateLimited {
		return "GitHub GraphQL rate limited"
	}
	return "GitHub GraphQL lookup failed: " + err.Error()
}

func daysAgo(then time.Time, now time.Time) string {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	days := int(now.UTC().Sub(then.UTC()).Hours() / 24)
	if days < 0 {
		days = 0
	}
	if days == 1 {
		return "1 day"
	}
	return strconv.Itoa(days) + " days"
}
