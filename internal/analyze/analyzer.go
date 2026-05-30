package analyze

import (
	"context"
	"errors"
	"fmt"
	"os"
	pathpkg "path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/maksemen2/trustmod/internal/collect"
	"github.com/maksemen2/trustmod/internal/findings"
	"github.com/maksemen2/trustmod/internal/git"
	"github.com/maksemen2/trustmod/internal/gomod"
	"github.com/maksemen2/trustmod/internal/policy"
	"golang.org/x/mod/semver"
)

func (a *Analyzer) CheckModule(ctx context.Context, spec string) (*ProjectReport, error) {
	ctx = a.gomodContext(ctx)
	modulePath, requested := ModuleSpecParts(spec)
	if modulePath == "" {
		return nil, ErrEmptyModule
	}
	tmp, err := os.MkdirTemp("", "trustmod-check-*")
	if err != nil {
		return nil, err
	}
	if !a.opts.KeepTemp {
		defer func() { _ = os.RemoveAll(tmp) }()
	}
	if _, initErr := gomod.Go(ctx, tmp, a.opts.Timeout, "mod", "init", "trustmod.local/check"); initErr != nil {
		return nil, initErr
	}
	if getErr := goGet(ctx, tmp, modulePath+"@"+requested, a.opts.Timeout); getErr != nil {
		pol, polPath, polLoaded, polWarnings, _ := policy.Load(a.opts.PolicyPath, a.opts.Profile)
		pol = a.applyPolicyOverrides(pol)
		r := &ProjectReport{
			SchemaVersion:   SchemaVersion,
			TrustmodVersion: a.opts.TrustmodVersion,
			GeneratedAt:     time.Now().UTC(),
			ProjectRoot:     tmp,
			ModuleMode:      "detached",
			Policy:          pol.Summary(polPath, polLoaded, polWarnings),
			Verdict:         VerdictReview,
		}
		f := findings.New("TM-GO-001", modulePath, requested, "go get")
		f.Evidence = []string{getErr.Error()}
		r.Findings = append(r.Findings, f)
		policy.EvaluateProject(r, pol)
		if a.opts.KeepTemp {
			r.Notes = append(r.Notes, "temporary check directory kept: "+tmp)
		}
		return r, nil
	}
	r, err := a.auditProject(ctx, tmp, auditRunOptions{explicitCheckTarget: modulePath})
	if err != nil {
		return nil, err
	}
	r.ProjectRoot = "."
	r.ModuleMode = "detached"
	for i := range r.Modules {
		if r.Modules[i].ModulePath == modulePath {
			r.Modules[i].RequestedVersion = requested
			r.Modules[i].Direct = true
			r.Modules[i].Indirect = false
		}
	}
	if pol, _, _, _, err := policy.Load(a.opts.PolicyPath, a.opts.Profile); err == nil {
		pol = a.applyPolicyOverrides(pol)
		policy.EvaluateProject(r, pol)
	}
	if a.opts.KeepTemp {
		r.Notes = append(r.Notes, "temporary check directory kept: "+tmp)
	}
	sort.Slice(r.Modules, func(i, j int) bool {
		if r.Modules[i].ModulePath == modulePath {
			return true
		}
		if r.Modules[j].ModulePath == modulePath {
			return false
		}
		return r.Modules[i].ModulePath < r.Modules[j].ModulePath
	})
	return r, nil
}

func (a *Analyzer) gomodContext(ctx context.Context) context.Context {
	if a != nil && a.opts.Offline {
		return gomod.WithOffline(ctx)
	}
	return ctx
}

func (a *Analyzer) Diff(ctx context.Context, opts DiffOptions) (*ProjectReport, error) {
	path := opts.Path
	if path == "" {
		path = a.opts.WorkingDir
	}
	base := opts.Base
	if base == "" {
		base = "main"
	}
	if opts.ChangedFilesOnly {
		project, projectErr := gomod.FindProject(path)
		if projectErr != nil {
			return nil, projectErr
		}
		if git.InsideWorktree(ctx, project.Root) {
			files, filesErr := git.ChangedFiles(ctx, project.Root, base)
			if filesErr == nil && !hasModuleFileChange(files) {
				pol, polPath, polLoaded, polWarnings, err := policy.Load(a.opts.PolicyPath, a.opts.Profile)
				if err != nil {
					return nil, err
				}
				pol = a.applyPolicyOverrides(pol)
				report := &ProjectReport{
					SchemaVersion:   SchemaVersion,
					TrustmodVersion: a.opts.TrustmodVersion,
					GeneratedAt:     time.Now().UTC(),
					ProjectRoot:     project.Root,
					ModuleMode:      project.Mode,
					MainModules:     append([]string(nil), project.MainModules...),
					GoVersion:       project.GoVersion,
					Policy:          pol.Summary(polPath, polLoaded, polWarnings),
					Verdict:         VerdictAllow,
					Diff:            &DiffReport{Base: base, Notes: []string{"no go.mod, go.sum, or go.work changes found"}},
				}
				policy.EvaluateProject(report, pol)
				return report, nil
			}
		}
	}
	report, err := a.Audit(ctx, path)
	if err != nil {
		return nil, err
	}
	report.Diff = &DiffReport{Base: base}
	if opts.Head != "" && opts.Head != "HEAD" {
		report.Diff.Notes = append(report.Diff.Notes, "head ref: "+opts.Head)
	}
	if opts.Deep {
		report.Diff.Notes = append(report.Diff.Notes, "deep mode ran full analysis of the current project before computing go.mod deltas")
	}
	if !git.InsideWorktree(ctx, report.ProjectRoot) {
		f := findings.New("TM-GIT-001", "", "", "git")
		f.Evidence = []string{"not inside a git worktree"}
		report.Findings = append(report.Findings, f)
		return report, nil
	}
	oldMod, err := refDiffGoModSnapshot(ctx, report.ProjectRoot, base)
	if err != nil {
		f := findings.New("TM-GIT-001", "", "", "git")
		f.Evidence = []string{"base module files unavailable: " + err.Error()}
		report.Findings = append(report.Findings, f)
		return report, nil
	}
	var cur *gomod.ParsedGoMod
	if opts.Head != "" && opts.Head != "HEAD" {
		cur, err = refDiffGoModSnapshot(ctx, report.ProjectRoot, opts.Head)
	} else {
		cur, err = currentDiffGoModSnapshot(report.ProjectRoot)
	}
	if err != nil {
		f := findings.New("TM-GIT-001", "", "", "git")
		f.Evidence = []string{"current module files unavailable: " + err.Error()}
		report.Findings = append(report.Findings, f)
		return report, nil
	}
	for mod, version := range cur.Requirements {
		oldVersion, ok := oldMod.Requirements[mod]
		change := DiffModuleChange{ModulePath: mod, To: version, Direct: cur.Direct[mod]}
		if !ok {
			report.Diff.NewModules = append(report.Diff.NewModules, change)
			markNew(report, mod)
		} else if oldVersion != version {
			change.From = oldVersion
			report.Diff.UpdatedModules = append(report.Diff.UpdatedModules, change)
			if compareVersions(version, oldVersion) < 0 {
				addModuleFinding(report, mod, findings.New("TM-VER-009", mod, version, "git diff"))
			}
		}
	}
	for mod, version := range oldMod.Requirements {
		if _, ok := cur.Requirements[mod]; !ok {
			report.Diff.RemovedModules = append(report.Diff.RemovedModules, DiffModuleChange{ModulePath: mod, From: version, Direct: oldMod.Direct[mod]})
		}
	}
	sortDiff(report.Diff)
	if pol, _, _, _, err := policy.Load(a.opts.PolicyPath, a.opts.Profile); err == nil {
		pol = a.applyPolicyOverrides(pol)
		policy.EvaluateProject(report, pol)
	}
	return report, nil
}

func (a *Analyzer) Compare(ctx context.Context, opts CompareOptions) (*CompareReport, error) {
	cr := &CompareReport{
		SchemaVersion: CompareSchemaVersion,
		GeneratedAt:   time.Now().UTC(),
		Profile:       a.opts.Profile,
		UseCase:       opts.UseCase,
		Caveat:        "This is not a universal quality ranking. Choose based on project requirements.",
	}
	type compareResult struct {
		entry CompareEntry
		err   error
		ok    bool
	}
	results := collect.ParallelMap(ctx, opts.Modules, a.opts.Concurrency, func(ctx context.Context, _ int, spec string) compareResult {
		if err := ctx.Err(); err != nil {
			return compareResult{err: err}
		}
		if opts.Latest {
			modulePath, _ := ModuleSpecParts(spec)
			if modulePath != "" {
				spec = modulePath + "@latest"
			}
		}
		r, err := a.CheckModule(ctx, spec)
		if err != nil {
			return compareResult{err: err}
		}
		if len(r.Modules) == 0 {
			return compareResult{}
		}
		target := r.Modules[0]
		if !opts.IncludeCapabilities {
			target.Capabilities = nil
		}
		return compareResult{
			entry: CompareEntry{
				Module:             target,
				DirectDependencies: target.DependencyFootprint.DirectModules,
				TransitiveDeps:     target.DependencyFootprint.TransitiveModules,
				KeyNotes:           keyNotes(target),
			},
			ok: true,
		}
	})
	for i := range results {
		result := &results[i]
		if result.err != nil {
			return nil, result.err
		}
		if !result.ok {
			continue
		}
		cr.Entries = append(cr.Entries, result.entry)
	}
	sort.Slice(cr.Entries, func(i, j int) bool {
		if cr.Entries[i].Module.Verdict == cr.Entries[j].Module.Verdict {
			return cr.Entries[i].Module.RiskScore < cr.Entries[j].Module.RiskScore
		}
		return verdictRank(cr.Entries[i].Module.Verdict) < verdictRank(cr.Entries[j].Module.Verdict)
	})
	if len(cr.Entries) > 0 {
		best := cr.Entries[0].Module.ModulePath
		cr.Recommendation = best + " has the lowest observed dependency risk under this policy."
	}
	return cr, nil
}

func markNew(report *ProjectReport, module string) {
	for i := range report.Modules {
		if report.Modules[i].ModulePath != module {
			continue
		}
		for j := range report.Modules[i].Findings {
			report.Modules[i].Findings[j].NewInDiff = true
		}
		for j := range report.Modules[i].Capabilities {
			report.Modules[i].Capabilities[j].NewInDiff = true
		}
	}
}

func addModuleFinding(report *ProjectReport, module string, f Finding) {
	for i := range report.Modules {
		if report.Modules[i].ModulePath == module {
			report.Modules[i].Findings = append(report.Modules[i].Findings, f)
			return
		}
	}
	report.Findings = append(report.Findings, f)
}

func currentDiffGoModSnapshot(root string) (*gomod.ParsedGoMod, error) {
	project, err := gomod.FindProject(root)
	if err != nil {
		return nil, err
	}
	return projectDiffGoModSnapshot(project), nil
}

func refDiffGoModSnapshot(ctx context.Context, root, ref string) (*gomod.ParsedGoMod, error) {
	repoRoot, prefix, err := gitRootPrefix(ctx, root)
	if err != nil {
		return nil, err
	}
	workData, workErr := git.Show(ctx, repoRoot, ref, gitPath(prefix, "go.work"))
	if workErr == nil {
		dirs, err := gomod.ParseGoWork("go.work", workData)
		if err != nil {
			return nil, err
		}
		return refWorkspaceGoModSnapshot(ctx, repoRoot, prefix, ref, dirs)
	}
	modData, modErr := git.Show(ctx, repoRoot, ref, gitPath(prefix, "go.mod"))
	if modErr != nil {
		return nil, fmt.Errorf("module file lookup failed: %w", errors.Join(workErr, modErr))
	}
	return gomod.ParseGoModBytes(modData)
}

func refWorkspaceGoModSnapshot(ctx context.Context, repoRoot, prefix, ref string, dirs []string) (*gomod.ParsedGoMod, error) {
	out := emptyParsedGoMod()
	found := false
	for _, dir := range dirs {
		modPath := gitPath(prefix, pathpkg.Join(filepath.ToSlash(dir), "go.mod"))
		data, err := git.Show(ctx, repoRoot, ref, modPath)
		if err != nil {
			continue
		}
		parsed, err := gomod.ParseGoMod(modPath, data)
		if err != nil {
			return nil, err
		}
		mergeParsedGoMod(out, parsed)
		found = true
	}
	if !found {
		return nil, errors.New("go.work did not reference any readable go.mod files")
	}
	return out, nil
}

func gitRootPrefix(ctx context.Context, root string) (repoRoot string, prefix string, err error) {
	repoRoot, err = git.WorktreeRoot(ctx, root)
	if err != nil {
		return "", "", err
	}
	prefix, err = git.RelativePath(ctx, repoRoot, root)
	if err != nil {
		return "", "", err
	}
	return repoRoot, prefix, nil
}

func gitPath(prefix, name string) string {
	name = filepath.ToSlash(strings.TrimSpace(name))
	if prefix == "" {
		return name
	}
	return pathpkg.Join(prefix, name)
}

func projectDiffGoModSnapshot(project *gomod.Project) *gomod.ParsedGoMod {
	out := emptyParsedGoMod()
	out.ModulePath = project.ModulePath
	out.GoVersion = project.GoVersion
	for k, v := range project.Requirements {
		out.Requirements[k] = v
	}
	for k, v := range project.Direct {
		out.Direct[k] = v
	}
	for k, v := range project.Replacements {
		out.Replacements[k] = v
	}
	for k := range project.Tools {
		out.Tools = append(out.Tools, k)
	}
	sort.Strings(out.Tools)
	return out
}

func emptyParsedGoMod() *gomod.ParsedGoMod {
	return &gomod.ParsedGoMod{
		Direct:       map[string]bool{},
		Requirements: map[string]string{},
		Replacements: map[string]gomod.Replacement{},
	}
}

func mergeParsedGoMod(dst, src *gomod.ParsedGoMod) {
	if dst.GoVersion == "" {
		dst.GoVersion = src.GoVersion
	}
	for k, v := range src.Requirements {
		dst.Requirements[k] = v
	}
	for k, v := range src.Direct {
		dst.Direct[k] = v
	}
	for k, v := range src.Replacements {
		dst.Replacements[k] = v
	}
	dst.Tools = append(dst.Tools, src.Tools...)
}

func sortDiff(d *DiffReport) {
	sort.Slice(d.NewModules, func(i, j int) bool { return d.NewModules[i].ModulePath < d.NewModules[j].ModulePath })
	sort.Slice(d.UpdatedModules, func(i, j int) bool { return d.UpdatedModules[i].ModulePath < d.UpdatedModules[j].ModulePath })
	sort.Slice(d.RemovedModules, func(i, j int) bool { return d.RemovedModules[i].ModulePath < d.RemovedModules[j].ModulePath })
}

func hasModuleFileChange(files []string) bool {
	for _, f := range files {
		f = filepath.ToSlash(strings.TrimSpace(f))
		switch {
		case f == "go.mod", f == "go.sum", f == "go.work", f == "go.work.sum":
			return true
		case strings.HasSuffix(f, "/go.mod"), strings.HasSuffix(f, "/go.sum"), strings.HasSuffix(f, "/go.work"), strings.HasSuffix(f, "/go.work.sum"):
			return true
		}
	}
	return false
}

func (a *Analyzer) applyPolicyOverrides(pol policy.Policy) policy.Policy {
	if len(a.opts.PolicyFailOn) == 0 {
		return pol
	}
	pol.FailOn = make([]string, 0, len(a.opts.PolicyFailOn))
	for _, v := range a.opts.PolicyFailOn {
		v = strings.ToUpper(strings.TrimSpace(v))
		if v != "" {
			pol.FailOn = append(pol.FailOn, v)
		}
	}
	return pol
}

func compareVersions(a, b string) int {
	return semver.Compare(strings.TrimSpace(a), strings.TrimSpace(b))
}

func keyNotes(m ModuleReport) []string {
	var notes []string
	if len(m.Licenses) > 0 {
		notes = append(notes, "license "+strings.Join(m.Licenses, ","))
	}
	if m.DependencyFootprint.TransitiveModules == 0 {
		notes = append(notes, "small footprint")
	} else {
		notes = append(notes, strconv.Itoa(m.DependencyFootprint.TransitiveModules)+" transitive modules")
	}
	for i := range m.Findings {
		f := m.Findings[i]
		if f.VerdictImpact != VerdictAllow {
			notes = append(notes, f.Code)
		}
		if len(notes) >= 3 {
			break
		}
	}
	return notes
}
