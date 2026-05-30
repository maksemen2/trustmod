package analyze

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/maksemen2/trustmod/internal/baseline"
	"github.com/maksemen2/trustmod/internal/bitset"
	"github.com/maksemen2/trustmod/internal/collect"
	"github.com/maksemen2/trustmod/internal/findings"
	"github.com/maksemen2/trustmod/internal/githubrepo"
	"github.com/maksemen2/trustmod/internal/gomod"
	"github.com/maksemen2/trustmod/internal/model"
	"github.com/maksemen2/trustmod/internal/packagescan"
	"github.com/maksemen2/trustmod/internal/policy"
	"github.com/maksemen2/trustmod/internal/provider"
)

type Analyzer struct {
	opts            Options
	providerFactory ProviderFactory
	sourceRules     []packagescan.SourceRule
}

func NewAnalyzer(opts Options) (*Analyzer, error) {
	return NewAnalyzerWithProviders(opts, DefaultProviderFactory)
}

func NewAnalyzerWithProviders(opts Options, factory ProviderFactory) (*Analyzer, error) {
	opts = opts.WithDefaults()
	if factory == nil {
		factory = DefaultProviderFactory
	}
	sourceRules, err := packagescan.LoadSourceRules(opts.CustomRulesPath)
	if err != nil {
		return nil, err
	}
	return &Analyzer{opts: opts, providerFactory: factory, sourceRules: sourceRules}, nil
}

func (a *Analyzer) Audit(ctx context.Context, path string) (*ProjectReport, error) {
	return a.auditProject(ctx, path, auditRunOptions{})
}

func (a *Analyzer) AuditPackages(ctx context.Context, path string, patterns []string) (*ProjectReport, error) {
	return a.auditProject(ctx, path, auditRunOptions{patterns: patterns})
}

type auditRunOptions struct {
	patterns            []string
	explicitCheckTarget string
}

func (a *Analyzer) auditProject(ctx context.Context, path string, run auditRunOptions) (*ProjectReport, error) {
	ctx = a.gomodContext(ctx)
	root := path
	if root == "" {
		root = a.opts.WorkingDir
	}
	project, err := gomod.FindProject(root)
	if err != nil {
		return nil, err
	}
	pol, polPath, polLoaded, polWarnings, err := policy.Load(a.opts.PolicyPath, a.opts.Profile)
	if err != nil {
		return nil, err
	}
	pol = a.applyPolicyOverrides(pol)
	base, basePath, baseLoaded, err := baseline.Load(a.opts.BaselinePath)
	if err != nil {
		return nil, err
	}
	report := &ProjectReport{
		SchemaVersion:   SchemaVersion,
		TrustmodVersion: a.opts.TrustmodVersion,
		GeneratedAt:     time.Now().UTC(),
		ProjectRoot:     project.Root,
		ModuleMode:      project.Mode,
		MainModules:     append([]string(nil), project.MainModules...),
		GoVersion:       project.GoVersion,
		GoEnvSummary:    goEnvSummary(ctx, project.Root, a.opts.Timeout),
		Policy:          pol.Summary(polPath, polLoaded, polWarnings),
		Providers:       nil,
		Verdict:         VerdictAllow,
	}
	if project.Mode == "detached" {
		f := findings.New("TM-GO-001", "", "", "go")
		f.Description = "No go.mod or go.work file was found for local project analysis."
		f.Evidence = []string{"path: " + project.Root}
		report.Findings = append(report.Findings, f)
		applyBaseline(report, base, basePath, baseLoaded)
		policy.EvaluateProject(report, pol)
		return report, nil
	}
	modules, err := gomod.ListModules(ctx, project.Root, a.opts.Timeout)
	if err != nil {
		f := findings.New("TM-GO-001", "", "", "go list")
		f.Evidence = []string{err.Error()}
		report.Findings = append(report.Findings, f)
	} else {
		if !a.opts.IncludeTools {
			modules = filterToolModules(modules, project.Tools)
		}
		report.Modules = a.buildModules(ctx, project, modules)
	}
	if run.explicitCheckTarget != "" {
		a.scanExplicitCheckTarget(ctx, report, run.explicitCheckTarget)
	} else {
		pkgs, pkgErr := gomod.ListPackages(ctx, project.Root, a.opts.Timeout, gomod.ListPackageOptions{IncludeTests: a.opts.IncludeTests, Tags: a.opts.Tags}, run.patterns...)
		if pkgErr != nil {
			report.Notes = append(report.Notes, "package graph unavailable: "+pkgErr.Error())
			a.scanModuleCapabilities(ctx, report.Modules)
		} else {
			applyPackageFootprint(report.Modules, pkgs)
			a.scanPackageCapabilities(ctx, report.Modules, pkgs)
		}
	}
	graph, graphErr := gomod.ModGraph(ctx, project.Root, a.opts.Timeout)
	if graphErr == nil {
		report.DependencyGraph = graph
		applyGraphFootprints(report.Modules, graph)
		if run.explicitCheckTarget == "" {
			a.applyWhyPaths(ctx, project.Root, report.Modules)
		}
	} else {
		report.DependencyGraph.Notes = append(report.DependencyGraph.Notes, graphErr.Error())
	}
	ok, verifyOut := gomod.Verify(ctx, project.Root, a.opts.Timeout)
	for i := range report.Modules {
		report.Modules[i].Security.ChecksumVerified = ok
	}
	if !ok {
		f := findings.New("TM-SEC-006", "", "", "go mod verify")
		f.Evidence = []string{verifyOut}
		report.Findings = append(report.Findings, f)
	}
	a.enrich(ctx, report, pol)
	attachCapabilitySourceURLs(report.Modules)
	applyBaseline(report, base, basePath, baseLoaded)
	policy.EvaluateProject(report, pol)
	return report, nil
}

func (a *Analyzer) buildModules(ctx context.Context, project *gomod.Project, mods []gomod.Module) []ModuleReport {
	privateMatcher := gomod.NewPrivateMatcher(project.MainModules)
	out := collect.ParallelMap(ctx, mods, a.opts.Concurrency, func(ctx context.Context, _ int, m gomod.Module) ModuleReport {
		selected := m.Version
		if selected == "" && m.Main {
			selected = "(main)"
		}
		rep := replacementFor(project, m)
		mr := ModuleReport{
			ModulePath:          m.Path,
			Version:             m.Version,
			SelectedVersion:     selected,
			Direct:              project.Direct[m.Path] || m.Main,
			Indirect:            !project.Direct[m.Path] && !m.Main,
			ToolOnly:            project.Tools[m.Path],
			Private:             privateMatcher.IsPrivate(m.Path),
			Retracted:           len(m.Retracted) > 0,
			Deprecated:          strings.TrimSpace(m.Deprecated) != "",
			PseudoVersion:       gomod.IsPseudoVersion(m.Version),
			MajorVersion:        gomod.MajorVersion(m.Version),
			SemverStatus:        gomod.SemverStatus(m.Version),
			Replacement:         rep,
			LocalReplace:        rep != nil && rep.Local,
			Verdict:             VerdictAllow,
			ProviderAnnotations: map[string]interface{}{},
			LocalDir:            m.Dir,
		}
		if m.Time != nil {
			mr.Maintenance.LastReleaseAt = m.Time
		}
		if m.Update != nil && m.Update.Version != "" {
			mr.ProviderAnnotations["goListLatest"] = m.Update.Version
		}
		mr.SourceHost = sourceHost(m.Path)
		mr.Identity = IdentitySignals{CanonicalModulePath: m.Path, Host: mr.SourceHost}
		if mr.LocalReplace {
			f := findings.New("TM-ID-008", m.Path, selected, "go.mod")
			mr.Findings = append(mr.Findings, f)
			mr.Private = true
		} else if rep != nil {
			f := findings.New("TM-ID-009", m.Path, selected, "go.mod")
			f.Evidence = []string{"replace => " + rep.Path + " " + rep.Version}
			mr.Findings = append(mr.Findings, f)
		}
		if m.Retracted != nil {
			f := findings.New("TM-VER-001", m.Path, selected, "go list")
			f.Evidence = append(f.Evidence, m.Retracted...)
			mr.Findings = append(mr.Findings, f)
		}
		if m.Deprecated != "" {
			f := findings.New("TM-VER-007", m.Path, selected, "go list")
			f.Evidence = []string{m.Deprecated}
			mr.Findings = append(mr.Findings, f)
		}
		if mr.PseudoVersion {
			mr.Findings = append(mr.Findings, findings.New("TM-VER-003", m.Path, selected, "go list"))
		}
		if gomod.IsPrerelease(m.Version) {
			mr.Findings = append(mr.Findings, findings.New("TM-VER-004", m.Path, selected, "go list"))
		}
		if m.Version != "" && mr.MajorVersion == 0 {
			mr.Findings = append(mr.Findings, findings.New("TM-VER-005", m.Path, selected, "go list"))
		}
		if gomod.MajorVersionPathMismatch(m.Path, m.Version) {
			mr.Findings = append(mr.Findings, findings.New("TM-ID-006", m.Path, selected, "go list"))
		}
		if m.Dir != "" {
			mr.Licenses = detectLocalLicenses(m.Dir)
		}
		if m.Main {
			mr.Private = true
		}
		return mr
	})
	sort.Slice(out, func(i, j int) bool {
		if out[i].Direct == out[j].Direct {
			return out[i].ModulePath < out[j].ModulePath
		}
		return out[i].Direct && !out[j].Direct
	})
	return out
}

func (a *Analyzer) enrich(ctx context.Context, report *ProjectReport, pol policy.Policy) {
	public := make([]ModuleReport, 0, len(report.Modules))
	privateSkipped := 0
	for i := range report.Modules {
		m := &report.Modules[i]
		if m.ModulePath == "" || m.SelectedVersion == "(main)" {
			continue
		}
		if m.Private && !a.opts.AllowPrivateRemote {
			privateSkipped++
			continue
		}
		public = append(public, *m)
	}
	reg := provider.NewRegistry()
	addProvider := func(name string, p provider.Provider) {
		if providerDisabled(a.opts, pol, name) {
			report.Providers = append(report.Providers, ProviderStatus{Name: name, Enabled: false, Status: ProviderStatusDisabled})
			return
		}
		reg.Providers = append(reg.Providers, p)
	}
	providers := a.providerFactory(a.opts)
	for _, p := range providers {
		addProvider(p.Name(), p)
	}
	if !providerIncluded(providers, "govulncheck") && providerDisabled(a.opts, pol, "govulncheck") {
		report.Providers = append(report.Providers, ProviderStatus{Name: "govulncheck", Enabled: false, Status: ProviderStatusDisabled})
	} else if !providerIncluded(providers, "govulncheck") {
		report.Providers = append(report.Providers, ProviderStatus{Name: "govulncheck", Enabled: true, Status: ProviderStatusNotRequested, Source: "local govulncheck"})
	}
	if privateSkipped > 0 {
		report.Providers = append(report.Providers, ProviderStatus{Name: "privacy", Enabled: true, Status: ProviderStatusSkippedPrivate, Skipped: privateSkipped, Source: "local privacy guard"})
	}
	moduleIndex := map[string]int{}
	for i := range report.Modules {
		moduleIndex[report.Modules[i].ModulePath] = i
	}
	type providerRun struct {
		name string
		res  provider.Result
		err  error
	}
	runs := collect.ParallelMap(ctx, reg.Providers, provider.Concurrency(a.opts), func(ctx context.Context, _ int, p provider.Provider) providerRun {
		res, err := p.Enrich(ctx, provider.Request{ProjectRoot: report.ProjectRoot, Modules: public, Options: a.opts})
		return providerRun{name: p.Name(), res: res, err: err}
	})
	for i := range runs {
		run := &runs[i]
		if run.err != nil {
			now := time.Now().UTC()
			report.Providers = append(report.Providers, ProviderStatus{Name: run.name, Enabled: true, Status: ProviderStatusError, FetchedAt: &now, ErrorSummary: run.err.Error()})
			continue
		}
		res := run.res
		report.Providers = append(report.Providers, res.Status)
		report.Findings = append(report.Findings, res.Findings...)
		for path := range res.Modules {
			update := res.Modules[path]
			i, ok := moduleIndex[path]
			if !ok {
				continue
			}
			applyUpdate(&report.Modules[i], update)
			report.Modules[i].DataAvailability = append(report.Modules[i].DataAvailability, res.Status)
		}
	}
}

func applyUpdate(m *ModuleReport, u provider.ModuleUpdate) {
	if len(u.Licenses) > 0 {
		m.Licenses = collect.AppendUniqueSortedStrings(m.Licenses, u.Licenses...)
	}
	if u.Repository != "" {
		m.Repository = u.Repository
		m.Identity.Repository = u.Repository
	}
	if u.SourceHost != "" {
		m.SourceHost = u.SourceHost
		m.Identity.Host = u.SourceHost
	}
	if u.Maintenance != nil {
		if u.Maintenance.RepositoryArchived {
			m.Maintenance.RepositoryArchived = true
		}
		if u.Maintenance.RepositoryArchivedAt != nil {
			m.Maintenance.RepositoryArchivedAt = u.Maintenance.RepositoryArchivedAt
		}
		if u.Maintenance.LastCommitAt != nil {
			m.Maintenance.LastCommitAt = u.Maintenance.LastCommitAt
		}
		if u.Maintenance.LastReleaseAt != nil {
			m.Maintenance.LastReleaseAt = u.Maintenance.LastReleaseAt
		}
		if u.Maintenance.ScorecardScore != nil {
			m.Maintenance.ScorecardScore = u.Maintenance.ScorecardScore
		}
		if u.Maintenance.Stars != nil {
			m.Maintenance.Stars = u.Maintenance.Stars
		}
	}
	if u.Security != nil {
		m.Security.KnownVulnerabilities += u.Security.KnownVulnerabilities
		m.Security.ReachableFindings += u.Security.ReachableFindings
	}
	if u.Identity != nil {
		if u.Identity.Repository != "" {
			m.Identity.Repository = u.Identity.Repository
		}
		if u.Identity.Host != "" {
			m.Identity.Host = u.Identity.Host
		}
	}
	if u.Adoption != nil {
		if u.Adoption.Stars != nil {
			m.Adoption.Stars = u.Adoption.Stars
		}
		if u.Adoption.Dependents != nil {
			m.Adoption.Dependents = u.Adoption.Dependents
		}
	}
	m.Findings = mergeFindings(m.Findings, u.Findings...)
	if len(u.Annotations) > 0 {
		if m.ProviderAnnotations == nil {
			m.ProviderAnnotations = map[string]interface{}{}
		}
		for k, v := range u.Annotations {
			m.ProviderAnnotations[k] = v
		}
	}
}

func attachCapabilitySourceURLs(mods []ModuleReport) {
	for i := range mods {
		attachCapabilitySourceURL(&mods[i])
	}
}

func attachCapabilitySourceURL(m *ModuleReport) {
	if m.Private || m.LocalReplace || len(m.Capabilities) == 0 {
		return
	}
	repoURL, subdir, ok := githubSourceTarget(*m)
	if !ok {
		return
	}
	ref, ok := githubrepo.RefForVersion(m.SelectedVersion)
	if !ok {
		return
	}
	for i := range m.Capabilities {
		for j := range m.Capabilities[i].Evidence {
			loc := &m.Capabilities[i].Evidence[j]
			if loc.URL != "" || loc.File == "" {
				continue
			}
			loc.URL = githubrepo.BlobURL(repoURL, ref, subdir, loc.File, loc.Line)
		}
	}
}

func githubSourceTarget(m ModuleReport) (repoURL string, subdir string, ok bool) {
	return githubrepo.SourceTarget(m.ModulePath, collect.FirstNonBlank(m.Repository, m.Identity.Repository))
}

func mergeFindings(existing []Finding, incoming ...Finding) []Finding {
	if len(incoming) == 0 {
		return existing
	}
	index := make(map[findingMergeKey][]int, len(existing))
	for i := range existing {
		if key, ok := mergeKey(existing[i]); ok {
			index[key] = append(index[key], i)
		}
	}
	for i := range incoming {
		f := incoming[i]
		key, ok := mergeKey(f)
		if !ok {
			existing = append(existing, f)
			continue
		}
		merged := false
		for _, i := range index[key] {
			if !equivalentFinding(existing[i], f) {
				continue
			}
			existing[i].Evidence = collect.AppendUniqueSortedStrings(existing[i].Evidence, f.Evidence...)
			existing[i].References = collect.AppendUniqueSortedStrings(existing[i].References, f.References...)
			merged = true
			break
		}
		if !merged {
			index[key] = append(index[key], len(existing))
			existing = append(existing, f)
		}
	}
	return existing
}

type findingMergeKey struct {
	Code          string
	ModulePath    string
	ModuleVersion string
}

func mergeKey(f Finding) (findingMergeKey, bool) {
	if f.Code == "" {
		return findingMergeKey{}, false
	}
	return findingMergeKey{Code: f.Code, ModulePath: f.ModulePath, ModuleVersion: f.ModuleVersion}, true
}

func equivalentFinding(a, b Finding) bool {
	if a.Code == "" || a.Code != b.Code || a.ModulePath != b.ModulePath || a.ModuleVersion != b.ModuleVersion {
		return false
	}
	if collect.OverlapsTrimmed(a.References, b.References) {
		return true
	}
	if a.Source == b.Source && collect.OverlapsTrimmed(a.Evidence, b.Evidence) {
		return true
	}
	return false
}

func replacementFor(project *gomod.Project, m gomod.Module) *Replacement {
	if m.Replace != nil {
		return &Replacement{Path: m.Replace.Path, Version: m.Replace.Version, Local: isLocalReplacement(m.Replace.Path)}
	}
	if rep, ok := project.Replacements[m.Path]; ok {
		return &Replacement{Path: rep.NewPath, Version: rep.NewVersion, Local: rep.Local}
	}
	return nil
}

func isLocalReplacement(path string) bool {
	return path != "" && (filepath.IsAbs(path) || strings.HasPrefix(path, ".") || strings.HasPrefix(path, ".."))
}

func sourceHost(modulePath string) string {
	parts := strings.Split(modulePath, "/")
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

func filterToolModules(mods []gomod.Module, tools map[string]bool) []gomod.Module {
	if len(tools) == 0 {
		return mods
	}
	out := mods[:0]
	for i := range mods {
		m := mods[i]
		if tools[m.Path] && !m.Main {
			continue
		}
		out = append(out, m)
	}
	return out
}

func applyGraphFootprints(mods []ModuleReport, graph DependencyGraph) {
	index := map[string]int{}
	nodeFor := func(path string) int {
		if i, ok := index[path]; ok {
			return i
		}
		i := len(index)
		index[path] = i
		return i
	}
	type edgePair struct {
		from int
		to   int
	}
	pairs := make([]edgePair, 0, len(graph.Edges))
	for _, edge := range graph.Edges {
		if edge.From == "" || edge.To == "" || edge.From == edge.To {
			continue
		}
		if !isDependencyModule(edge.From) || !isDependencyModule(edge.To) {
			continue
		}
		pairs = append(pairs, edgePair{from: nodeFor(edge.From), to: nodeFor(edge.To)})
	}
	if len(index) == 0 {
		return
	}
	adj := make([]collect.Set[int], len(index))
	for _, pair := range pairs {
		if adj[pair.from] == nil {
			adj[pair.from] = collect.NewSet[int]()
		}
		adj[pair.from].Add(pair.to)
	}
	reachableMemo := make([]bitset.Bits, len(index))
	state := make([]uint8, len(index))
	var reachable func(int) bitset.Bits
	reachable = func(node int) bitset.Bits {
		switch state[node] {
		case 2:
			return reachableMemo[node]
		case 1:
			return nil
		}
		state[node] = 1
		out := bitset.New(len(index))
		for dep := range adj[node] {
			out.Set(dep)
			out.Merge(reachable(dep))
		}
		out.Clear(node)
		state[node] = 2
		reachableMemo[node] = out
		return out
	}
	for i := range mods {
		node, ok := index[mods[i].ModulePath]
		if !ok {
			continue
		}
		direct := adj[node]
		mods[i].DependencyFootprint.DirectModules = len(direct)
		transitive := reachable(node).Count() - len(direct)
		if transitive < 0 {
			transitive = 0
		}
		mods[i].DependencyFootprint.TransitiveModules = transitive
	}
}

func (a *Analyzer) applyWhyPaths(ctx context.Context, root string, mods []ModuleReport) {
	targets := whyPathTargets(mods)
	if len(targets) == 0 {
		return
	}
	paths := make([]string, 0, len(targets))
	for _, target := range targets {
		paths = append(paths, target.modulePath)
	}
	byModule := map[string][]string{}
	for _, batch := range collect.Chunks(paths, 50) {
		lines, err := gomod.WhyModules(ctx, root, batch, a.opts.Timeout)
		if err != nil {
			a.applyWhyPathsIndividually(ctx, root, mods)
			return
		}
		for modulePath, pathLines := range lines {
			if len(pathLines) > 0 {
				byModule[modulePath] = pathLines
			}
		}
	}
	for _, target := range targets {
		if lines := byModule[target.modulePath]; len(lines) > 0 {
			mods[target.index].DependencyFootprint.ShortestModulePaths = lines
		}
	}
}

type whyPathTarget struct {
	index      int
	modulePath string
}

func whyPathTargets(mods []ModuleReport) []whyPathTarget {
	targets := make([]whyPathTarget, 0, len(mods))
	for i := range mods {
		if shouldExplainWhy(mods[i]) {
			targets = append(targets, whyPathTarget{index: i, modulePath: mods[i].ModulePath})
		}
	}
	return targets
}

func shouldExplainWhy(m ModuleReport) bool {
	return m.ModulePath != "" && m.SelectedVersion != "(main)" && (m.Direct || len(m.Findings) > 0)
}

func (a *Analyzer) applyWhyPathsIndividually(ctx context.Context, root string, mods []ModuleReport) {
	targets := whyPathTargets(mods)
	collect.ParallelMap(ctx, targets, a.opts.Concurrency, func(ctx context.Context, _ int, target whyPathTarget) struct{} {
		if err := ctx.Err(); err != nil {
			return struct{}{}
		}
		lines, err := gomod.WhyModule(ctx, root, target.modulePath, a.opts.Timeout)
		if err == nil && len(lines) > 0 {
			mods[target.index].DependencyFootprint.ShortestModulePaths = lines
		}
		return struct{}{}
	})
}

func isDependencyModule(path string) bool {
	return path != "" && path != "go" && path != "toolchain"
}

func providerDisabled(opts Options, pol policy.Policy, name string) bool {
	name = model.NormalizeProviderName(name)
	if len(opts.DisabledProviders) > 0 && opts.DisabledProviders[name] {
		return true
	}
	for _, disabled := range pol.Providers.Disabled {
		if model.NormalizeProviderName(disabled) == name {
			return true
		}
	}
	return false
}

func applyPackageFootprint(mods []ModuleReport, pkgs []gomod.Package) {
	index := map[string]*ModuleReport{}
	for i := range mods {
		index[mods[i].ModulePath] = &mods[i]
	}
	prod := map[string]map[string]bool{}
	test := map[string]map[string]bool{}
	addImports := func(dst map[string]map[string]bool, modulePath string, imports []string) {
		if len(imports) == 0 {
			return
		}
		if dst[modulePath] == nil {
			dst[modulePath] = map[string]bool{}
		}
		for _, imp := range imports {
			if imp != "" {
				dst[modulePath][imp] = true
			}
		}
	}
	for i := range pkgs {
		p := pkgs[i]
		if p.Module == nil || p.Module.Path == "" {
			continue
		}
		if p.ImportPath != "" {
			if prod[p.Module.Path] == nil {
				prod[p.Module.Path] = map[string]bool{}
			}
			prod[p.Module.Path][p.ImportPath] = true
		}
		addImports(test, p.Module.Path, p.TestImports)
		addImports(test, p.Module.Path, p.XTestImports)
	}
	for path, packages := range prod {
		if m := index[path]; m != nil {
			m.DependencyFootprint.ProductionPackages = len(packages)
		}
	}
	for path, packages := range test {
		if m := index[path]; m != nil {
			m.DependencyFootprint.TestPackages = len(packages)
			if len(prod[path]) == 0 && len(packages) > 0 {
				m.TestOnly = true
			}
		}
	}
}

func (a *Analyzer) scanPackageCapabilities(ctx context.Context, mods []ModuleReport, pkgs []gomod.Package) {
	filesByModule := packageFilesByModule(pkgs)
	collect.ParallelMap(ctx, mods, a.opts.Concurrency, func(ctx context.Context, i int, m ModuleReport) struct{} {
		files := filesByModule[m.ModulePath]
		if len(files) == 0 || m.Replacement != nil && m.Replacement.Local {
			return struct{}{}
		}
		scan, err := packagescan.ScanFilesWithOptions(ctx, m.ModulePath, m.SelectedVersion, moduleDir(m), files, m.Direct, a.packageScanOptions())
		if err == nil {
			mods[i].Capabilities = scan.Capabilities
			mods[i].Findings = append(mods[i].Findings, scan.Findings...)
		}
		return struct{}{}
	})
}

func (a *Analyzer) scanModuleCapabilities(ctx context.Context, mods []ModuleReport) {
	collect.ParallelMap(ctx, mods, a.opts.Concurrency, func(ctx context.Context, i int, m ModuleReport) struct{} {
		dir := moduleDir(m)
		if dir == "" || m.Replacement != nil && m.Replacement.Local {
			return struct{}{}
		}
		scan, err := packagescan.ScanModuleWithOptions(ctx, m.ModulePath, m.SelectedVersion, dir, m.Direct, a.packageScanOptions())
		if err == nil {
			mods[i].Capabilities = scan.Capabilities
			mods[i].Findings = append(mods[i].Findings, scan.Findings...)
		}
		return struct{}{}
	})
}

func (a *Analyzer) scanExplicitCheckTarget(ctx context.Context, report *ProjectReport, modulePath string) {
	if report == nil || modulePath == "" {
		return
	}
	for i := range report.Modules {
		if report.Modules[i].ModulePath != modulePath {
			continue
		}
		m := &report.Modules[i]
		dir := moduleDir(*m)
		if dir == "" || m.Replacement != nil && m.Replacement.Local {
			return
		}
		scan, err := packagescan.ScanModuleWithOptions(ctx, m.ModulePath, m.SelectedVersion, dir, true, a.packageScanOptions())
		if err != nil {
			return
		}
		m.Capabilities = mergeCapabilities(m.Capabilities, scan.Capabilities...)
		m.Findings = mergeFindings(m.Findings, scan.Findings...)
		attachCapabilitySourceURL(m)
		return
	}
}

func (a *Analyzer) packageScanOptions() packagescan.ScanOptions {
	return packagescan.ScanOptions{AdditionalSourceRules: a.sourceRules}
}

func mergeCapabilities(existing []Capability, incoming ...Capability) []Capability {
	if len(incoming) == 0 {
		return existing
	}
	index := make(map[string]int, len(existing))
	for i := range existing {
		index[existing[i].Name] = i
	}
	for i := range incoming {
		incomingCapability := incoming[i]
		if incomingCapability.Name == "" {
			continue
		}
		if i, ok := index[incomingCapability.Name]; ok {
			mergeCapability(&existing[i], incomingCapability)
			continue
		}
		index[incomingCapability.Name] = len(existing)
		existing = append(existing, incomingCapability)
	}
	sort.Slice(existing, func(i, j int) bool { return existing[i].Name < existing[j].Name })
	return existing
}

func mergeCapability(dst *Capability, src Capability) {
	if dst == nil {
		return
	}
	if dst.FindingCode == "" {
		dst.FindingCode = src.FindingCode
	}
	if dst.Source == "" {
		dst.Source = src.Source
	}
	if confidenceRank(src.Confidence) > confidenceRank(dst.Confidence) {
		dst.Confidence = src.Confidence
	}
	if src.DirectCalls > dst.DirectCalls {
		dst.DirectCalls = src.DirectCalls
	}
	if src.IndirectCalls > dst.IndirectCalls {
		dst.IndirectCalls = src.IndirectCalls
	}
	dst.NewInDiff = dst.NewInDiff || src.NewInDiff
	dst.LocalEvidence = collect.AppendUnique(dst.LocalEvidence, src.LocalEvidence...)
	dst.Evidence = mergeCapabilityEvidence(dst.Evidence, src.Evidence...)
	mergeCapabilityDomains(dst, src)
}

func mergeCapabilityEvidence(existing []SourceLocation, incoming ...SourceLocation) []SourceLocation {
	if len(incoming) == 0 {
		return existing
	}
	seen := collect.NewSet[capabilityEvidenceKey]()
	for _, loc := range existing {
		seen.Add(capabilityEvidenceKeyFor(loc))
	}
	for _, loc := range incoming {
		if !seen.Add(capabilityEvidenceKeyFor(loc)) {
			continue
		}
		existing = append(existing, loc)
	}
	sort.Slice(existing, func(i, j int) bool {
		if existing[i].File == existing[j].File {
			return existing[i].Line < existing[j].Line
		}
		return existing[i].File < existing[j].File
	})
	return existing
}

type capabilityEvidenceKey struct {
	File      string
	Line      int
	Text      string
	URL       string
	LocalPath string
}

func capabilityEvidenceKeyFor(loc SourceLocation) capabilityEvidenceKey {
	return capabilityEvidenceKey{
		File:      loc.File,
		Line:      loc.Line,
		Text:      loc.Text,
		URL:       loc.URL,
		LocalPath: loc.LocalPath,
	}
}

func mergeCapabilityDomains(dst *Capability, src Capability) {
	if dst == nil {
		return
	}
	knownTotal := max(domainTotal(*dst), domainTotal(src))
	dst.Domains = collect.AppendUniqueSortedStrings(dst.Domains, src.Domains...)
	if len(dst.Domains) > knownTotal {
		knownTotal = len(dst.Domains)
	}
	if len(dst.Domains) > maxMergedCapabilityDomains {
		dst.Domains = append([]string(nil), dst.Domains[:maxMergedCapabilityDomains]...)
	}
	if knownTotal > len(dst.Domains) {
		dst.DomainCount = knownTotal
	} else {
		dst.DomainCount = 0
	}
}

func domainTotal(c Capability) int {
	if c.DomainCount > len(c.Domains) {
		return c.DomainCount
	}
	return len(c.Domains)
}

const maxMergedCapabilityDomains = 8

func confidenceRank(c Confidence) int {
	switch c {
	case ConfidenceHigh:
		return 3
	case ConfidenceMedium:
		return 2
	case ConfidenceLow:
		return 1
	default:
		return 0
	}
}

func packageFilesByModule(pkgs []gomod.Package) map[string][]string {
	out := map[string][]string{}
	seen := map[string]collect.Set[string]{}
	for i := range pkgs {
		p := pkgs[i]
		if p.Module == nil || p.Module.Path == "" || p.Dir == "" {
			continue
		}
		if seen[p.Module.Path] == nil {
			seen[p.Module.Path] = collect.NewSet[string]()
		}
		for _, name := range append(append([]string{}, p.GoFiles...), p.CgoFiles...) {
			if strings.TrimSpace(name) == "" {
				continue
			}
			path := filepath.Join(p.Dir, name)
			if seen[p.Module.Path].Add(path) {
				out[p.Module.Path] = append(out[p.Module.Path], path)
			}
		}
	}
	return out
}

func moduleDir(m ModuleReport) string {
	if m.Replacement != nil && m.Replacement.Local {
		return m.Replacement.Path
	}
	return m.LocalDir
}

func goEnvSummary(ctx context.Context, dir string, timeout time.Duration) GoEnvSummary {
	s := GoEnvSummary{}
	if out, err := gomod.Go(ctx, dir, timeout, "version"); err == nil {
		s.GoVersion = strings.TrimSpace(out)
	}
	out, err := gomod.Go(ctx, dir, timeout, "env", "-json", "GOMOD", "GOWORK", "GOMODCACHE", "GOPRIVATE", "GONOPROXY", "GONOSUMDB")
	if err != nil {
		return s
	}
	var env map[string]string
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		return s
	}
	s.GOMOD = strings.TrimSpace(env["GOMOD"])
	s.GOWORK = strings.TrimSpace(env["GOWORK"])
	s.GOMODCACHE = strings.TrimSpace(env["GOMODCACHE"])
	s.GOPRIVATE = collect.SplitCommaList(env["GOPRIVATE"])
	s.GONOPROXY = collect.SplitCommaList(env["GONOPROXY"])
	s.GONOSUMDB = collect.SplitCommaList(env["GONOSUMDB"])
	return s
}

func goGet(ctx context.Context, dir, spec string, timeout time.Duration) error {
	_, err := gomod.Go(ctx, dir, timeout, "get", spec)
	return err
}

func detectLocalLicenses(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	for _, e := range entries {
		name := strings.ToLower(e.Name())
		if e.IsDir() || (!strings.HasPrefix(name, "license") && !strings.HasPrefix(name, "copying")) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		text := strings.ToLower(string(data))
		switch {
		case strings.Contains(text, "mit license"):
			return []string{"MIT"}
		case strings.Contains(text, "apache license") && strings.Contains(text, "version 2.0"):
			return []string{"Apache-2.0"}
		case strings.Contains(text, "bsd 3-clause"):
			return []string{"BSD-3-Clause"}
		case strings.Contains(text, "bsd 2-clause"):
			return []string{"BSD-2-Clause"}
		case strings.Contains(text, "gnu general public license") && strings.Contains(text, "version 3"):
			return []string{"GPL-3.0"}
		case strings.Contains(text, "gnu affero general public license"):
			return []string{"AGPL-3.0"}
		}
	}
	return nil
}
