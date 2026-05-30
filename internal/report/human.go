package report

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	analyze "github.com/maksemen2/trustmod/internal/model"
	"github.com/maksemen2/trustmod/internal/textutil"
	"golang.org/x/term"
)

type HumanOptions struct {
	NoColor bool
	Verbose bool
}

func HumanProject(w io.Writer, r *analyze.ProjectReport, opts HumanOptions) {
	c := colors{enabled: !opts.NoColor && isTerminal(w)}
	if len(r.Modules) == 1 || r.ModuleMode == "detached" && len(r.Modules) > 0 {
		humanModule(w, r, opts, c)
		return
	}
	fmt.Fprintln(w, c.bold("trustmod project dependency review"))
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Project: %s\n", r.ProjectRoot)
	fmt.Fprintf(w, "Mode:    %s\n", r.ModuleMode)
	fmt.Fprintf(w, "Verdict: %s\n", c.verdict(r.Verdict))
	fmt.Fprintf(w, "Profile: %s\n", r.Policy.Profile)
	fmt.Fprintf(w, "Modules: %d direct, %d transitive, %d private\n", r.Summary.DirectModules, r.Summary.TransitiveModules, r.Summary.PrivateModules)
	fmt.Fprintf(w, "Findings: %d (%d block, %d review)\n", r.Summary.Findings, r.Summary.BlockingFindings, r.Summary.ReviewFindings)
	if r.Diff != nil {
		fmt.Fprintf(w, "Diff:    +%d ~%d -%d vs %s\n", len(r.Diff.NewModules), len(r.Diff.UpdatedModules), len(r.Diff.RemovedModules), r.Diff.Base)
	}
	printWhy(w, r.Findings, c)
	printModules(w, r.Modules, c)
	printData(w, r.Providers)
	printNext(w, r.Verdict, "audit")
	if opts.Verbose {
		printPrivacy(w, r)
	}
}

func humanModule(w io.Writer, r *analyze.ProjectReport, opts HumanOptions, c colors) {
	module := r.Modules[0]
	fmt.Fprintln(w, c.bold("trustmod module review"))
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Module:  %s\n", module.ModulePath)
	fmt.Fprintf(w, "Version: %s\n", textutil.DashIfEmpty(module.SelectedVersion))
	if module.RequestedVersion != "" {
		fmt.Fprintf(w, "Request: %s\n", module.RequestedVersion)
	}
	fmt.Fprintf(w, "Verdict: %s\n", c.verdict(module.Verdict))
	fmt.Fprintf(w, "Risk:    %d/100\n", module.RiskScore)
	fmt.Fprintf(w, "Profile: %s\n", r.Policy.Profile)
	printWhy(w, module.Findings, c)
	printGoodSignals(w, module)
	printCapabilities(w, module, opts.Verbose)
	printData(w, r.Providers)
	printNext(w, module.Verdict, "check")
	if opts.Verbose {
		printPrivacy(w, r)
	}
}

func HumanCompare(w io.Writer, r *analyze.CompareReport, opts HumanOptions) {
	c := colors{enabled: !opts.NoColor && isTerminal(w)}
	fmt.Fprintln(w, c.bold("trustmod module comparison"))
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Profile: %s\n", r.Profile)
	if r.UseCase != "" {
		fmt.Fprintf(w, "Use case: %s\n", r.UseCase)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "| Module | Verdict | Risk | License | Direct deps | Transitive deps | Key notes |")
	fmt.Fprintln(w, "|---|---:|---:|---|---:|---:|---|")
	for i := range r.Entries {
		e := &r.Entries[i]
		m := e.Module
		fmt.Fprintf(w, "| %s | %s | %d | %s | %d | %d | %s |\n",
			m.ModulePath, m.Verdict, m.RiskScore, strings.Join(m.Licenses, ","), e.DirectDependencies, e.TransitiveDeps, strings.Join(e.KeyNotes, ", "))
	}
	if r.Recommendation != "" {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Recommendation under "+r.Profile+":")
		fmt.Fprintln(w, "  "+r.Recommendation)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Caveat:")
	fmt.Fprintln(w, "  "+r.Caveat)
}

func printWhy(w io.Writer, findings []analyze.Finding, c colors) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Why:")
	count := 0
	for i := range findings {
		f := findings[i]
		if f.BaselineAccepted {
			continue
		}
		if f.VerdictImpact == analyze.VerdictAllow && count >= 5 {
			continue
		}
		fmt.Fprintf(w, "  %-6s  %-10s  %s", c.verdict(f.VerdictImpact), f.Code, f.Title)
		if f.ModulePath != "" {
			fmt.Fprintf(w, " (%s)", f.ModulePath)
		}
		fmt.Fprint(w, findingInlineDetail(f))
		fmt.Fprintln(w)
		count++
		if count >= 12 {
			break
		}
	}
	if count == 0 {
		fmt.Fprintln(w, "  OK      no blocking or review-level findings under this policy")
	}
}

func findingInlineDetail(f analyze.Finding) string {
	if len(f.Evidence) == 0 {
		return ""
	}
	switch f.Code {
	case "TM-MNT-001":
		return archivedFindingInlineDetail(f.Evidence[0])
	case "TM-CAP-003":
		return networkFindingInlineDetail(f.Evidence)
	default:
		return ""
	}
}

func networkFindingInlineDetail(evidence []string) string {
	for _, item := range evidence {
		if domains, ok := strings.CutPrefix(item, "network domains: "); ok {
			return " domains: " + sanitizeLine(domains)
		}
	}
	return ""
}

func archivedFindingInlineDetail(evidence string) string {
	const archivedAtPrefix = "GitHub repository archived at "
	if rest, ok := strings.CutPrefix(evidence, archivedAtPrefix); ok {
		if when, _, ok := strings.Cut(rest, "): "); ok {
			return " at " + sanitizeLine(when) + ")"
		}
		return " at " + sanitizeLine(rest)
	}

	const missingPrefix = "GitHub repository is archived; archive date unavailable"
	if rest, ok := strings.CutPrefix(evidence, missingPrefix); ok {
		if reason, _, ok := strings.Cut(strings.TrimSpace(rest), ": "); ok && reason != "" {
			return "; archive date unavailable " + sanitizeLine(reason)
		}
		return "; archive date unavailable"
	}

	return ""
}

func printModules(w io.Writer, modules []analyze.ModuleReport, c colors) {
	if len(modules) == 0 {
		return
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Modules:")
	limit := len(modules)
	if limit > 12 {
		limit = 12
	}
	for i := 0; i < limit; i++ {
		m := modules[i]
		if !m.Direct && m.Verdict == analyze.VerdictAllow {
			continue
		}
		fmt.Fprintf(w, "  %-6s  %-44s %s\n", c.verdict(m.Verdict), m.ModulePath, textutil.DashIfEmpty(m.SelectedVersion))
	}
}

func printGoodSignals(w io.Writer, m analyze.ModuleReport) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Good signals:")
	if m.Security.KnownVulnerabilities == 0 {
		fmt.Fprintln(w, "  OK  No known vulnerabilities reported by enabled providers")
	}
	if len(m.Licenses) > 0 {
		fmt.Fprintln(w, "  OK  License: "+strings.Join(m.Licenses, ", "))
	}
	if !m.Maintenance.RepositoryArchived && m.Repository != "" {
		fmt.Fprintln(w, "  OK  Repository is not archived")
	}
}

func printCapabilities(w io.Writer, m analyze.ModuleReport, verbose bool) {
	if len(m.Capabilities) == 0 {
		return
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Capabilities:")
	limit := len(m.Capabilities)
	if limit > 8 {
		limit = 8
	}
	for i := 0; i < limit; i++ {
		c := m.Capabilities[i]
		fmt.Fprintf(w, "  %-18s confidence:%s", c.Name, c.Confidence)
		if domains := capabilityDomainSummary(c); domains != "" {
			fmt.Fprintf(w, " domains: %s", domains)
		}
		if loc, ok := firstCapabilityLocation(c); ok {
			label := sourceLocationLabel(loc)
			fmt.Fprintf(w, " (%s)", label)
			if link := sourceLocationLink(loc); link != "" && link != label {
				fmt.Fprintf(w, " -> %s", link)
			}
			if verbose {
				if loc.URL != "" {
					fmt.Fprintf(w, "\n      web:   %s", loc.URL)
				}
				if uri := vscodeURI(loc); uri != "" {
					fmt.Fprintf(w, "\n      local: %s", uri)
				}
			}
		}
		fmt.Fprintln(w)
	}
}

func capabilityDomainSummary(c analyze.Capability) string {
	if len(c.Domains) == 0 {
		return ""
	}
	limit := len(c.Domains)
	if limit > 5 {
		limit = 5
	}
	parts := append([]string(nil), c.Domains[:limit]...)
	total := c.DomainCount
	if total <= 0 {
		total = len(c.Domains)
	}
	if more := total - limit; more > 0 {
		parts = append(parts, "+"+strconv.Itoa(more)+" more")
	}
	return strings.Join(parts, ", ")
}

func firstCapabilityLocation(c analyze.Capability) (analyze.SourceLocation, bool) {
	for _, loc := range c.Evidence {
		if loc.File != "" || loc.URL != "" {
			return loc, true
		}
	}
	return analyze.SourceLocation{}, false
}

func sourceLocationLabel(loc analyze.SourceLocation) string {
	if loc.File == "" {
		if loc.URL != "" {
			return loc.URL
		}
		return vscodeURI(loc)
	}
	if loc.Line > 0 {
		return loc.File + ":" + strconv.Itoa(loc.Line)
	}
	return loc.File
}

func sourceLocationLink(loc analyze.SourceLocation) string {
	if loc.URL != "" {
		return loc.URL
	}
	return vscodeURI(loc)
}

func vscodeURI(loc analyze.SourceLocation) string {
	if loc.LocalPath == "" {
		return ""
	}
	path := loc.LocalPath
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	path = filepath.ToSlash(path)
	if runtime.GOOS == "windows" && len(path) >= 2 && path[1] == ':' {
		path = strings.ToUpper(path[:1]) + path[1:]
	}
	out := "vscode://file/" + escapeVSCodePath(path)
	if loc.Line > 0 {
		out += ":" + strconv.Itoa(loc.Line)
	}
	return out
}

func escapeVSCodePath(path string) string {
	leadingSlash := strings.HasPrefix(path, "/")
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if part == "" {
			continue
		}
		if i == 0 && len(part) == 2 && part[1] == ':' {
			continue
		}
		parts[i] = url.PathEscape(part)
	}
	out := strings.Join(parts, "/")
	if leadingSlash && !strings.HasPrefix(out, "/") {
		out = "/" + out
	}
	return out
}

func printData(w io.Writer, providers []analyze.ProviderStatus) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Data:")
	if len(providers) == 0 {
		fmt.Fprintln(w, "  local          ok")
		return
	}
	for _, p := range providers {
		name := p.Name
		if len(name) > 14 {
			name = name[:14]
		}
		fmt.Fprintf(w, "  %-14s %s", name, p.Status)
		if p.Cached {
			fmt.Fprint(w, " cached")
		}
		if p.ErrorSummary != "" {
			fmt.Fprint(w, " - "+sanitizeLine(p.ErrorSummary))
		}
		fmt.Fprintln(w)
	}
}

func printNext(w io.Writer, verdict analyze.Verdict, mode string) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Next:")
	switch verdict {
	case analyze.VerdictBlock:
		fmt.Fprintln(w, "  Blocking findings need remediation before this passes the default policy.")
	case analyze.VerdictReview:
		fmt.Fprintln(w, "  Manual review recommended under this policy.")
		if mode == "check" {
			fmt.Fprintln(w, "  To add anyway: trustmod add <module> --allow-review")
		}
	default:
		fmt.Fprintln(w, "  No blocking or review-level findings under this policy.")
	}
}

func printPrivacy(w io.Writer, r *analyze.ProjectReport) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Privacy:")
	for _, p := range r.Providers {
		if p.Name == "privacy" {
			fmt.Fprintf(w, "  private modules skipped for remote providers: %d\n", p.Skipped)
		}
	}
	fmt.Fprintln(w, "  no telemetry or update checks are performed")
}

func sanitizeLine(s string) string {
	return textutil.SingleLine(s, 120)
}

func isTerminal(w io.Writer) bool {
	if f, ok := w.(*os.File); ok {
		return term.IsTerminal(int(f.Fd()))
	}
	return false
}

type colors struct{ enabled bool }

func (c colors) bold(s string) string {
	if !c.enabled {
		return s
	}
	return "\x1b[1m" + s + "\x1b[0m"
}

func (c colors) verdict(v analyze.Verdict) string {
	if !c.enabled {
		return string(v)
	}
	switch v {
	case analyze.VerdictBlock:
		return "\x1b[31m" + string(v) + "\x1b[0m"
	case analyze.VerdictReview:
		return "\x1b[33m" + string(v) + "\x1b[0m"
	default:
		return "\x1b[32m" + string(v) + "\x1b[0m"
	}
}
