package report

import (
	"bytes"
	"fmt"
	"strings"

	analyze "github.com/maksemen2/trustmod/internal/model"
	"github.com/maksemen2/trustmod/internal/textutil"
)

func MarkdownProject(r *analyze.ProjectReport) []byte {
	var b bytes.Buffer
	fmt.Fprintln(&b, "## trustmod dependency review")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "**Verdict:** `%s`  \n", r.Verdict)
	fmt.Fprintf(&b, "**Profile:** `%s`  \n", r.Policy.Profile)
	fmt.Fprintf(&b, "**Findings:** %d total, %d blocking, %d review\n", r.Summary.Findings, r.Summary.BlockingFindings, r.Summary.ReviewFindings)
	if r.Diff != nil {
		fmt.Fprintf(&b, "\n**Diff:** +%d ~%d -%d vs `%s`\n", len(r.Diff.NewModules), len(r.Diff.UpdatedModules), len(r.Diff.RemovedModules), r.Diff.Base)
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "| Impact | Code | Severity | Confidence | Module | Evidence | Finding |")
	fmt.Fprintln(&b, "|---|---|---|---|---|---|---|")
	n := 0
	for i := range r.Findings {
		f := r.Findings[i]
		if f.BaselineAccepted {
			continue
		}
		fmt.Fprintf(&b, "| `%s` | `%s` | `%s` | `%s` | `%s` | %s | %s |\n", f.VerdictImpact, f.Code, f.Severity, f.Confidence, textutil.DashIfEmpty(f.ModulePath), markdownEvidence(r, f), textutil.EscapeMarkdownPipes(f.Title))
		n++
		if n >= 20 {
			break
		}
	}
	if n == 0 {
		fmt.Fprintln(&b, "| `ALLOW` | - | - | No blocking or review-level findings under this policy. |")
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "<details><summary>Data availability</summary>")
	fmt.Fprintln(&b)
	for _, p := range r.Providers {
		fmt.Fprintf(&b, "- `%s`: `%s`\n", p.Name, p.Status)
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "</details>")
	return b.Bytes()
}

func markdownEvidence(r *analyze.ProjectReport, f analyze.Finding) string {
	if f.File != "" {
		return markdownLocation(f.File, f.Line)
	}
	for i := range r.Modules {
		m := &r.Modules[i]
		if m.ModulePath != f.ModulePath {
			continue
		}
		for j := range m.Capabilities {
			capability := &m.Capabilities[j]
			if capability.FindingCode != f.Code {
				continue
			}
			for _, evidence := range capability.Evidence {
				uri := evidence.URL
				if uri == "" {
					uri = evidence.File
				}
				if uri != "" {
					return markdownLocation(uri, evidence.Line)
				}
			}
		}
	}
	if len(f.References) > 0 {
		ref := f.References[0]
		if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
			return fmt.Sprintf("[reference](%s)", ref)
		}
		return "`" + textutil.EscapeMarkdownPipes(ref) + "`"
	}
	if len(f.Evidence) > 0 {
		return "`" + textutil.EscapeMarkdownPipes(f.Evidence[0]) + "`"
	}
	return "-"
}

func markdownLocation(uri string, line int) string {
	label := uri
	if line > 0 && !hasLineHint(uri) {
		label = fmt.Sprintf("%s:%d", label, line)
	}
	if strings.HasPrefix(uri, "http://") || strings.HasPrefix(uri, "https://") || strings.HasPrefix(uri, "vscode://") {
		return fmt.Sprintf("[%s](%s)", textutil.EscapeMarkdownPipes(label), uri)
	}
	return "`" + textutil.EscapeMarkdownPipes(label) + "`"
}

func hasLineHint(uri string) bool {
	lower := strings.ToLower(uri)
	return strings.Contains(lower, "#l") || strings.Contains(lower, ":line=")
}

func MarkdownCompare(r *analyze.CompareReport) []byte {
	var b bytes.Buffer
	fmt.Fprintln(&b, "## trustmod module comparison")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "Profile: `%s`\n\n", r.Profile)
	fmt.Fprintln(&b, "| Module | Verdict | Risk | License | Direct deps | Transitive deps | Key notes |")
	fmt.Fprintln(&b, "|---|---:|---:|---|---:|---:|---|")
	for i := range r.Entries {
		e := &r.Entries[i]
		m := e.Module
		fmt.Fprintf(&b, "| `%s` | `%s` | %d | %s | %d | %d | %s |\n", m.ModulePath, m.Verdict, m.RiskScore, textutil.DashIfEmpty(strings.Join(m.Licenses, ",")), e.DirectDependencies, e.TransitiveDeps, textutil.EscapeMarkdownPipes(strings.Join(e.KeyNotes, ", ")))
	}
	if r.Recommendation != "" {
		fmt.Fprintf(&b, "\n**Recommendation:** %s\n", r.Recommendation)
	}
	fmt.Fprintf(&b, "\n_Caveat: %s_\n", r.Caveat)
	return b.Bytes()
}
