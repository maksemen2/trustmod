package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	analyze "github.com/maksemen2/trustmod/internal/model"
	"github.com/maksemen2/trustmod/internal/pathutil"
)

func JSONProject(r *analyze.ProjectReport) ([]byte, error) {
	if r == nil {
		return []byte("null\n"), nil
	}
	safe, err := cloneProjectReport(r)
	if err != nil {
		return nil, err
	}
	normalizeProjectReport(&safe)
	sanitizeProjectReport(&safe)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(&safe); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func JSONCompare(r *analyze.CompareReport) ([]byte, error) {
	normalizeCompareReport(r)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func normalizeProjectReport(r *analyze.ProjectReport) {
	if r == nil {
		return
	}
	if r.MainModules == nil {
		r.MainModules = []string{}
	}
	if r.Providers == nil {
		r.Providers = []analyze.ProviderStatus{}
	}
	if r.Modules == nil {
		r.Modules = []analyze.ModuleReport{}
	}
	if r.Findings == nil {
		r.Findings = []analyze.Finding{}
	}
	normalizeGraph(&r.DependencyGraph)
	if r.Diff != nil {
		normalizeDiff(r.Diff)
	}
	for i := range r.Modules {
		normalizeModule(&r.Modules[i])
	}
}

func cloneProjectReport(r *analyze.ProjectReport) (analyze.ProjectReport, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return analyze.ProjectReport{}, err
	}
	var out analyze.ProjectReport
	if err := json.Unmarshal(data, &out); err != nil {
		return analyze.ProjectReport{}, err
	}
	return out, nil
}

func sanitizeProjectReport(r *analyze.ProjectReport) {
	if r == nil {
		return
	}
	redactor := newPathRedactor()
	r.ProjectRoot = redactor.path(r.ProjectRoot)
	r.Policy.Path = redactor.path(r.Policy.Path)
	r.Baseline.Path = redactor.path(r.Baseline.Path)
	r.GoEnvSummary.GOMOD = redactor.path(r.GoEnvSummary.GOMOD)
	r.GoEnvSummary.GOWORK = redactor.path(r.GoEnvSummary.GOWORK)
	r.GoEnvSummary.GOMODCACHE = redactor.path(r.GoEnvSummary.GOMODCACHE)
	r.GoEnvSummary.GOPRIVATE = nil
	r.GoEnvSummary.GONOPROXY = nil
	r.GoEnvSummary.GONOSUMDB = nil
	r.Notes = redactor.strings(r.Notes)
	r.DependencyGraph.Notes = redactor.strings(r.DependencyGraph.Notes)
	for i := range r.Providers {
		r.Providers[i].ErrorSummary = redactor.string(r.Providers[i].ErrorSummary)
	}
	for i := range r.Findings {
		sanitizeFinding(&r.Findings[i], redactor)
	}
	for i := range r.Modules {
		m := &r.Modules[i]
		for j := range m.Findings {
			sanitizeFinding(&m.Findings[j], redactor)
		}
		for j := range m.Capabilities {
			m.Capabilities[j].LocalEvidence = redactor.strings(m.Capabilities[j].LocalEvidence)
			for k := range m.Capabilities[j].Evidence {
				loc := &m.Capabilities[j].Evidence[k]
				loc.File = redactor.path(loc.File)
				loc.Text = redactor.string(loc.Text)
			}
		}
		for j := range m.DataAvailability {
			m.DataAvailability[j].ErrorSummary = redactor.string(m.DataAvailability[j].ErrorSummary)
		}
	}
}

func sanitizeFinding(f *analyze.Finding, redactor pathRedactor) {
	f.File = redactor.path(f.File)
	f.Evidence = redactor.strings(f.Evidence)
	f.References = redactor.strings(f.References)
}

type pathRedactor struct {
	cwd      string
	home     string
	temp     string
	prefixes []redactionPrefix
}

type redactionPrefix struct {
	prefix string
	label  string
}

func newPathRedactor() pathRedactor {
	cwd, _ := os.Getwd()
	home, _ := os.UserHomeDir()
	p := pathRedactor{
		cwd:  pathutil.CleanAbs(cwd),
		home: pathutil.CleanAbs(home),
		temp: pathutil.CleanAbs(os.TempDir()),
	}
	p.prefixes = redactionPrefixes(
		redactionPrefix{prefix: cwd, label: "."},
		redactionPrefix{prefix: p.cwd, label: "."},
		redactionPrefix{prefix: home, label: "~"},
		redactionPrefix{prefix: p.home, label: "~"},
		redactionPrefix{prefix: os.TempDir(), label: "<temp>"},
		redactionPrefix{prefix: p.temp, label: "<temp>"},
	)
	return p
}

func redactionPrefixes(prefixes ...redactionPrefix) []redactionPrefix {
	seen := map[string]bool{}
	out := make([]redactionPrefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		prefix.prefix = filepath.Clean(strings.TrimSpace(prefix.prefix))
		if prefix.prefix == "" || prefix.prefix == "." || prefix.label == "" {
			continue
		}
		key := prefix.label + "\x00" + prefix.prefix
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, prefix)
	}
	sort.Slice(out, func(i, j int) bool {
		return len(out[i].prefix) > len(out[j].prefix)
	})
	return out
}

func (p pathRedactor) strings(values []string) []string {
	if len(values) == 0 {
		return values
	}
	out := make([]string, len(values))
	for i := range values {
		out[i] = p.string(values[i])
	}
	return out
}

func (p pathRedactor) string(value string) string {
	for _, prefix := range p.prefixes {
		value = p.replacePathPrefix(value, prefix.prefix, prefix.label)
	}
	return value
}

func (p pathRedactor) path(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.Contains(value, "://") || !filepath.IsAbs(value) {
		return filepath.ToSlash(value)
	}
	if rel, ok := pathutil.RelativeInside(p.cwd, value); ok {
		return filepath.ToSlash(rel)
	}
	if rel, ok := pathutil.RelativeInside(p.temp, value); ok {
		return pathutil.JoinLabel("<temp>", rel)
	}
	if rel, ok := pathutil.RelativeInside(p.home, value); ok {
		return pathutil.JoinLabel("~", rel)
	}
	base := filepath.Base(value)
	if base == "." || base == string(filepath.Separator) || base == "" {
		return "<redacted>"
	}
	return pathutil.JoinLabel("<redacted>", base)
}

func (p pathRedactor) replacePathPrefix(value, prefix, label string) string {
	if value == "" || prefix == "" {
		return value
	}
	cleanPrefix := filepath.ToSlash(prefix)
	if cleanPrefix == "" {
		return value
	}
	value = strings.ReplaceAll(value, cleanPrefix, label)
	osPrefix := filepath.Clean(prefix)
	if osPrefix != cleanPrefix {
		value = strings.ReplaceAll(value, osPrefix, label)
	}
	return value
}

func normalizeCompareReport(r *analyze.CompareReport) {
	if r == nil {
		return
	}
	if r.Entries == nil {
		r.Entries = []analyze.CompareEntry{}
	}
	for i := range r.Entries {
		normalizeModule(&r.Entries[i].Module)
		if r.Entries[i].KeyNotes == nil {
			r.Entries[i].KeyNotes = []string{}
		}
	}
}

func normalizeModule(m *analyze.ModuleReport) {
	if m.Findings == nil {
		m.Findings = []analyze.Finding{}
	}
	if m.Capabilities == nil {
		m.Capabilities = []analyze.Capability{}
	}
	if m.Licenses == nil {
		m.Licenses = []string{}
	}
	if m.DataAvailability == nil {
		m.DataAvailability = []analyze.ProviderStatus{}
	}
	if m.DependencyFootprint.ShortestModulePaths == nil {
		m.DependencyFootprint.ShortestModulePaths = []string{}
	}
}

func normalizeGraph(g *analyze.DependencyGraph) {
	if g.Nodes == nil {
		g.Nodes = []analyze.GraphNode{}
	}
	if g.Edges == nil {
		g.Edges = []analyze.GraphEdge{}
	}
	if g.Notes == nil {
		g.Notes = []string{}
	}
}

func normalizeDiff(d *analyze.DiffReport) {
	if d.NewModules == nil {
		d.NewModules = []analyze.DiffModuleChange{}
	}
	if d.UpdatedModules == nil {
		d.UpdatedModules = []analyze.DiffModuleChange{}
	}
	if d.RemovedModules == nil {
		d.RemovedModules = []analyze.DiffModuleChange{}
	}
	if d.Notes == nil {
		d.Notes = []string{}
	}
}
