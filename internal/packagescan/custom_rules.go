package packagescan

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/maksemen2/trustmod/internal/collect"
	analyze "github.com/maksemen2/trustmod/internal/model"
	"gopkg.in/yaml.v3"
)

type customRulesFile struct {
	Version int              `yaml:"version"`
	Rules   []customRuleSpec `yaml:"rules"`
}

type customRuleSpec struct {
	ID          string              `yaml:"id"`
	Code        string              `yaml:"code"`
	Title       string              `yaml:"title"`
	Description string              `yaml:"description"`
	Category    string              `yaml:"category"`
	Severity    string              `yaml:"severity"`
	Verdict     string              `yaml:"verdict"`
	Confidence  string              `yaml:"confidence"`
	Remediation []string            `yaml:"remediation"`
	Match       customRuleMatchSpec `yaml:"match"`
}

type customRuleMatchSpec struct {
	RequireAll    bool     `yaml:"require_all"`
	CaseSensitive bool     `yaml:"case_sensitive"`
	Imports       []string `yaml:"imports"`
	Selectors     []string `yaml:"selectors"`
	Strings       []string `yaml:"strings"`
	Domains       []string `yaml:"domains"`
}

type customSourceRule struct {
	id          string
	code        string
	title       string
	description string
	category    string
	severity    analyze.Severity
	verdict     analyze.Verdict
	confidence  analyze.Confidence
	remediation []string
	match       customRuleMatchSpec
}

func LoadSourceRules(path string) ([]SourceRule, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc customRulesFile
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse custom rules %s: %w", path, err)
	}
	if doc.Version != 0 && doc.Version != 1 {
		return nil, fmt.Errorf("custom rules %s: unsupported version %d", path, doc.Version)
	}
	rules := make([]SourceRule, 0, len(doc.Rules))
	ids := collect.NewSet[string]()
	codes := collect.NewSet[string]()
	for i := range doc.Rules {
		rule, err := newCustomSourceRule(i, doc.Rules[i])
		if err != nil {
			return nil, fmt.Errorf("custom rules %s: %w", path, err)
		}
		if !ids.Add(rule.id) {
			return nil, fmt.Errorf("custom rules %s: duplicate id %q", path, rule.id)
		}
		if !codes.Add(rule.code) {
			return nil, fmt.Errorf("custom rules %s: duplicate code %q", path, rule.code)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func newCustomSourceRule(index int, spec customRuleSpec) (customSourceRule, error) {
	id := strings.TrimSpace(spec.ID)
	if id == "" {
		return customSourceRule{}, fmt.Errorf("rule %d: id is required", index+1)
	}
	if spec.Match.empty() {
		return customSourceRule{}, fmt.Errorf("rule %q: at least one match condition is required", id)
	}
	code := strings.TrimSpace(spec.Code)
	if code == "" {
		code = "TM-CUSTOM-" + leftPadInt(index+1, 3)
	}
	title := strings.TrimSpace(spec.Title)
	if title == "" {
		title = id
	}
	severity, err := parseRuleSeverity(spec.Severity)
	if err != nil {
		return customSourceRule{}, fmt.Errorf("rule %q: %w", id, err)
	}
	verdict, err := parseRuleVerdict(spec.Verdict)
	if err != nil {
		return customSourceRule{}, fmt.Errorf("rule %q: %w", id, err)
	}
	confidence, err := parseRuleConfidence(spec.Confidence)
	if err != nil {
		return customSourceRule{}, fmt.Errorf("rule %q: %w", id, err)
	}
	return customSourceRule{
		id:          id,
		code:        code,
		title:       title,
		description: collect.FirstNonEmpty(strings.TrimSpace(spec.Description), "Custom source rule matched local code."),
		category:    collect.FirstNonEmpty(strings.TrimSpace(spec.Category), "custom"),
		severity:    severity,
		verdict:     verdict,
		confidence:  confidence,
		remediation: trimStrings(spec.Remediation),
		match:       normalizeCustomMatch(spec.Match),
	}, nil
}

func (m customRuleMatchSpec) empty() bool {
	return len(m.Imports) == 0 && len(m.Selectors) == 0 && len(m.Strings) == 0 && len(m.Domains) == 0
}

func normalizeCustomMatch(m customRuleMatchSpec) customRuleMatchSpec {
	m.Imports = trimStrings(m.Imports)
	m.Selectors = trimStrings(m.Selectors)
	m.Strings = trimStrings(m.Strings)
	m.Domains = trimDomains(m.Domains)
	return m
}

func (r customSourceRule) ID() string {
	return r.id
}

func (r customSourceRule) Code() string {
	return r.code
}

func (r customSourceRule) Title() string {
	return r.title
}

func (r customSourceRule) Description() string {
	return r.description
}

func (r customSourceRule) Category() string {
	return r.category
}

func (r customSourceRule) Severity() analyze.Severity {
	return r.severity
}

func (r customSourceRule) VerdictImpact() analyze.Verdict {
	return r.verdict
}

func (r customSourceRule) Confidence() analyze.Confidence {
	return r.confidence
}

func (r customSourceRule) Remediation() []string {
	return append([]string(nil), r.remediation...)
}

func (r customSourceRule) Source() string {
	return "custom-source-rule"
}

func (r customSourceRule) Match(facts sourceFacts) []sourceRuleMatch {
	var matches []sourceRuleMatch
	for _, file := range facts.Files {
		if matched, evs := r.matchFile(file); matched {
			matches = append(matches, sourceRuleMatch{Evidence: evs})
		}
	}
	return matches
}

func (r customSourceRule) matchFile(file sourceFileFacts) (bool, []evidence) {
	needed := 0
	matched := 0
	var evs []evidence
	record := func(found []evidence) {
		needed++
		if len(found) == 0 {
			return
		}
		matched++
		evs = append(evs, found[0])
	}
	for _, importPath := range r.match.Imports {
		record(matchCustomImport(file, importPath, r.match.CaseSensitive))
	}
	for _, selector := range r.match.Selectors {
		record(matchCustomSelector(file, selector, r.match.CaseSensitive))
	}
	for _, substring := range r.match.Strings {
		record(matchCustomString(file, substring, r.match.CaseSensitive))
	}
	for _, domain := range r.match.Domains {
		record(matchCustomDomain(file, domain, r.match.CaseSensitive))
	}
	if needed == 0 || matched == 0 {
		return false, nil
	}
	if r.match.RequireAll && matched != needed {
		return false, nil
	}
	return true, limitEvidence(uniqueEvidence(evs), 8)
}

func matchCustomImport(file sourceFileFacts, want string, caseSensitive bool) []evidence {
	for _, importPath := range file.Imports {
		if equalRuleString(importPath, want, caseSensitive) {
			return []evidence{{file: file.Path, line: 1, text: "import " + importPath}}
		}
	}
	return nil
}

func matchCustomSelector(file sourceFileFacts, want string, caseSensitive bool) []evidence {
	var out []evidence
	for _, call := range file.Calls {
		if selectorRuleMatch(call, want, caseSensitive) {
			out = append(out, callEvidence(call))
		}
	}
	return out
}

func matchCustomString(file sourceFileFacts, want string, caseSensitive bool) []evidence {
	var out []evidence
	for _, literal := range file.Strings {
		if containsRuleString(literal.Value, want, caseSensitive) {
			out = append(out, evidence{file: literal.File, line: literal.Line, text: "string contains " + strconv.Quote(want)})
		}
	}
	return out
}

func matchCustomDomain(file sourceFileFacts, want string, caseSensitive bool) []evidence {
	var out []evidence
	for _, literal := range file.Strings {
		for _, domain := range domainsFromLiteral(literal.Value) {
			if domainRuleMatch(domain, want, caseSensitive) {
				out = append(out, evidence{file: literal.File, line: literal.Line, text: "domain matched: " + domain})
			}
		}
	}
	return out
}

func selectorRuleMatch(call sourceCall, want string, caseSensitive bool) bool {
	for _, candidate := range []string{call.Selector, call.Text} {
		if equalRuleString(candidate, want, caseSensitive) {
			return true
		}
	}
	return false
}

func domainsFromLiteral(value string) []string {
	seen := collect.NewSet[string]()
	for _, raw := range urlLiterals(value) {
		if domain := domainFromNetworkTarget(raw); domain != "" {
			seen.Add(domain)
		}
	}
	if domain := domainFromNetworkTarget(value); domain != "" {
		seen.Add(domain)
	}
	out := make([]string, 0, len(seen))
	for domain := range seen {
		out = append(out, domain)
	}
	sort.Strings(out)
	return out
}

func domainRuleMatch(domain, want string, caseSensitive bool) bool {
	domain = compareString(domain, caseSensitive)
	want = compareString(want, caseSensitive)
	return domain == want || strings.HasSuffix(domain, "."+want)
}

func equalRuleString(got, want string, caseSensitive bool) bool {
	return compareString(strings.TrimSpace(got), caseSensitive) == compareString(strings.TrimSpace(want), caseSensitive)
}

func containsRuleString(got, want string, caseSensitive bool) bool {
	return strings.Contains(compareString(got, caseSensitive), compareString(want, caseSensitive))
}

func compareString(value string, caseSensitive bool) string {
	if caseSensitive {
		return value
	}
	return strings.ToLower(value)
}

func uniqueEvidence(evs []evidence) []evidence {
	seen := collect.NewSet[string]()
	out := evs[:0]
	for _, ev := range evs {
		key := ev.file + "\x00" + strconv.Itoa(ev.line) + "\x00" + ev.text
		if !seen.Add(key) {
			continue
		}
		out = append(out, ev)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].file == out[j].file {
			if out[i].line == out[j].line {
				return out[i].text < out[j].text
			}
			return out[i].line < out[j].line
		}
		return out[i].file < out[j].file
	})
	return out
}

func limitEvidence(evs []evidence, limit int) []evidence {
	if limit > 0 && len(evs) > limit {
		return append([]evidence(nil), evs[:limit]...)
	}
	return evs
}

func parseRuleSeverity(value string) (analyze.Severity, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return analyze.SeverityMedium, nil
	case string(analyze.SeverityCritical):
		return analyze.SeverityCritical, nil
	case string(analyze.SeverityHigh):
		return analyze.SeverityHigh, nil
	case string(analyze.SeverityMedium):
		return analyze.SeverityMedium, nil
	case string(analyze.SeverityLow):
		return analyze.SeverityLow, nil
	case string(analyze.SeverityInfo):
		return analyze.SeverityInfo, nil
	default:
		return "", fmt.Errorf("unknown severity %q", value)
	}
}

func parseRuleVerdict(value string) (analyze.Verdict, error) {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "":
		return analyze.VerdictReview, nil
	case string(analyze.VerdictAllow):
		return analyze.VerdictAllow, nil
	case string(analyze.VerdictReview):
		return analyze.VerdictReview, nil
	case string(analyze.VerdictBlock):
		return analyze.VerdictBlock, nil
	default:
		return "", fmt.Errorf("unknown verdict %q", value)
	}
}

func parseRuleConfidence(value string) (analyze.Confidence, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return analyze.ConfidenceMedium, nil
	case string(analyze.ConfidenceHigh):
		return analyze.ConfidenceHigh, nil
	case string(analyze.ConfidenceMedium):
		return analyze.ConfidenceMedium, nil
	case string(analyze.ConfidenceLow):
		return analyze.ConfidenceLow, nil
	default:
		return "", fmt.Errorf("unknown confidence %q", value)
	}
}

func trimStrings(values []string) []string {
	out := values[:0]
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func trimDomains(values []string) []string {
	out := trimStrings(values)
	for i := range out {
		out[i] = strings.TrimPrefix(strings.TrimPrefix(out[i], "https://"), "http://")
		out[i] = strings.Trim(out[i], "/.")
	}
	return out
}

func leftPadInt(value, width int) string {
	out := strconv.Itoa(value)
	for len(out) < width {
		out = "0" + out
	}
	return out
}
