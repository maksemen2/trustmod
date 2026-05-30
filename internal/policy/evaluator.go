package policy

import (
	"sort"
	"strconv"

	"github.com/maksemen2/trustmod/internal/collect"
	"github.com/maksemen2/trustmod/internal/findings"
	analyze "github.com/maksemen2/trustmod/internal/model"
)

func EvaluateProject(report *analyze.ProjectReport, p Policy) {
	for i := range report.Modules {
		evaluateModule(&report.Modules[i], p)
	}
	for _, status := range report.Providers {
		if p.Strict && MatchAny(p.Providers.Required, status.Name) && !analyze.ProviderStatusSatisfiesRequirement(status.Status) {
			f := findings.New("TM-POL-002", "", "", "policy")
			f.Evidence = []string{"required provider " + status.Name + " status: " + status.Status}
			report.Findings = append(report.Findings, f)
		}
	}
	report.Findings = collectFindings(report.Modules, report.Findings)
	report.Summary = summarize(*report, p.Allow.FindingCodes)
	report.Verdict = analyze.VerdictAllow
	for i := range report.Modules {
		report.Verdict = analyze.MaxVerdict(report.Verdict, report.Modules[i].Verdict)
	}
	for i := range report.Findings {
		f := report.Findings[i]
		if !f.BaselineAccepted && !MatchAny(p.Allow.FindingCodes, f.Code) {
			report.Verdict = analyze.MaxVerdict(report.Verdict, f.VerdictImpact)
		}
	}
	report.ExitCodeRecommendation = 0
	for _, v := range p.Summary(report.Policy.Path, report.Policy.Loaded, nil).FailOn {
		if report.Verdict == v || (v == analyze.VerdictReview && report.Verdict == analyze.VerdictBlock) {
			report.ExitCodeRecommendation = 1
		}
	}
}

func evaluateModule(m *analyze.ModuleReport, p Policy) {
	findingKeys := newFindingKeySet(m.Findings)
	if MatchAny(p.Deny.Modules, m.ModulePath) {
		f := findings.New("TM-POL-001", m.ModulePath, m.SelectedVersion, "policy")
		f.PolicyRule = "deny.modules"
		addFindingOnce(m, findingKeys, f)
	}
	if len(m.Licenses) > 0 {
		for _, l := range m.Licenses {
			if MatchAny(p.Licenses.Banned, l) {
				f := findings.New("TM-LIC-001", m.ModulePath, m.SelectedVersion, "policy")
				f.Evidence = []string{"license " + l + " is banned by policy"}
				f.PolicyRule = "licenses.banned"
				addFindingOnce(m, findingKeys, f)
			}
		}
	}
	if p.Thresholds.TransitiveReview > 0 && m.Direct && m.DependencyFootprint.TransitiveModules > p.Thresholds.TransitiveReview {
		f := findings.New("TM-FP-001", m.ModulePath, m.SelectedVersion, "local-go-list")
		f.Evidence = []string{"transitive modules: " + strconv.Itoa(m.DependencyFootprint.TransitiveModules)}
		addFindingOnce(m, findingKeys, f)
	}
	risk := 0
	contrib := map[string]analyze.RiskContribution{}
	verdict := analyze.VerdictAllow
	m.RiskContributions = nil
	for i := range m.Findings {
		f := m.Findings[i]
		if f.BaselineAccepted || MatchAny(p.Allow.FindingCodes, f.Code) {
			continue
		}
		points := findings.SeverityPoints(f.Severity)
		risk += points
		verdict = analyze.MaxVerdict(verdict, f.VerdictImpact)
		if f.Code != "" {
			contrib[f.Code] = analyze.RiskContribution{Code: f.Code, Reason: f.Title, Points: contrib[f.Code].Points + points}
		}
	}
	if risk > 100 {
		risk = 100
	}
	if p.Thresholds.RiskBlock > 0 && risk >= p.Thresholds.RiskBlock {
		verdict = analyze.VerdictBlock
	} else if p.Thresholds.RiskReview > 0 && risk >= p.Thresholds.RiskReview {
		verdict = analyze.MaxVerdict(verdict, analyze.VerdictReview)
	}
	m.RiskScore = risk
	m.Verdict = verdict
	for _, c := range contrib {
		m.RiskContributions = append(m.RiskContributions, c)
	}
	sort.Slice(m.RiskContributions, func(i, j int) bool {
		if m.RiskContributions[i].Points == m.RiskContributions[j].Points {
			return m.RiskContributions[i].Code < m.RiskContributions[j].Code
		}
		return m.RiskContributions[i].Points > m.RiskContributions[j].Points
	})
}

type findingKey struct {
	Code          string
	Source        string
	ModulePath    string
	ModuleVersion string
	PolicyRule    string
}

func newFindingKeySet(in []analyze.Finding) collect.Set[findingKey] {
	out := make(collect.Set[findingKey], len(in))
	for i := range in {
		out.Add(keyForFinding(in[i]))
	}
	return out
}

func addFindingOnce(m *analyze.ModuleReport, seen collect.Set[findingKey], f analyze.Finding) {
	key := keyForFinding(f)
	if !seen.Add(key) {
		return
	}
	m.Findings = append(m.Findings, f)
}

func keyForFinding(f analyze.Finding) findingKey {
	return findingKey{
		Code:          f.Code,
		Source:        f.Source,
		ModulePath:    f.ModulePath,
		ModuleVersion: f.ModuleVersion,
		PolicyRule:    f.PolicyRule,
	}
}

func collectFindings(mods []analyze.ModuleReport, project []analyze.Finding) []analyze.Finding {
	out := append([]analyze.Finding(nil), project...)
	seen := collect.NewSet[string]()
	for i := range out {
		seen.Add(out[i].ID)
	}
	for i := range mods {
		m := &mods[i]
		for j := range m.Findings {
			f := m.Findings[j]
			if !seen.Add(f.ID) {
				continue
			}
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].VerdictImpact == out[j].VerdictImpact {
			if out[i].Code == out[j].Code {
				return out[i].ModulePath < out[j].ModulePath
			}
			return out[i].Code < out[j].Code
		}
		return verdictRank(out[i].VerdictImpact) > verdictRank(out[j].VerdictImpact)
	})
	return out
}

func Summarize(report analyze.ProjectReport) analyze.Summary {
	return summarize(report, nil)
}

func summarize(report analyze.ProjectReport, allowedFindingCodes []string) analyze.Summary {
	var s analyze.Summary
	s.Modules = len(report.Modules)
	moduleFindingIDs := collect.NewSet[string]()
	for i := range report.Modules {
		m := report.Modules[i]
		if m.Direct {
			s.DirectModules++
		} else if !m.Private {
			s.TransitiveModules++
		}
		if m.Private {
			s.PrivateModules++
		}
		s.Capabilities += len(m.Capabilities)
		s.KnownVulnerabilities += m.Security.KnownVulnerabilities
		for j := range m.Findings {
			f := m.Findings[j]
			moduleFindingIDs.Add(f.ID)
			s.Findings++
			if f.BaselineAccepted {
				s.BaselineAccepted++
				continue
			}
			if MatchAny(allowedFindingCodes, f.Code) {
				continue
			}
			switch f.VerdictImpact {
			case analyze.VerdictBlock:
				s.BlockingFindings++
			case analyze.VerdictReview:
				s.ReviewFindings++
			}
			if f.NewInDiff {
				s.NewFindings++
			}
		}
	}
	for i := range report.Findings {
		f := report.Findings[i]
		if moduleFindingIDs.Has(f.ID) {
			continue
		}
		s.Findings++
		if f.BaselineAccepted {
			s.BaselineAccepted++
			continue
		}
		if MatchAny(allowedFindingCodes, f.Code) {
			continue
		}
		switch f.VerdictImpact {
		case analyze.VerdictBlock:
			s.BlockingFindings++
		case analyze.VerdictReview:
			s.ReviewFindings++
		}
	}
	for _, st := range report.Providers {
		if analyze.ProviderStatusCountsAsError(st.Status) {
			s.ProviderErrors++
		}
	}
	if report.Diff != nil {
		s.NewModules = len(report.Diff.NewModules)
		s.UpdatedModules = len(report.Diff.UpdatedModules)
		s.RemovedModules = len(report.Diff.RemovedModules)
	}
	return s
}

func verdictRank(v analyze.Verdict) int {
	switch v {
	case analyze.VerdictBlock:
		return 3
	case analyze.VerdictReview:
		return 2
	default:
		return 1
	}
}
