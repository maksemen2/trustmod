package policy

import (
	"testing"

	"github.com/maksemen2/trustmod/internal/findings"
	analyze "github.com/maksemen2/trustmod/internal/model"
)

func TestEvaluateProjectBlocksDeniedModule(t *testing.T) {
	p := Default("backend-service")
	p.Deny.Modules = []string{"example.com/bad"}
	r := analyze.ProjectReport{
		Modules: []analyze.ModuleReport{{ModulePath: "example.com/bad", SelectedVersion: "v1.0.0", Direct: true}},
		Policy:  p.Summary("", true, nil),
	}
	EvaluateProject(&r, p)
	if r.Verdict != analyze.VerdictBlock {
		t.Fatalf("expected block, got %s", r.Verdict)
	}
}

func TestEvaluateProjectRiskReview(t *testing.T) {
	p := Default("backend-service")
	p.Thresholds.RiskReview = 5
	f := findings.New("TM-VER-005", "example.com/v0", "v0.9.0", "test")
	r := analyze.ProjectReport{
		Modules: []analyze.ModuleReport{{ModulePath: "example.com/v0", SelectedVersion: "v0.9.0", Direct: true, Findings: []analyze.Finding{f}}},
		Policy:  p.Summary("", true, nil),
	}
	EvaluateProject(&r, p)
	if r.Modules[0].Verdict != analyze.VerdictReview {
		t.Fatalf("expected review, got %s", r.Modules[0].Verdict)
	}
}

func TestEvaluateProjectAllowsSingleContextSignalBelowThreshold(t *testing.T) {
	p := Default("backend-service")
	f := findings.New("TM-CAP-005", "example.com/mod", "v1.0.0", "test")
	r := analyze.ProjectReport{
		Modules: []analyze.ModuleReport{{ModulePath: "example.com/mod", SelectedVersion: "v1.0.0", Direct: true, Findings: []analyze.Finding{f}}},
		Policy:  p.Summary("", true, nil),
	}
	EvaluateProject(&r, p)
	if r.Modules[0].Verdict != analyze.VerdictAllow {
		t.Fatalf("expected allow for a single low-risk context signal, got %s", r.Modules[0].Verdict)
	}
	if r.Modules[0].RiskScore == 0 {
		t.Fatalf("expected context signal to still contribute risk")
	}
}

func TestEvaluateProjectAllowedFindingCodesDoNotRaiseProjectVerdict(t *testing.T) {
	p := Default("backend-service")
	p.Allow.FindingCodes = []string{"TM-CAP-001"}
	p.FailOn = []string{string(analyze.VerdictReview)}
	f := findings.New("TM-CAP-001", "example.com/mod", "v1.0.0", "test")
	r := analyze.ProjectReport{
		Modules: []analyze.ModuleReport{{ModulePath: "example.com/mod", SelectedVersion: "v1.0.0", Direct: true, Findings: []analyze.Finding{f}}},
		Policy:  p.Summary("", true, nil),
	}
	EvaluateProject(&r, p)
	if r.Verdict != analyze.VerdictAllow || r.ExitCodeRecommendation != 0 {
		t.Fatalf("expected allowed finding code to keep project allowed, verdict=%s exit=%d", r.Verdict, r.ExitCodeRecommendation)
	}
	if r.Summary.ReviewFindings != 0 {
		t.Fatalf("expected allowed finding code to be excluded from review count, summary=%#v", r.Summary)
	}
}

func TestEvaluateProjectIsIdempotentForRiskAndPolicyFindings(t *testing.T) {
	p := Default("backend-service")
	p.Thresholds.TransitiveReview = 1
	f := findings.New("TM-CAP-005", "example.com/mod", "v1.0.0", "test")
	r := analyze.ProjectReport{
		Modules: []analyze.ModuleReport{{
			ModulePath:      "example.com/mod",
			SelectedVersion: "v1.0.0",
			Direct:          true,
			DependencyFootprint: analyze.DependencyFootprint{
				TransitiveModules: 2,
			},
			Findings: []analyze.Finding{f},
		}},
		Policy: p.Summary("", true, nil),
	}
	EvaluateProject(&r, p)
	EvaluateProject(&r, p)
	if got := len(r.Modules[0].RiskContributions); got != 2 {
		t.Fatalf("expected stable risk contribution count, got %d: %#v", got, r.Modules[0].RiskContributions)
	}
	fp := 0
	for _, f := range r.Modules[0].Findings {
		if f.Code == "TM-FP-001" {
			fp++
		}
	}
	if fp != 1 {
		t.Fatalf("expected one footprint policy finding, got %d", fp)
	}
}

func TestProviderSkippedStatesAreNotProviderErrors(t *testing.T) {
	r := analyze.ProjectReport{
		Providers: []analyze.ProviderStatus{
			{Name: "github", Enabled: true, Status: analyze.ProviderStatusSkippedUnsupportedHost},
			{Name: "scorecard", Enabled: true, Status: analyze.ProviderStatusSkippedNoProviderData},
			{Name: "deps.dev", Enabled: true, Status: analyze.ProviderStatusSkippedNoEligibleVersions},
			{Name: "govulncheck", Enabled: true, Status: analyze.ProviderStatusNotRequested},
			{Name: "osv", Enabled: true, Status: analyze.ProviderStatusOfflineCacheMiss},
		},
	}
	s := Summarize(r)
	if s.ProviderErrors != 1 {
		t.Fatalf("expected only offline cache miss to count as provider error, got %d", s.ProviderErrors)
	}
}

func TestSummarizeCountsProjectFindingsWithModulePath(t *testing.T) {
	f := findings.New("TM-GO-001", "not-a-module", "latest", "go get")
	r := analyze.ProjectReport{Findings: []analyze.Finding{f}}
	s := Summarize(r)
	if s.Findings != 1 || s.ReviewFindings != 1 {
		t.Fatalf("summary = %#v, want one review finding", s)
	}
}

func TestStrictRequiredProviderAllowsNotApplicableButNotDisabled(t *testing.T) {
	p := Default("strict")
	p.Strict = true
	p.Providers.Required = []string{"github", "govulncheck"}
	r := analyze.ProjectReport{
		Providers: []analyze.ProviderStatus{
			{Name: "github", Enabled: true, Status: analyze.ProviderStatusSkippedUnsupportedHost},
			{Name: "govulncheck", Enabled: true, Status: analyze.ProviderStatusNotRequested},
		},
		Policy: p.Summary("", true, nil),
	}
	EvaluateProject(&r, p)
	found := false
	for _, f := range r.Findings {
		if f.Code == "TM-POL-002" {
			found = true
			if len(f.Evidence) == 0 || f.Evidence[0] != "required provider govulncheck status: not_requested" {
				t.Fatalf("unexpected required-provider evidence: %#v", f.Evidence)
			}
		}
	}
	if !found {
		t.Fatalf("expected not_requested required provider to produce TM-POL-002")
	}
}
