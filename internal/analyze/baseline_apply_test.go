package analyze

import (
	"testing"

	"github.com/maksemen2/trustmod/internal/baseline"
	"github.com/maksemen2/trustmod/internal/findings"
	"github.com/maksemen2/trustmod/internal/policy"
)

func TestApplyBaselineMarksProjectLevelGovulncheckFindings(t *testing.T) {
	f := findings.New("TM-SEC-001", "golang.org/x/net", "v0.1.0", "govulncheck")
	pol := policy.Default("backend-service")
	report := &ProjectReport{
		Modules: []ModuleReport{{
			ModulePath:      "golang.org/x/net",
			SelectedVersion: "v0.1.0",
			Findings:        []Finding{f},
		}},
		Findings: []Finding{f},
		Policy:   pol.Summary("", false, nil),
	}
	base := baseline.Baseline{
		AcceptedFindings: []baseline.AcceptedFinding{{
			Module:  "golang.org/x/net",
			Version: "v0.1.0",
			Code:    "TM-SEC-001",
		}},
	}

	applyBaseline(report, base, ".trustmod/baseline.yml", true)
	policy.EvaluateProject(report, pol)

	if !report.Modules[0].Findings[0].BaselineAccepted {
		t.Fatalf("module-level finding was not accepted")
	}
	if len(report.Findings) == 0 || !report.Findings[0].BaselineAccepted {
		t.Fatalf("project-level govulncheck finding was not accepted: %#v", report.Findings)
	}
	if report.Verdict != VerdictAllow {
		t.Fatalf("expected accepted govulncheck finding not to affect verdict, got %s", report.Verdict)
	}
}
