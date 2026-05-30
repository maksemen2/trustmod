package analyze

import (
	"time"

	"github.com/maksemen2/trustmod/internal/baseline"
	"github.com/maksemen2/trustmod/internal/findings"
)

func applyBaseline(report *ProjectReport, b baseline.Baseline, path string, loaded bool) {
	now := time.Now()
	summary := BaselineSummary{Path: path, Loaded: loaded, AcceptedFindings: len(b.AcceptedFindings), AcceptedModules: len(b.AcceptedModules)}
	for i := range report.Modules {
		for j := range report.Modules[i].Findings {
			f := &report.Modules[i].Findings[j]
			if b.AcceptsFinding(f.ModulePath, f.ModuleVersion, f.Code, now) {
				f.BaselineAccepted = true
			}
		}
	}
	for i := range report.Findings {
		f := &report.Findings[i]
		if b.AcceptsFinding(f.ModulePath, f.ModuleVersion, f.Code, now) {
			f.BaselineAccepted = true
		}
	}
	for _, af := range b.ExpiredFindings(now) {
		summary.ExpiredExceptions++
		f := findings.New("TM-BAS-001", af.Module, af.Version, "baseline")
		f.Evidence = []string{"expired finding exception for " + af.Code}
		report.Findings = append(report.Findings, f)
	}
	for _, am := range b.ExpiredModules(now) {
		summary.ExpiredExceptions++
		f := findings.New("TM-BAS-001", am.Module, am.Version, "baseline")
		f.Evidence = []string{"expired module exception"}
		report.Findings = append(report.Findings, f)
	}
	report.Baseline = summary
}
