package report

import analyze "github.com/maksemen2/trustmod/internal/model"

func HasBlockingFindings(r *analyze.ProjectReport) bool {
	return r.Summary.BlockingFindings > 0 || r.Verdict == analyze.VerdictBlock
}
