package findings

import analyze "github.com/maksemen2/trustmod/internal/model"

func SeverityPoints(sev analyze.Severity) int {
	switch sev {
	case analyze.SeverityCritical:
		return 40
	case analyze.SeverityHigh:
		return 28
	case analyze.SeverityMedium:
		return 14
	case analyze.SeverityLow:
		return 5
	case analyze.SeverityInfo:
		return 1
	default:
		return 3
	}
}

func SARIFLevel(sev analyze.Severity) string {
	switch sev {
	case analyze.SeverityCritical, analyze.SeverityHigh:
		return "error"
	case analyze.SeverityMedium:
		return "warning"
	case analyze.SeverityLow:
		return "note"
	default:
		return "none"
	}
}
