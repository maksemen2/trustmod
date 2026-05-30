package policy

func Validate(p Policy) []string {
	var warnings []string
	if p.Version == 0 {
		warnings = append(warnings, "policy version is not set; assuming version 1")
	}
	if p.Thresholds.RiskReview > 0 && p.Thresholds.RiskBlock > 0 && p.Thresholds.RiskReview > p.Thresholds.RiskBlock {
		warnings = append(warnings, "risk_review is greater than risk_block")
	}
	return warnings
}
