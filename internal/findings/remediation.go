package findings

func RemediationFor(code string) []string {
	def, ok := Lookup(code)
	if !ok {
		return []string{"Review this finding manually."}
	}
	out := make([]string, len(def.Remediation))
	copy(out, def.Remediation)
	return out
}
