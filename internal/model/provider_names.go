package model

import "strings"

func CanonicalProviderName(name string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "osv":
		return "osv", true
	case "deps.dev", "depsdev", "deps-dev":
		return "deps.dev", true
	case "github", "git-hub":
		return "github", true
	case "scorecard", "openssf-scorecard", "openssf_scorecard":
		return "scorecard", true
	case "govulncheck", "go-vulncheck":
		return "govulncheck", true
	default:
		return "", false
	}
}

func NormalizeProviderName(name string) string {
	if canonical, ok := CanonicalProviderName(name); ok {
		return canonical
	}
	return strings.ToLower(strings.TrimSpace(name))
}
