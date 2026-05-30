package policy

import (
	"path"
	"strings"
)

func MatchAny(patterns []string, value string) bool {
	for _, pat := range patterns {
		pat = strings.TrimSpace(pat)
		if pat == "" {
			continue
		}
		if pat == value {
			return true
		}
		if ok, _ := path.Match(pat, value); ok {
			return true
		}
		if strings.HasSuffix(pat, "/...") && strings.HasPrefix(value, strings.TrimSuffix(pat, "/...")) {
			return true
		}
	}
	return false
}
