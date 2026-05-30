package gomod

import (
	"os"
	"strings"

	"golang.org/x/mod/module"
)

type PrivateMatcher struct {
	Patterns string
	Main     []string
}

func NewPrivateMatcher(mainModules []string) PrivateMatcher {
	patterns := make([]string, 0, 8)
	for _, env := range []string{"GOPRIVATE", "GONOPROXY", "GONOSUMDB"} {
		patterns = append(patterns, splitPatterns(os.Getenv(env))...)
	}
	return PrivateMatcher{Patterns: strings.Join(patterns, ","), Main: mainModules}
}

func (m PrivateMatcher) IsPrivate(modulePath string) bool {
	for _, main := range m.Main {
		if modulePath == main || strings.HasPrefix(modulePath, main+"/") {
			return true
		}
	}
	return module.MatchPrefixPatterns(m.Patterns, modulePath)
}

func splitPatterns(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
