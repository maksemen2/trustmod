package gomod

import (
	"context"
	"strings"
	"time"

	"github.com/maksemen2/trustmod/internal/collect"
)

func WhyModule(ctx context.Context, dir, modulePath string, timeout time.Duration) ([]string, error) {
	paths, err := WhyModules(ctx, dir, []string{modulePath}, timeout)
	if err != nil {
		return nil, err
	}
	return paths[modulePath], nil
}

func WhyModules(ctx context.Context, dir string, modulePaths []string, timeout time.Duration) (map[string][]string, error) {
	clean := collect.UniqueTrimmedStrings(modulePaths)
	if len(clean) == 0 {
		return map[string][]string{}, nil
	}
	args := make([]string, 0, len(clean)+3)
	args = append(args, "mod", "why", "-m")
	args = append(args, clean...)
	out, err := Go(ctx, dir, timeout, args...)
	if err != nil {
		return nil, err
	}
	return parseWhyModulesOutput(clean, out), nil
}

func parseWhyModulesOutput(modulePaths []string, out string) map[string][]string {
	paths := make(map[string][]string, len(modulePaths))
	for _, modulePath := range modulePaths {
		paths[modulePath] = nil
	}
	current := ""
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			current = strings.TrimSpace(strings.TrimPrefix(line, "#"))
			if _, ok := paths[current]; !ok {
				paths[current] = nil
			}
			continue
		}
		if current != "" {
			paths[current] = append(paths[current], line)
		}
	}
	return paths
}
