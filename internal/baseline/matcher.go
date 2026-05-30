package baseline

import (
	"path"
	"strings"
	"time"
)

func (b Baseline) AcceptsFinding(module, version, code string, now time.Time) bool {
	return acceptedFinding(module, version, code, b.AcceptedFindings, now) || acceptedModule(module, version, b.AcceptedModules, now)
}

func (b Baseline) ExpiredFindings(now time.Time) []AcceptedFinding {
	var out []AcceptedFinding
	for _, e := range b.AcceptedFindings {
		if expired(e.Expires, now) {
			out = append(out, e)
		}
	}
	return out
}

func (b Baseline) ExpiredModules(now time.Time) []AcceptedModule {
	var out []AcceptedModule
	for _, e := range b.AcceptedModules {
		if expired(e.Expires, now) {
			out = append(out, e)
		}
	}
	return out
}

func acceptedFinding(module, version, code string, entries []AcceptedFinding, now time.Time) bool {
	for _, e := range entries {
		if e.Code != "" && e.Code != code {
			continue
		}
		if !match(e.Module, module) {
			continue
		}
		if e.Version != "" && e.Version != version {
			continue
		}
		if expired(e.Expires, now) {
			continue
		}
		return true
	}
	return false
}

func acceptedModule(module, version string, entries []AcceptedModule, now time.Time) bool {
	for _, e := range entries {
		if !match(e.Module, module) {
			continue
		}
		if e.Version != "" && e.Version != version {
			continue
		}
		if expired(e.Expires, now) {
			continue
		}
		return true
	}
	return false
}

func match(pattern, value string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false
	}
	if pattern == value {
		return true
	}
	if ok, _ := path.Match(pattern, value); ok {
		return true
	}
	if strings.HasSuffix(pattern, "/...") && strings.HasPrefix(value, strings.TrimSuffix(pattern, "/...")) {
		return true
	}
	return false
}

func expired(value string, now time.Time) bool {
	if value == "" {
		return false
	}
	t, err := time.Parse("2006-01-02", value)
	if err != nil {
		t, err = time.Parse(time.RFC3339, value)
	}
	if err != nil {
		return true
	}
	return now.After(t)
}
