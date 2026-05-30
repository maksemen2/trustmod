package buildinfo

import (
	"runtime/debug"
	"strings"
)

type Info struct {
	Version string
	Commit  string
	Date    string
}

func Resolve(base Info) Info {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return base
	}
	return Enrich(base, info)
}

func Enrich(base Info, info *debug.BuildInfo) Info {
	if info == nil {
		return base
	}
	if isDefaultValue(base.Version) {
		if v := cleanValue(info.Main.Version); v != "" {
			base.Version = v
		}
	}
	settings := settingsMap(info)
	if isDefaultValue(base.Commit) {
		if v := cleanValue(settings["vcs.revision"]); v != "" {
			base.Commit = v
		}
	}
	if isDefaultValue(base.Date) {
		if v := cleanValue(settings["vcs.time"]); v != "" {
			base.Date = v
		}
	}
	return base
}

func settingsMap(info *debug.BuildInfo) map[string]string {
	out := make(map[string]string, len(info.Settings))
	for _, setting := range info.Settings {
		out[setting.Key] = setting.Value
	}
	return out
}

func isDefaultValue(v string) bool {
	switch strings.TrimSpace(v) {
	case "", "dev", "unknown", "(devel)":
		return true
	default:
		return false
	}
}

func cleanValue(v string) string {
	v = strings.TrimSpace(v)
	if isDefaultValue(v) {
		return ""
	}
	return v
}
