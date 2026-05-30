package analyze

import "strings"

func ModuleSpecParts(spec string) (path string, version string) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return "", ""
	}
	if i := strings.LastIndex(spec, "@"); i > 0 {
		return spec[:i], spec[i+1:]
	}
	return spec, "latest"
}

func ModuleKey(path, version string) string {
	if version == "" {
		return path
	}
	return path + "@" + version
}
