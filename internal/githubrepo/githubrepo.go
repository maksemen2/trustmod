package githubrepo

import (
	"net/url"
	"path"
	"strconv"
	"strings"
)

type Repository struct {
	Owner  string
	Name   string
	Subdir string
}

func FromModule(modulePath string) (Repository, bool) {
	parts := strings.Split(strings.Trim(modulePath, "/"), "/")
	if len(parts) < 3 || parts[0] != "github.com" || parts[1] == "" || parts[2] == "" {
		return Repository{}, false
	}
	rest := parts[3:]
	if len(rest) > 0 && isMajorPathSuffix(rest[len(rest)-1]) {
		rest = rest[:len(rest)-1]
	}
	return Repository{
		Owner:  parts[1],
		Name:   strings.TrimSuffix(parts[2], ".git"),
		Subdir: strings.Join(rest, "/"),
	}, true
}

func URI(modulePath string) (string, bool) {
	repo, ok := FromModule(modulePath)
	if !ok {
		return "", false
	}
	return repo.URI(), true
}

func URLFromModule(modulePath string) (repoURL, subdir string, ok bool) {
	repo, ok := FromModule(modulePath)
	if !ok {
		return "", "", false
	}
	return repo.URL(), repo.Subdir, true
}

func NormalizeURL(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	if strings.HasPrefix(raw, "github.com/") {
		raw = "https://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host != "github.com" {
		return "", false
	}
	parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", false
	}
	return (Repository{Owner: parts[0], Name: strings.TrimSuffix(parts[1], ".git")}).URL(), true
}

func SourceTarget(modulePath, rawRepo string) (repoURL, subdir string, ok bool) {
	if normalized, ok := NormalizeURL(rawRepo); ok {
		if _, derivedSubdir, derivedOK := URLFromModule(modulePath); derivedOK {
			return normalized, derivedSubdir, true
		}
		return normalized, "", true
	}
	return URLFromModule(modulePath)
}

func RefForVersion(version string) (string, bool) {
	version = strings.TrimSpace(version)
	if version == "" || version == "(main)" || version == "(devel)" {
		return "", false
	}
	version = strings.TrimSuffix(version, "+incompatible")
	if commit := pseudoVersionCommit(version); commit != "" {
		return commit, true
	}
	return version, true
}

func BlobURL(repoURL, ref, subdir, file string, line int) string {
	sourcePath := joinPath(subdir, file)
	out := strings.TrimRight(repoURL, "/") + "/blob/" + url.PathEscape(ref) + "/" + escapePath(sourcePath)
	if line > 0 {
		out += "#L" + strconv.Itoa(line)
	}
	return out
}

func (r Repository) URI() string {
	if r.Owner == "" || r.Name == "" {
		return ""
	}
	return "github.com/" + r.Owner + "/" + r.Name
}

func (r Repository) URL() string {
	if r.Owner == "" || r.Name == "" {
		return ""
	}
	return "https://github.com/" + r.Owner + "/" + r.Name
}

func joinPath(parts ...string) string {
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.Trim(path.Clean(strings.ReplaceAll(part, "\\", "/")), "/")
		if part != "" && part != "." {
			out = append(out, part)
		}
	}
	return strings.Join(out, "/")
}

func escapePath(p string) string {
	parts := strings.Split(strings.ReplaceAll(p, "\\", "/"), "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
}

func pseudoVersionCommit(version string) string {
	parts := strings.Split(version, "-")
	if len(parts) < 3 {
		return ""
	}
	commit := parts[len(parts)-1]
	if len(commit) < 12 || !isLowerHex(commit) {
		return ""
	}
	return commit
}

func isMajorPathSuffix(s string) bool {
	if len(s) < 2 || s[0] != 'v' {
		return false
	}
	for _, r := range s[1:] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != "v0" && s != "v1"
}

func isLowerHex(s string) bool {
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}
