package pathutil

import (
	"os"
	"path/filepath"
	"strings"
)

func CleanAbs(path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return filepath.Clean(path)
	}
	return resolveExistingAbs(abs)
}

func RelativeInside(root, path string) (string, bool) {
	rootAbs := CleanAbs(root)
	if rootAbs == "" {
		return "", false
	}
	pathAbs := CleanAbs(path)
	if pathAbs == "" {
		return "", false
	}
	rel, err := filepath.Rel(rootAbs, pathAbs)
	if err != nil {
		return "", false
	}
	if rel == "." {
		return rel, true
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", false
	}
	return rel, true
}

func resolveExistingAbs(path string) string {
	clean := filepath.Clean(path)
	if resolved, err := filepath.EvalSymlinks(clean); err == nil {
		return filepath.Clean(resolved)
	}
	var suffix []string
	for current := clean; ; current = filepath.Dir(current) {
		parent := filepath.Dir(current)
		if parent == current {
			return clean
		}
		suffix = append(suffix, filepath.Base(current))
		if resolved, err := filepath.EvalSymlinks(parent); err == nil {
			for i := len(suffix) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, suffix[i])
			}
			return filepath.Clean(resolved)
		}
	}
}

func HasPrefix(path, prefix string) bool {
	cleanPath := filepath.Clean(path)
	cleanPrefix := filepath.Clean(prefix)
	return cleanPath == cleanPrefix || strings.HasPrefix(cleanPath, cleanPrefix+string(os.PathSeparator))
}

func JoinLabel(prefix, rel string) string {
	rel = filepath.ToSlash(rel)
	if rel == "." || rel == "" {
		return prefix
	}
	return prefix + "/" + rel
}
