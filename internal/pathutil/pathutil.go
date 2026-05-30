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
	return filepath.Clean(abs)
}

func RelativeInside(root, path string) (string, bool) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", false
	}
	pathAbs, err := filepath.Abs(path)
	if err != nil {
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
