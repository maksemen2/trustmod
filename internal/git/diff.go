package git

import (
	"context"
	"sort"
	"strings"
	"time"
)

func Show(ctx context.Context, dir, ref, path string) ([]byte, error) {
	out, err := run(ctx, dir, 10*time.Second, "show", ref+":"+path)
	return []byte(out), err
}

func MergeBase(ctx context.Context, dir, base string) (string, error) {
	out, err := run(ctx, dir, 10*time.Second, "merge-base", base, "HEAD")
	return strings.TrimSpace(out), err
}

func ChangedFiles(ctx context.Context, dir, base string) ([]string, error) {
	seen := map[string]bool{}
	files, err := changedFilesFrom(ctx, dir, base+"...HEAD")
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		seen[file] = true
	}
	for _, spec := range []string{"HEAD", "--cached"} {
		files, err := changedFilesFrom(ctx, dir, spec)
		if err != nil {
			continue
		}
		for _, file := range files {
			seen[file] = true
		}
	}
	out := make([]string, 0, len(seen))
	for file := range seen {
		out = append(out, file)
	}
	sort.Strings(out)
	return out, nil
}

func changedFilesFrom(ctx context.Context, dir, spec string) ([]string, error) {
	out, err := run(ctx, dir, 10*time.Second, "diff", "--name-only", spec)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			files = append(files, line)
		}
	}
	return files, nil
}
