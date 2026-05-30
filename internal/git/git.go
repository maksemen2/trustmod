package git

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/maksemen2/trustmod/internal/command"
)

func InsideWorktree(ctx context.Context, dir string) bool {
	out, err := run(ctx, dir, 5*time.Second, "rev-parse", "--is-inside-work-tree")
	return err == nil && strings.TrimSpace(out) == "true"
}

func CurrentBranch(ctx context.Context, dir string) (string, error) {
	out, err := run(ctx, dir, 5*time.Second, "branch", "--show-current")
	return strings.TrimSpace(out), err
}

func WorktreeRoot(ctx context.Context, dir string) (string, error) {
	out, err := run(ctx, dir, 5*time.Second, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", err
	}
	return filepath.FromSlash(strings.TrimSpace(out)), nil
}

func RelativePath(ctx context.Context, worktreeRoot, path string) (string, error) {
	absRoot, err := filepath.Abs(worktreeRoot)
	if err != nil {
		return "", err
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(absRoot, absPath)
	if err != nil {
		return "", err
	}
	if rel == "." {
		return "", nil
	}
	return filepath.ToSlash(rel), nil
}

func run(ctx context.Context, dir string, timeout time.Duration, args ...string) (string, error) {
	out, err := command.CombinedOutput(ctx, dir, timeout, "git", args...)
	if command.IsTimeout(err) {
		return string(out), err
	}
	if err != nil {
		return string(out), fmt.Errorf("git %s failed: %s", strings.Join(args, " "), strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
