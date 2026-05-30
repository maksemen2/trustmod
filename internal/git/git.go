package git

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/maksemen2/trustmod/internal/command"
	"github.com/maksemen2/trustmod/internal/pathutil"
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
	return pathutil.CleanAbs(filepath.FromSlash(strings.TrimSpace(out))), nil
}

func RelativePath(ctx context.Context, worktreeRoot, path string) (string, error) {
	if prefix, err := WorktreePrefix(ctx, path); err == nil {
		return prefix, nil
	}
	rel, ok := pathutil.RelativeInside(worktreeRoot, path)
	if !ok {
		return "", fmt.Errorf("%s is outside git worktree %s", path, worktreeRoot)
	}
	if rel == "." {
		return "", nil
	}
	return filepath.ToSlash(rel), nil
}

func WorktreePrefix(ctx context.Context, dir string) (string, error) {
	out, err := run(ctx, dir, 5*time.Second, "rev-parse", "--show-prefix")
	if err != nil {
		return "", err
	}
	prefix := strings.Trim(strings.TrimSpace(out), "/")
	if prefix == "" {
		return "", nil
	}
	return filepath.ToSlash(filepath.Clean(filepath.FromSlash(prefix))), nil
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
