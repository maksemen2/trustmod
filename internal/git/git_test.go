package git

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRelativePathResolvesSymlinkedWorktreePath(t *testing.T) {
	root := t.TempDir()
	worktree := filepath.Join(root, "worktree")
	link := filepath.Join(root, "link")
	if err := os.MkdirAll(filepath.Join(worktree, "app"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(worktree, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	rel, err := RelativePath(context.Background(), worktree, filepath.Join(link, "app", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if rel != "app/go.mod" {
		t.Fatalf("relative path = %q, want app/go.mod", rel)
	}
}

func TestWorktreePrefixUsesGitViewOfSymlinkedPath(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	root := t.TempDir()
	worktree := filepath.Join(root, "worktree")
	link := filepath.Join(root, "link")
	if err := os.MkdirAll(filepath.Join(worktree, "app"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(worktree, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	runTestGit(t, worktree, "init")

	prefix, err := WorktreePrefix(context.Background(), filepath.Join(link, "app"))
	if err != nil {
		t.Fatal(err)
	}
	if prefix != "app" {
		t.Fatalf("prefix = %q, want app", prefix)
	}
}

func runTestGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.CommandContext(context.Background(), "git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}
