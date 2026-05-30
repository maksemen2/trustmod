package pathutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRelativeInside(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "a", "b.txt")
	rel, ok := RelativeInside(root, inside)
	if !ok || rel != filepath.Join("a", "b.txt") {
		t.Fatalf("RelativeInside inside = %q, %v", rel, ok)
	}

	if rel, ok := RelativeInside(root, filepath.Dir(root)); ok {
		t.Fatalf("RelativeInside outside = %q, true", rel)
	}
}

func TestHasPrefix(t *testing.T) {
	if !HasPrefix(filepath.Join("a", "b", "c.go"), filepath.Join("a", "b")) {
		t.Fatal("expected nested path to match prefix")
	}
	if HasPrefix(filepath.Join("a", "bee", "c.go"), filepath.Join("a", "b")) {
		t.Fatal("expected sibling path not to match prefix")
	}
}

func TestJoinLabel(t *testing.T) {
	if got := JoinLabel("<temp>", "."); got != "<temp>" {
		t.Fatalf("JoinLabel dot = %q", got)
	}
	if got := JoinLabel("<temp>", filepath.Join("a", "b.txt")); got != "<temp>/a/b.txt" {
		t.Fatalf("JoinLabel nested = %q", got)
	}
}

func TestRelativeInsideResolvesSymlinkedExistingParent(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	link := filepath.Join(root, "link")
	if err := os.MkdirAll(filepath.Join(realDir, "service"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realDir, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	rel, ok := RelativeInside(realDir, filepath.Join(link, "service", "go.mod"))
	if !ok || rel != filepath.Join("service", "go.mod") {
		t.Fatalf("RelativeInside symlinked child = %q, %v", rel, ok)
	}
}
