package pathutil

import (
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
