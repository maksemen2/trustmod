package gomod

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestModGraphAnnotatesDirectAndPrivateNodes(t *testing.T) {
	t.Setenv("GOPRIVATE", "example.com/*")
	root := t.TempDir()
	depDir := filepath.Join(root, "dep")
	if err := os.MkdirAll(depDir, 0o750); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "go.mod"), `module example.com/app

go 1.23

require example.com/dep v1.0.0

replace example.com/dep => ./dep
`)
	writeFile(t, filepath.Join(depDir, "go.mod"), `module example.com/dep

go 1.23
`)

	graph, err := ModGraph(context.Background(), root, 30*time.Second)
	if err != nil {
		t.Fatalf("ModGraph failed: %v", err)
	}
	nodes := map[string]struct {
		direct  bool
		private bool
	}{}
	for _, node := range graph.Nodes {
		nodes[node.ID] = struct {
			direct  bool
			private bool
		}{direct: node.Direct, private: node.Private}
	}
	for _, path := range []string{"example.com/app", "example.com/dep"} {
		node, ok := nodes[path]
		if !ok {
			t.Fatalf("expected graph node %s in %#v", path, graph.Nodes)
		}
		if !node.direct {
			t.Fatalf("expected %s to be marked direct", path)
		}
		if !node.private {
			t.Fatalf("expected %s to be marked private", path)
		}
	}
}

func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}
