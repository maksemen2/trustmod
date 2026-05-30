package analyze

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestCompareVersionsUsesSemverPrecedence(t *testing.T) {
	if compareVersions("v1.10.0", "v1.9.9") <= 0 {
		t.Fatalf("expected v1.10.0 to compare newer than v1.9.9")
	}
	if compareVersions("v1.0.0-rc.1", "v1.0.0") >= 0 {
		t.Fatalf("expected pre-release to compare lower than the final release")
	}
	if compareVersions("not-semver", "v0.0.1") >= 0 {
		t.Fatalf("expected invalid versions to compare lower than valid semver")
	}
}

func TestDiffGoModSnapshotReadsWorkspaceModules(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	root := t.TempDir()
	writeTestFile(t, root, "go.work", "go 1.23.0\n\nuse (\n\t./app\n\t./dep\n)\n")
	writeTestFile(t, root, "app/go.mod", "module example.com/app\n\ngo 1.23.0\n\nrequire example.com/dep v1.9.9\n")
	writeTestFile(t, root, "app/main.go", "package main\n\nfunc main() {}\n")
	writeTestFile(t, root, "dep/go.mod", "module example.com/dep\n\ngo 1.23.0\n")
	writeTestFile(t, root, "dep/dep.go", "package dep\n")
	runGit(t, root, "init")
	runGit(t, root, "config", "user.email", "trustmod@example.invalid")
	runGit(t, root, "config", "user.name", "trustmod test")
	runGit(t, root, "add", ".")
	runGit(t, root, "commit", "-m", "base")
	writeTestFile(t, root, "app/go.mod", "module example.com/app\n\ngo 1.23.0\n\nrequire example.com/dep v1.10.0\n")

	base, err := refDiffGoModSnapshot(context.Background(), root, "HEAD")
	if err != nil {
		t.Fatalf("base snapshot: %v", err)
	}
	current, err := currentDiffGoModSnapshot(root)
	if err != nil {
		t.Fatalf("current snapshot: %v", err)
	}
	if got := base.Requirements["example.com/dep"]; got != "v1.9.9" {
		t.Fatalf("base dependency = %q, want v1.9.9", got)
	}
	if got := current.Requirements["example.com/dep"]; got != "v1.10.0" {
		t.Fatalf("current dependency = %q, want v1.10.0", got)
	}
	if !current.Direct["example.com/dep"] {
		t.Fatalf("expected nested workspace requirement to stay direct")
	}

	analyzer, err := NewAnalyzer(Options{
		WorkingDir: root,
		NoCache:    true,
		DisabledProviders: map[string]bool{
			"osv":         true,
			"deps.dev":    true,
			"github":      true,
			"scorecard":   true,
			"govulncheck": true,
		},
	})
	if err != nil {
		t.Fatalf("new analyzer: %v", err)
	}
	report, err := analyzer.Diff(context.Background(), DiffOptions{Path: root, Base: "HEAD"})
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	if len(report.Diff.UpdatedModules) != 1 {
		t.Fatalf("updated modules = %#v, want one nested workspace update", report.Diff.UpdatedModules)
	}
	update := report.Diff.UpdatedModules[0]
	if update.ModulePath != "example.com/dep" || update.From != "v1.9.9" || update.To != "v1.10.0" {
		t.Fatalf("unexpected workspace update: %#v", update)
	}
}

func TestDiffChangedFilesOnlyIncludesUncommittedModuleChanges(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	root := t.TempDir()
	writeTestFile(t, root, "go.mod", "module example.com/app\n\ngo 1.23.0\n\nrequire example.com/dep v1.9.9\n\nreplace example.com/dep => ./dep\n")
	writeTestFile(t, root, "main.go", "package main\n\nfunc main() {}\n")
	writeTestFile(t, root, "dep/go.mod", "module example.com/dep\n\ngo 1.23.0\n")
	writeTestFile(t, root, "dep/dep.go", "package dep\n")
	runGit(t, root, "init")
	runGit(t, root, "config", "user.email", "trustmod@example.invalid")
	runGit(t, root, "config", "user.name", "trustmod test")
	runGit(t, root, "add", ".")
	runGit(t, root, "commit", "-m", "base")
	writeTestFile(t, root, "go.mod", "module example.com/app\n\ngo 1.23.0\n\nrequire example.com/dep v1.10.0\n\nreplace example.com/dep => ./dep\n")

	analyzer := newOfflineDiffAnalyzer(t, root)
	report, err := analyzer.Diff(context.Background(), DiffOptions{Path: root, Base: "HEAD", ChangedFilesOnly: true})
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	if len(report.Diff.UpdatedModules) != 1 {
		t.Fatalf("updated modules = %#v, want uncommitted go.mod update", report.Diff.UpdatedModules)
	}
}

func TestDiffSnapshotReadsNestedModuleRelativeToGitRoot(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	root := t.TempDir()
	app := filepath.Join(root, "app")
	writeTestFile(t, root, "app/go.mod", "module example.com/app\n\ngo 1.23.0\n\nrequire example.com/dep v1.9.9\n\nreplace example.com/dep => ../dep\n")
	writeTestFile(t, root, "app/main.go", "package main\n\nfunc main() {}\n")
	writeTestFile(t, root, "dep/go.mod", "module example.com/dep\n\ngo 1.23.0\n")
	writeTestFile(t, root, "dep/dep.go", "package dep\n")
	runGit(t, root, "init")
	runGit(t, root, "config", "user.email", "trustmod@example.invalid")
	runGit(t, root, "config", "user.name", "trustmod test")
	runGit(t, root, "add", ".")
	runGit(t, root, "commit", "-m", "base")
	writeTestFile(t, root, "app/go.mod", "module example.com/app\n\ngo 1.23.0\n\nrequire example.com/dep v1.10.0\n\nreplace example.com/dep => ../dep\n")

	analyzer := newOfflineDiffAnalyzer(t, app)
	report, err := analyzer.Diff(context.Background(), DiffOptions{Path: app, Base: "HEAD", ChangedFilesOnly: true})
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	if len(report.Diff.UpdatedModules) != 1 {
		t.Fatalf("updated modules = %#v, want nested module update", report.Diff.UpdatedModules)
	}
	update := report.Diff.UpdatedModules[0]
	if update.ModulePath != "example.com/dep" || update.From != "v1.9.9" || update.To != "v1.10.0" {
		t.Fatalf("unexpected nested update: %#v", update)
	}
}

func newOfflineDiffAnalyzer(t *testing.T, root string) *Analyzer {
	t.Helper()
	analyzer, err := NewAnalyzer(Options{
		WorkingDir: root,
		NoCache:    true,
		Offline:    true,
		DisabledProviders: map[string]bool{
			"osv":         true,
			"deps.dev":    true,
			"github":      true,
			"scorecard":   true,
			"govulncheck": true,
		},
	})
	if err != nil {
		t.Fatalf("new analyzer: %v", err)
	}
	return analyzer
}

func writeTestFile(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("mkdir %s: %v", rel, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.CommandContext(context.Background(), "git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}
