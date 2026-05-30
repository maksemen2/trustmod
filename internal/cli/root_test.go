package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReportMissingUserFileIsUsageExit(t *testing.T) {
	_, err := executeTestCommand(t, "report", filepath.Join(t.TempDir(), "missing.json"))
	if err == nil {
		t.Fatalf("expected missing report file to fail")
	}
	if code := ExitCode(err); code != ExitUsage {
		t.Fatalf("expected usage exit, got %d: %v", code, err)
	}
}

func TestUnsupportedFormatIsUsageExit(t *testing.T) {
	reportPath := filepath.Join(t.TempDir(), "trustmod.json")
	if err := os.WriteFile(reportPath, []byte(`{"schemaVersion":"trustmod.report/v1","verdict":"ALLOW"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := executeTestCommand(t, "--format", "bogus", "report", reportPath)
	if err == nil {
		t.Fatalf("expected unsupported format to fail")
	}
	if code := ExitCode(err); code != ExitUsage {
		t.Fatalf("expected usage exit, got %d: %v", code, err)
	}
}

func TestReportJSONHonorsOutFile(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "trustmod.json")
	if err := os.WriteFile(reportPath, []byte(`{"schemaVersion":"trustmod.report/v1","verdict":"ALLOW"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(dir, "rendered.json")
	stdout, err := executeTestCommand(t, "--format", "json", "--out", outPath, "report", reportPath)
	if err != nil {
		t.Fatalf("report failed: %v", err)
	}
	if strings.TrimSpace(stdout) != "" {
		t.Fatalf("expected report --out to keep stdout empty, got %q", stdout)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("expected report output file: %v", err)
	}
	if !strings.Contains(string(data), `"verdict": "ALLOW"`) {
		t.Fatalf("expected rendered JSON to contain verdict, got:\n%s", data)
	}
}

func TestReportRendersCompareReport(t *testing.T) {
	reportPath := filepath.Join(t.TempDir(), "compare.json")
	data := []byte(`{
  "schemaVersion": "trustmod.compare.v1",
  "profile": "backend-service",
  "entries": [{
    "module": {"modulePath": "example.com/a", "verdict": "ALLOW", "riskScore": 0, "dependencyFootprint": {}, "maintenance": {}, "security": {}, "identity": {}, "adoption": {}},
    "directDependencies": 0,
    "transitiveDependencies": 0
  }],
  "caveat": "test"
}`)
	if err := os.WriteFile(reportPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(t.TempDir(), "compare.md")
	out, err := executeTestCommand(t, "--format", "markdown", "--out", outPath, "report", reportPath)
	if err != nil {
		t.Fatalf("report compare failed: %v", err)
	}
	if strings.TrimSpace(out) != "" {
		t.Fatalf("expected --out to keep stdout empty, got:\n%s", out)
	}
	data, err = os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read compare output: %v", err)
	}
	if !strings.Contains(string(data), "trustmod module comparison") || !strings.Contains(string(data), "example.com/a") {
		t.Fatalf("expected compare markdown, got:\n%s", data)
	}
}

func TestExplicitMissingConfigFails(t *testing.T) {
	_, err := executeTestCommand(t, "--config", filepath.Join(t.TempDir(), "missing.yml"), "version")
	if err == nil {
		t.Fatalf("expected missing explicit config to fail")
	}
	if code := ExitCode(err); code != ExitConfig {
		t.Fatalf("expected config exit, got %d: %v", code, err)
	}
}

func TestExplicitMissingPolicyFails(t *testing.T) {
	_, err := executeTestCommand(t, "--policy", filepath.Join(t.TempDir(), "missing.yml"), "policy", "explain")
	if err == nil {
		t.Fatalf("expected missing explicit policy to fail")
	}
	if code := ExitCode(err); code != ExitConfig {
		t.Fatalf("expected config exit, got %d: %v", code, err)
	}
}

func TestExplicitMissingRulesFails(t *testing.T) {
	projectRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectRoot, "go.mod"), []byte("module example.com/app\n\ngo 1.23\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := executeTestCommand(t, "--cwd", projectRoot, "--rules", filepath.Join(projectRoot, "missing.yml"), "audit", "--offline")
	if err == nil {
		t.Fatalf("expected missing explicit rules to fail")
	}
	if code := ExitCode(err); code != ExitConfig {
		t.Fatalf("expected config exit, got %d: %v", code, err)
	}
}

func TestPolicyTestReturnsPolicyExitForFailingReport(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yml")
	policy := []byte(`version: 1
fail_on: [BLOCK, REVIEW]
`)
	if err := os.WriteFile(policyPath, policy, 0o600); err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(dir, "report.json")
	report := []byte(`{
  "schemaVersion": "trustmod.report.v1",
  "modules": [{
    "modulePath": "example.com/app",
    "selectedVersion": "v1.0.0",
    "direct": true,
    "findings": [{
      "id": "fnd_test",
      "code": "TM-CAP-001",
      "title": "Process execution capability detected",
      "severity": "medium",
      "verdictImpact": "REVIEW",
      "modulePath": "example.com/app",
      "moduleVersion": "v1.0.0"
    }]
  }]
}`)
	if err := os.WriteFile(reportPath, report, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := executeTestCommand(t, "--policy", policyPath, "policy", "test", reportPath)
	if err == nil {
		t.Fatalf("expected policy test to fail, got output:\n%s", out)
	}
	if code := ExitCode(err); code != ExitPolicyFailure {
		t.Fatalf("expected policy exit, got %d: %v\n%s", code, err, out)
	}
	if !strings.Contains(out, "exitCodeRecommendation: 1") {
		t.Fatalf("expected policy output to explain recommendation, got:\n%s", out)
	}
	out, err = executeTestCommand(t, "--policy", policyPath, "--fail-on", "BLOCK", "policy", "test", reportPath)
	if err != nil {
		t.Fatalf("expected --fail-on BLOCK override to allow review report, got %v\n%s", err, out)
	}
	if !strings.Contains(out, "exitCodeRecommendation: 0") {
		t.Fatalf("expected fail-on override in policy test output, got:\n%s", out)
	}
}

func TestInitWritesIntoCWDTarget(t *testing.T) {
	target := filepath.Join(t.TempDir(), "target")
	if _, err := executeTestCommand(t, "--cwd", target, "init"); err != nil {
		t.Fatalf("init failed: %v", err)
	}
	for _, path := range []string{
		filepath.Join(target, ".trustmod.yaml"),
		filepath.Join(target, ".trustmod", "policy.yml"),
		filepath.Join(target, ".trustmod", "baseline.yml"),
		filepath.Join(target, ".trustmod", "rules.yml"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected init to create %s: %v", path, err)
		}
	}
}

func TestImplicitPolicyDefaultUsesCWDProjectRootAndPolicyProfile(t *testing.T) {
	projectRoot := t.TempDir()
	writeProjectPolicy(t, projectRoot)
	subdir := filepath.Join(projectRoot, "cmd", "app")
	if err := os.MkdirAll(subdir, 0o750); err != nil {
		t.Fatal(err)
	}
	out, err := executeTestCommand(t, "--cwd", subdir, "policy", "explain")
	if err != nil {
		t.Fatalf("policy explain failed: %v", err)
	}
	if !strings.Contains(out, "loaded: true") {
		t.Fatalf("expected policy to load from project root, got:\n%s", out)
	}
	if !strings.Contains(out, "profile: strict") {
		t.Fatalf("expected policy file profile to win, got:\n%s", out)
	}
}

func TestBaselineListPrintsEntries(t *testing.T) {
	projectRoot := t.TempDir()
	if _, err := executeTestCommand(t, "--cwd", projectRoot, "baseline", "approve", "example.com/mod", "--version", "v1.0.0", "--code", "TM-CAP-001", "--reason", "reviewed", "--approved-by", "alice"); err != nil {
		t.Fatalf("baseline approve failed: %v", err)
	}
	out, err := executeTestCommand(t, "--cwd", projectRoot, "baseline", "list")
	if err != nil {
		t.Fatalf("baseline list failed: %v", err)
	}
	for _, want := range []string{"finding: module=example.com/mod", "version=v1.0.0", "code=TM-CAP-001", "approved_by=alice", "reason=reviewed"} {
		if !strings.Contains(out, want) {
			t.Fatalf("baseline list missing %q:\n%s", want, out)
		}
	}
}

func TestExplicitMissingBaselineFailsForAnalysisCommands(t *testing.T) {
	projectRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectRoot, "go.mod"), []byte("module example.com/app\n\ngo 1.23\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := executeTestCommand(t, "--cwd", projectRoot, "--baseline", filepath.Join(projectRoot, "missing.yml"), "audit", "--offline", "--format", "json")
	if err == nil {
		t.Fatalf("expected explicit missing baseline to fail")
	}
	if code := ExitCode(err); code != ExitConfig {
		t.Fatalf("expected config exit, got %d: %v", code, err)
	}
}

func TestImplicitBaselineDefaultUsesCWDProjectRoot(t *testing.T) {
	projectRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectRoot, "go.mod"), []byte("module example.com/app\n\ngo 1.23\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	subdir := filepath.Join(projectRoot, "cmd", "app")
	if err := os.MkdirAll(subdir, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := executeTestCommand(t, "--cwd", subdir, "baseline", "approve", "example.com/legacy", "--reason", "test"); err != nil {
		t.Fatalf("baseline approve failed: %v", err)
	}
	path := filepath.Join(projectRoot, ".trustmod", "baseline.yml")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected baseline at project root: %v", err)
	}
}

func executeTestCommand(t *testing.T, args ...string) (string, error) {
	t.Helper()
	for _, name := range []string{
		"TRUSTMOD_CONFIG",
		"TRUSTMOD_POLICY",
		"TRUSTMOD_BASELINE",
		"TRUSTMOD_RULES",
		"TRUSTMOD_CWD",
		"TRUSTMOD_PROFILE",
		"TRUSTMOD_FORMAT",
	} {
		t.Setenv(name, "")
	}
	var out bytes.Buffer
	cmd := NewRootCommand(BuildInfo{Version: "test", Commit: "test", Date: "test"})
	cmd.SetArgs(args)
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	err := cmd.Execute()
	return out.String(), err
}

func writeProjectPolicy(t *testing.T, projectRoot string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(projectRoot, "go.mod"), []byte("module example.com/app\n\ngo 1.23\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	policyDir := filepath.Join(projectRoot, ".trustmod")
	if err := os.MkdirAll(policyDir, 0o750); err != nil {
		t.Fatal(err)
	}
	policy := []byte(`version: 1
profile: strict
fail_on: [BLOCK]
profiles:
  strict:
    fail_on: [BLOCK, REVIEW]
`)
	if err := os.WriteFile(filepath.Join(policyDir, "policy.yml"), policy, 0o600); err != nil {
		t.Fatal(err)
	}
}
