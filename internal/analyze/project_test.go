package analyze

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/maksemen2/trustmod/internal/githubrepo"
)

func TestMergeFindingsDeduplicatesSharedAdvisory(t *testing.T) {
	first := Finding{
		Code:          "TM-SEC-002",
		ModulePath:    "example.com/mod",
		ModuleVersion: "v1.0.0",
		Source:        "osv",
		Evidence:      []string{"OSV advisory: GHSA-1"},
		References:    []string{"GHSA-1"},
	}
	second := Finding{
		Code:          "TM-SEC-002",
		ModulePath:    "example.com/mod",
		ModuleVersion: "v1.0.0",
		Source:        "deps.dev",
		Evidence:      []string{"deps.dev advisory: GHSA-1"},
		References:    []string{"GHSA-1"},
	}
	got := mergeFindings([]Finding{first}, second)
	if len(got) != 1 {
		t.Fatalf("expected one merged finding, got %d", len(got))
	}
	if len(got[0].Evidence) != 2 {
		t.Fatalf("expected merged evidence from both providers, got %v", got[0].Evidence)
	}
}

func TestAttachCapabilitySourceURL(t *testing.T) {
	m := ModuleReport{
		ModulePath:      "github.com/go-chi/chi/v5",
		SelectedVersion: "v5.2.3",
		Repository:      "https://github.com/go-chi/chi",
		SourceHost:      "github.com",
		Direct:          true,
		Capabilities: []Capability{{
			Name: "env.read",
			Evidence: []SourceLocation{{
				File: "middleware/request_id.go",
				Line: 46,
				Text: "os.Getenv",
			}},
		}},
	}
	attachCapabilitySourceURL(&m)
	got := m.Capabilities[0].Evidence[0].URL
	want := "https://github.com/go-chi/chi/blob/v5.2.3/middleware/request_id.go#L46"
	if got != want {
		t.Fatalf("URL = %q, want %q", got, want)
	}
}

func TestAttachCapabilitySourceURLSkipsPrivateModules(t *testing.T) {
	m := ModuleReport{
		ModulePath:      "github.com/acme/private",
		SelectedVersion: "v1.0.0",
		Private:         true,
		Capabilities: []Capability{{
			Name:     "fs.write",
			Evidence: []SourceLocation{{File: "secret.go", Line: 1}},
		}},
	}
	attachCapabilitySourceURL(&m)
	if got := m.Capabilities[0].Evidence[0].URL; got != "" {
		t.Fatalf("expected no URL for private module, got %q", got)
	}
}

func TestApplyGraphFootprintsCountsReachableModulesWithCycle(t *testing.T) {
	mods := []ModuleReport{
		{ModulePath: "example.com/app"},
		{ModulePath: "example.com/a"},
		{ModulePath: "example.com/b"},
		{ModulePath: "example.com/c"},
	}
	graph := DependencyGraph{Edges: []GraphEdge{
		{From: "example.com/app", To: "example.com/a"},
		{From: "example.com/app", To: "example.com/b"},
		{From: "example.com/a", To: "example.com/c"},
		{From: "example.com/c", To: "example.com/a"},
		{From: "example.com/b", To: "go"},
	}}
	applyGraphFootprints(mods, graph)
	if got := mods[0].DependencyFootprint.DirectModules; got != 2 {
		t.Fatalf("app direct modules = %d, want 2", got)
	}
	if got := mods[0].DependencyFootprint.TransitiveModules; got != 1 {
		t.Fatalf("app transitive modules = %d, want 1", got)
	}
	if got := mods[1].DependencyFootprint.DirectModules; got != 1 {
		t.Fatalf("a direct modules = %d, want 1", got)
	}
	if got := mods[1].DependencyFootprint.TransitiveModules; got != 0 {
		t.Fatalf("a transitive modules = %d, want 0", got)
	}
}

func TestGitHubRefForPseudoVersionUsesCommit(t *testing.T) {
	got, ok := githubrepo.RefForVersion("v0.0.0-20200622213623-75b288015ac9")
	if !ok || got != "75b288015ac9" {
		t.Fatalf("ref = %q, %v", got, ok)
	}
}

func TestScanExplicitCheckTargetScansModuleDir(t *testing.T) {
	dir := t.TempDir()
	src := `package client

import "net/http"

const apiBase = "https://api.example.com"

func Fetch() {
	_, _ = http.Get(apiBase + "/v1")
}
`
	if err := os.WriteFile(filepath.Join(dir, "client.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := NewAnalyzer(Options{})
	if err != nil {
		t.Fatal(err)
	}
	report := &ProjectReport{Modules: []ModuleReport{{
		ModulePath:      "example.com/client",
		SelectedVersion: "v1.0.0",
		LocalDir:        dir,
	}}}
	a.scanExplicitCheckTarget(context.Background(), report, "example.com/client")

	m := report.Modules[0]
	var netClient *Capability
	for i := range m.Capabilities {
		if m.Capabilities[i].Name == "net.client" {
			netClient = &m.Capabilities[i]
			break
		}
	}
	if netClient == nil {
		t.Fatalf("missing net.client capability: %#v", m.Capabilities)
	}
	if len(netClient.Domains) != 1 || netClient.Domains[0] != "api.example.com" {
		t.Fatalf("domains = %#v, want api.example.com", netClient.Domains)
	}
	for _, f := range m.Findings {
		if f.Code == "TM-CAP-003" && f.Direct {
			return
		}
	}
	t.Fatalf("missing direct TM-CAP-003 finding: %#v", m.Findings)
}

func TestScanExplicitCheckTargetIncludesSourceRules(t *testing.T) {
	dir := t.TempDir()
	src := `package client

import (
	"encoding/base64"
	"os/exec"
)

func Run() {
	payload, _ := base64.StdEncoding.DecodeString("ZWNobyBoaQ==")
	_ = exec.Command("sh", "-c", string(payload)).Run()
}
`
	if err := os.WriteFile(filepath.Join(dir, "client.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := NewAnalyzer(Options{})
	if err != nil {
		t.Fatal(err)
	}
	report := &ProjectReport{Modules: []ModuleReport{{
		ModulePath:      "example.com/client",
		SelectedVersion: "v1.0.0",
		LocalDir:        dir,
	}}}
	a.scanExplicitCheckTarget(context.Background(), report, "example.com/client")

	m := report.Modules[0]
	for i := range m.Findings {
		if m.Findings[i].Code == "TM-MAL-001" && m.Findings[i].Direct {
			return
		}
	}
	t.Fatalf("missing direct TM-MAL-001 finding: %#v", m.Findings)
}

func TestScanExplicitCheckTargetIncludesCustomSourceRules(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yml")
	if err := os.WriteFile(rulesPath, []byte(`version: 1
rules:
  - id: org-telegram-api
    code: TM-CUSTOM-TELEGRAM
    title: Telegram API access
    verdict: REVIEW
    match:
      domains:
        - telegram.org
`), 0o600); err != nil {
		t.Fatal(err)
	}
	src := `package client

const defaultBotAPIServer = "https://api.telegram.org"
`
	if err := os.WriteFile(filepath.Join(dir, "client.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := NewAnalyzer(Options{CustomRulesPath: rulesPath})
	if err != nil {
		t.Fatal(err)
	}
	report := &ProjectReport{Modules: []ModuleReport{{
		ModulePath:      "example.com/client",
		SelectedVersion: "v1.0.0",
		LocalDir:        dir,
	}}}
	a.scanExplicitCheckTarget(context.Background(), report, "example.com/client")

	m := report.Modules[0]
	for i := range m.Findings {
		if m.Findings[i].Code == "TM-CUSTOM-TELEGRAM" && m.Findings[i].Title == "Telegram API access" {
			return
		}
	}
	t.Fatalf("missing custom source rule finding: %#v", m.Findings)
}
