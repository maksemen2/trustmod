package report

import (
	"bytes"
	"strings"
	"testing"

	analyze "github.com/maksemen2/trustmod/internal/model"
)

func TestSourceLocationLinkPrefersWebURL(t *testing.T) {
	loc := analyze.SourceLocation{
		File:      "x.go",
		Line:      7,
		URL:       "https://github.com/acme/mod/blob/v1.0.0/x.go#L7",
		LocalPath: `C:\Users\me\go\pkg\mod\acme\mod\x.go`,
	}
	if got := sourceLocationLink(loc); got != loc.URL {
		t.Fatalf("sourceLocationLink = %q, want %q", got, loc.URL)
	}
}

func TestVSCodeURI(t *testing.T) {
	loc := analyze.SourceLocation{LocalPath: "dir with spaces/file.go", Line: 12}
	got := vscodeURI(loc)
	if !strings.HasPrefix(got, "vscode://file/") {
		t.Fatalf("expected vscode URI, got %q", got)
	}
	if !strings.Contains(got, "dir%20with%20spaces") {
		t.Fatalf("expected escaped path, got %q", got)
	}
	if !strings.HasSuffix(got, ":12") {
		t.Fatalf("expected line suffix, got %q", got)
	}
}

func TestPrintWhyShowsArchivedRepositoryEvidenceInline(t *testing.T) {
	var buf bytes.Buffer
	printWhy(&buf, []analyze.Finding{{
		Code:          "TM-MNT-001",
		Title:         "Repository archived",
		VerdictImpact: analyze.VerdictReview,
		ModulePath:    "github.com/example/archived",
		Evidence:      []string{"GitHub repository archived at 2022-05-21T03:31:02Z (1464 days ago): https://github.com/example/archived"},
	}}, colors{})

	got := buf.String()
	want := "TM-MNT-001  Repository archived (github.com/example/archived) at 2022-05-21T03:31:02Z (1464 days ago)"
	if !strings.Contains(got, want) {
		t.Fatalf("printWhy() did not include inline archive detail %q:\n%s", want, got)
	}
	if strings.Contains(got, "\n      GitHub repository archived") {
		t.Fatalf("printWhy() should not render bulky archive evidence on a second line:\n%s", got)
	}
}

func TestPrintWhyShowsNetworkDomainsInline(t *testing.T) {
	var buf bytes.Buffer
	printWhy(&buf, []analyze.Finding{{
		Code:          "TM-CAP-003",
		Title:         "Network capability detected",
		VerdictImpact: analyze.VerdictAllow,
		ModulePath:    "github.com/example/client",
		Evidence:      []string{"client.go:12 http.Get", "network domains: api.example.com, cdn.example.com"},
	}}, colors{})

	got := buf.String()
	want := "TM-CAP-003  Network capability detected (github.com/example/client) domains: api.example.com, cdn.example.com"
	if !strings.Contains(got, want) {
		t.Fatalf("printWhy() did not include network domains %q:\n%s", want, got)
	}
}

func TestCapabilityDomainSummaryLimitsOutput(t *testing.T) {
	got := capabilityDomainSummary(analyze.Capability{
		Domains:     []string{"a.example.com", "b.example.com", "c.example.com", "d.example.com", "e.example.com"},
		DomainCount: 8,
	})
	want := "a.example.com, b.example.com, c.example.com, d.example.com, e.example.com, +3 more"
	if got != want {
		t.Fatalf("capabilityDomainSummary() = %q, want %q", got, want)
	}
}
