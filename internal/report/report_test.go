package report

import (
	"encoding/json"
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/maksemen2/trustmod/internal/findings"
	analyze "github.com/maksemen2/trustmod/internal/model"
)

func TestJSONAndSARIF(t *testing.T) {
	f := findings.New("TM-VER-005", "example.com/mod", "v0.1.0", "test")
	r := &analyze.ProjectReport{
		SchemaVersion: analyze.SchemaVersion,
		GeneratedAt:   time.Unix(0, 0).UTC(),
		Modules:       []analyze.ModuleReport{{ModulePath: "example.com/mod", SelectedVersion: "v0.1.0", Findings: []analyze.Finding{f}}},
		Findings:      []analyze.Finding{f},
		Verdict:       analyze.VerdictReview,
	}
	data, err := JSONProject(r)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if unmarshalErr := json.Unmarshal(data, &decoded); unmarshalErr != nil {
		t.Fatal(unmarshalErr)
	}
	sarif, err := SARIFProject(r)
	if err != nil {
		t.Fatal(err)
	}
	if unmarshalErr := json.Unmarshal(sarif, &decoded); unmarshalErr != nil {
		t.Fatal(unmarshalErr)
	}
}

func TestJSONProjectUsesEmptyArraysForPublicCollections(t *testing.T) {
	r := &analyze.ProjectReport{SchemaVersion: analyze.SchemaVersion, GeneratedAt: time.Unix(0, 0).UTC(), Verdict: analyze.VerdictAllow}
	data, err := JSONProject(r)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Providers       []any `json:"providers"`
		Modules         []any `json:"modules"`
		Findings        []any `json:"findings"`
		DependencyGraph struct {
			Nodes []any `json:"nodes"`
			Edges []any `json:"edges"`
		} `json:"dependencyGraph"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Providers == nil || decoded.Modules == nil || decoded.DependencyGraph.Nodes == nil || decoded.DependencyGraph.Edges == nil {
		t.Fatalf("expected empty arrays instead of nulls:\n%s", data)
	}
}

func TestJSONProjectRedactsLocalPaths(t *testing.T) {
	repo := t.TempDir()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if chdirErr := os.Chdir(repo); chdirErr != nil {
		t.Fatal(chdirErr)
	}
	t.Cleanup(func() {
		if restoreErr := os.Chdir(wd); restoreErr != nil {
			t.Errorf("restore working directory: %v", restoreErr)
		}
	})
	tempProject := filepath.Join(os.TempDir(), "trustmod-check-secret", "go.mod")
	r := &analyze.ProjectReport{
		SchemaVersion: analyze.SchemaVersion,
		GeneratedAt:   time.Unix(0, 0).UTC(),
		ProjectRoot:   filepath.Join(repo, "service"),
		GoEnvSummary: analyze.GoEnvSummary{
			GOMOD:      filepath.Join(repo, "service", "go.mod"),
			GOMODCACHE: filepath.Join(os.TempDir(), "gomodcache", "pkg", "mod"),
			GOPRIVATE:  []string{"corp.example.com/*"},
		},
		Policy:   analyze.PolicySummary{Path: filepath.Join(repo, ".trustmod", "policy.yml")},
		Baseline: analyze.BaselineSummary{Path: tempProject},
		Findings: []analyze.Finding{{
			Code:     "TM-GO-001",
			Title:    "go failed",
			Evidence: []string{"go list failed in " + tempProject},
		}},
		Verdict: analyze.VerdictReview,
	}
	data, err := JSONProject(r)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, leaked := range []string{repo, os.TempDir(), "corp.example.com"} {
		if strings.Contains(text, leaked) {
			t.Fatalf("JSON leaked %q:\n%s", leaked, text)
		}
	}
	var decoded struct {
		ProjectRoot  string `json:"projectRoot"`
		GoEnvSummary struct {
			GOMOD      string   `json:"GOMOD"`
			GOMODCACHE string   `json:"GOMODCACHE"`
			GOPRIVATE  []string `json:"GOPRIVATE"`
		} `json:"goEnvSummary"`
		Baseline struct {
			Path string `json:"path"`
		} `json:"baseline"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ProjectRoot != "service" || decoded.GoEnvSummary.GOMOD != "service/go.mod" {
		t.Fatalf("unexpected sanitized paths: %#v", decoded)
	}
	if decoded.GoEnvSummary.GOPRIVATE != nil {
		t.Fatalf("GOPRIVATE should be omitted/redacted: %#v", decoded.GoEnvSummary.GOPRIVATE)
	}
	if !strings.HasPrefix(decoded.Baseline.Path, "<temp>/") {
		t.Fatalf("expected temp baseline path to be redacted, got %q", decoded.Baseline.Path)
	}
}

func TestPathRedactorStringRedactsAliasPrefix(t *testing.T) {
	root := t.TempDir()
	canonicalDir := filepath.Join(root, "canonical-temp")
	rawDir := filepath.Join(root, "raw-temp")
	redactor := pathRedactor{
		temp: filepath.Clean(canonicalDir),
		prefixes: redactionPrefixes(
			redactionPrefix{prefix: canonicalDir, label: "<temp>"},
			redactionPrefix{prefix: rawDir, label: "<temp>"},
		),
	}
	got := redactor.string("go list failed in " + filepath.Join(rawDir, "secret", "go.mod"))
	if strings.Contains(got, canonicalDir) || strings.Contains(got, rawDir) {
		t.Fatalf("path alias leaked: %q", got)
	}
	if !strings.Contains(filepath.ToSlash(got), "<temp>/secret/go.mod") {
		t.Fatalf("unexpected redaction: %q", got)
	}
}

func TestSARIFUsesCapabilityEvidenceLocations(t *testing.T) {
	f := findings.New("TM-CAP-001", "example.com/mod", "(main)", "local-static-scan")
	r := &analyze.ProjectReport{
		SchemaVersion: analyze.SchemaVersion,
		GeneratedAt:   time.Unix(0, 0).UTC(),
		Modules: []analyze.ModuleReport{{
			ModulePath:      "example.com/mod",
			SelectedVersion: "(main)",
			Findings:        []analyze.Finding{f},
			Capabilities: []analyze.Capability{{
				Name:        "process.exec",
				FindingCode: "TM-CAP-001",
				Evidence:    []analyze.SourceLocation{{File: "main.go", Line: 12, Text: "exec.Command"}},
			}},
		}},
		Findings: []analyze.Finding{f},
		Verdict:  analyze.VerdictReview,
	}
	data, err := SARIFProject(r)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Runs []struct {
			Results []struct {
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	loc := decoded.Runs[0].Results[0].Locations[0].PhysicalLocation
	if loc.ArtifactLocation.URI != "main.go" || loc.Region.StartLine != 12 {
		t.Fatalf("unexpected SARIF location: %#v", loc)
	}
}

func TestSARIFUsesRepositoryRelativePathForCWDSubdir(t *testing.T) {
	repo := t.TempDir()
	backend := filepath.Join(repo, "backend")
	if err := os.MkdirAll(backend, 0o750); err != nil {
		t.Fatal(err)
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if chdirErr := os.Chdir(repo); chdirErr != nil {
		t.Fatal(chdirErr)
	}
	t.Cleanup(func() {
		if restoreErr := os.Chdir(wd); restoreErr != nil {
			t.Errorf("restore working directory: %v", restoreErr)
		}
	})

	f := findings.New("TM-MAL-002", "example.com/mod", "(main)", "local-source-rule")
	f.File = "main.go"
	f.Line = 7
	r := &analyze.ProjectReport{
		SchemaVersion: analyze.SchemaVersion,
		GeneratedAt:   time.Unix(0, 0).UTC(),
		ProjectRoot:   backend,
		Findings:      []analyze.Finding{f},
		Verdict:       analyze.VerdictReview,
	}
	data, err := SARIFProject(r)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Runs []struct {
			Results []struct {
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	loc := decoded.Runs[0].Results[0].Locations[0].PhysicalLocation
	if loc.ArtifactLocation.URI != "backend/main.go" || loc.Region.StartLine != 7 {
		t.Fatalf("unexpected SARIF location: %#v\n%s", loc, data)
	}
}

func TestJUnitMarksReviewFindingsAsSkipped(t *testing.T) {
	review := findings.New("TM-CAP-001", "example.com/review", "v1.0.0", "test")
	review.VerdictImpact = analyze.VerdictReview
	block := findings.New("TM-MAL-002", "example.com/block", "v1.0.0", "test")
	block.VerdictImpact = analyze.VerdictBlock
	r := &analyze.ProjectReport{Findings: []analyze.Finding{review, block}}

	data, err := JUnitProject(r)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Tests    int `xml:"tests,attr"`
		Failures int `xml:"failures,attr"`
		Skipped  int `xml:"skipped,attr"`
		Cases    []struct {
			Failure *struct{} `xml:"failure"`
			Skipped *struct{} `xml:"skipped"`
		} `xml:"testcase"`
	}
	if err := xml.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Tests != 2 || decoded.Failures != 1 || decoded.Skipped != 1 {
		t.Fatalf("unexpected JUnit counters: tests=%d failures=%d skipped=%d\n%s", decoded.Tests, decoded.Failures, decoded.Skipped, data)
	}
	if decoded.Cases[0].Failure != nil || decoded.Cases[0].Skipped == nil {
		t.Fatalf("review finding should be skipped, not failed:\n%s", data)
	}
	if decoded.Cases[1].Failure == nil || decoded.Cases[1].Skipped != nil {
		t.Fatalf("block finding should be failed:\n%s", data)
	}
}

func TestSARIFIncludesCustomFindingRules(t *testing.T) {
	f := analyze.Finding{
		ID:            "fnd_custom",
		Code:          "TM-CUSTOM-TELEGRAM",
		Title:         "Telegram API access",
		Description:   "The dependency contains a literal Telegram API endpoint.",
		Category:      "custom",
		Severity:      analyze.SeverityMedium,
		Confidence:    analyze.ConfidenceHigh,
		VerdictImpact: analyze.VerdictReview,
		ModulePath:    "example.com/mod",
		ModuleVersion: "(main)",
		Source:        "custom-source-rule",
	}
	r := &analyze.ProjectReport{
		SchemaVersion: analyze.SchemaVersion,
		GeneratedAt:   time.Unix(0, 0).UTC(),
		Findings:      []analyze.Finding{f},
		Verdict:       analyze.VerdictReview,
	}
	data, err := SARIFProject(r)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, rule := range decoded.Runs[0].Tool.Driver.Rules {
		if rule.ID == "TM-CUSTOM-TELEGRAM" {
			return
		}
	}
	t.Fatalf("custom rule missing from SARIF:\n%s", data)
}

func TestMarkdownLocationDoesNotDuplicateURLLineAnchor(t *testing.T) {
	got := markdownLocation("https://github.com/acme/mod/blob/v1.0.0/main.go#L15", 15)
	if strings.Contains(got, "#L15:15") {
		t.Fatalf("line number was duplicated in markdown label: %s", got)
	}
}
