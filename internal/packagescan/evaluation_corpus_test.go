package packagescan

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"
)

func TestEvaluationCorpusExpectations(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Join(filepath.Dir(file), "..", "..", "examples", "evaluation")
	cases := []struct {
		name      string
		path      string
		wantCodes []string
		noMalware bool
	}{
		{
			name:      "benign-http-client",
			path:      filepath.Join(root, "benign", "http-client"),
			wantCodes: []string{"TM-CAP-003"},
			noMalware: true,
		},
		{
			name:      "suspicious-rare-domain",
			path:      filepath.Join(root, "suspicious", "rare-domain"),
			wantCodes: []string{"TM-CAP-003", "TM-MAL-005"},
		},
		{
			name:      "suspicious-telegram-api",
			path:      filepath.Join(root, "suspicious", "telegram-api"),
			wantCodes: []string{"TM-CAP-003"},
			noMalware: true,
		},
		{
			name:      "malicious-download-exec",
			path:      filepath.Join(root, "malicious", "download-exec"),
			wantCodes: []string{"TM-CAP-001", "TM-CAP-002", "TM-CAP-003", "TM-MAL-002"},
		},
		{
			name:      "malicious-exfiltrate-secret",
			path:      filepath.Join(root, "malicious", "exfiltrate-secret"),
			wantCodes: []string{"TM-CAP-003", "TM-MAL-003"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := ScanModule(context.Background(), "example.com/"+tc.name, "v0.0.0", tc.path, true)
			if err != nil {
				t.Fatal(err)
			}
			codes := findingCodes(res.Findings)
			for _, code := range tc.wantCodes {
				if !codes[code] {
					t.Fatalf("missing %s from findings: %#v", code, res.Findings)
				}
			}
			if tc.noMalware {
				for code := range codes {
					if len(code) >= len("TM-MAL-") && code[:len("TM-MAL-")] == "TM-MAL-" {
						t.Fatalf("unexpected malware finding %s: %#v", code, res.Findings)
					}
				}
			}
		})
	}
}

func TestEvaluationCorpusCustomRuleExample(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Join(filepath.Dir(file), "..", "..")
	rules, err := LoadSourceRules(filepath.Join(repoRoot, "examples", "rules", "telegram-domain.yml"))
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(repoRoot, "examples", "evaluation", "suspicious", "telegram-api")
	res, err := ScanModuleWithOptions(context.Background(), "example.com/suspicious-telegram-api", "v0.0.0", target, true, ScanOptions{AdditionalSourceRules: rules})
	if err != nil {
		t.Fatal(err)
	}
	codes := findingCodes(res.Findings)
	if !codes["TM-CUSTOM-TELEGRAM"] {
		t.Fatalf("missing custom telegram finding: %#v", res.Findings)
	}
}
