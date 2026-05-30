package github

import (
	"context"
	"strings"
	"testing"
	"time"

	analyze "github.com/maksemen2/trustmod/internal/model"
	"github.com/maksemen2/trustmod/internal/provider"
)

func TestProviderReportsUnsupportedHostInsteadOfDisabled(t *testing.T) {
	p := &Provider{}
	res, err := p.Enrich(context.Background(), provider.Request{
		Modules: []analyze.ModuleReport{{ModulePath: "golang.org/x/crypto", SelectedVersion: "v0.1.0"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status.Status != analyze.ProviderStatusSkippedUnsupportedHost {
		t.Fatalf("status = %q, want %q", res.Status.Status, analyze.ProviderStatusSkippedUnsupportedHost)
	}
	if !res.Status.Enabled {
		t.Fatalf("unsupported host should be enabled-but-skipped, not disabled")
	}
}

func TestArchivedEvidenceIncludesArchiveDateAndAge(t *testing.T) {
	archivedAt := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	now := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)

	got := archivedEvidence("https://github.com/example/archived", &archivedAt, now, "")

	for _, want := range []string{"2026-05-01T12:00:00Z", "(23 days ago)", "https://github.com/example/archived"} {
		if !strings.Contains(got, want) {
			t.Fatalf("archivedEvidence() = %q, want it to contain %q", got, want)
		}
	}
}

func TestArchivedEvidenceExplainsMissingArchiveDate(t *testing.T) {
	got := archivedEvidence("https://github.com/example/archived", nil, time.Time{}, "no GitHub token configured")

	if !strings.Contains(got, "archive date unavailable") {
		t.Fatalf("archivedEvidence() = %q, want archive date unavailable note", got)
	}
	if !strings.Contains(got, "no GitHub token configured") {
		t.Fatalf("archivedEvidence() = %q, want missing date reason", got)
	}
}
