package scorecard

import (
	"context"
	"testing"

	"github.com/maksemen2/trustmod/internal/githubrepo"
	analyze "github.com/maksemen2/trustmod/internal/model"
	"github.com/maksemen2/trustmod/internal/provider"
)

func TestRepoURIForModuleStripsGoMajorSuffix(t *testing.T) {
	got, ok := githubrepo.URI("github.com/go-chi/chi/v5")
	if !ok {
		t.Fatalf("expected github module to be supported")
	}
	if got != "github.com/go-chi/chi" {
		t.Fatalf("githubrepo.URI() = %q", got)
	}
}

func TestRepoURIForModuleRejectsNonGitHub(t *testing.T) {
	if got, ok := githubrepo.URI("golang.org/x/net"); ok || got != "" {
		t.Fatalf("expected non-github module to be skipped, got %q", got)
	}
}

func TestMaintainedFindingRequiresLowOverallScore(t *testing.T) {
	if shouldEmitMaintainedFinding(5.8, "Maintained", 0) {
		t.Fatalf("stable library with non-low aggregate score should not get maintained finding")
	}
	if !shouldEmitMaintainedFinding(4.9, "Maintained", 0) {
		t.Fatalf("low aggregate score plus low maintained check should emit finding")
	}
}

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
