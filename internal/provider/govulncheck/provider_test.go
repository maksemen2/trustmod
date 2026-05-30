package govulncheck

import (
	"context"
	"errors"
	"testing"
	"time"

	analyze "github.com/maksemen2/trustmod/internal/model"
	"github.com/maksemen2/trustmod/internal/provider"
)

type fakeRunner struct {
	out    []byte
	status string
	err    error
}

func (r fakeRunner) Run(context.Context, string) ([]byte, string, error) {
	return r.out, r.status, r.err
}

func TestProviderDoesNotTurnOSVMetadataIntoReachableFinding(t *testing.T) {
	p := &Provider{runner: fakeRunner{
		out:    []byte(`{"osv":{"id":"GO-2024-0001","summary":"metadata only","affected":[{"package":{"name":"example.com/mod"}}]}}` + "\n"),
		status: analyze.ProviderStatusOK,
	}}
	res, err := p.Enrich(context.Background(), provider.Request{ProjectRoot: ".", Modules: []analyze.ModuleReport{{ModulePath: "example.com/mod", SelectedVersion: "v1.0.0"}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 || len(res.Modules) != 0 {
		t.Fatalf("expected no reachable finding from OSV metadata only, got %#v %#v", res.Findings, res.Modules)
	}
}

func TestProviderMapsFindingTraceToReachableFinding(t *testing.T) {
	p := &Provider{runner: fakeRunner{
		out: []byte(`{"osv":{"id":"GO-2024-0001","summary":"reachable","affected":[{"package":{"name":"example.com/mod"}}]}}` + "\n" +
			`{"finding":{"osv":"GO-2024-0001","trace":[{"module":"example.com/mod","version":"v1.0.0","package":"example.com/mod/pkg","function":"Bad"}]}}` + "\n"),
		status: analyze.ProviderStatusOK,
	}}
	res, err := p.Enrich(context.Background(), provider.Request{ProjectRoot: ".", Modules: []analyze.ModuleReport{{ModulePath: "example.com/mod", SelectedVersion: "v1.0.0"}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected one finding, got %#v", res.Findings)
	}
	if res.Findings[0].Code != "TM-SEC-001" || res.Findings[0].Reachable == nil || !*res.Findings[0].Reachable {
		t.Fatalf("expected reachable TM-SEC-001, got %#v", res.Findings[0])
	}
	update := res.Modules["example.com/mod"]
	if update.Security == nil || update.Security.ReachableFindings != 1 || update.Security.KnownVulnerabilities != 1 {
		t.Fatalf("unexpected security update: %#v", update.Security)
	}
}

func TestProviderProcessesFindingsWhenGovulncheckExitsNonZero(t *testing.T) {
	p := &Provider{runner: fakeRunner{
		out:    []byte(`{"finding":{"osv":"GO-2024-0001","trace":[{"module":"example.com/mod","version":"v1.0.0","package":"example.com/mod/pkg","function":"Bad"}]}}` + "\n"),
		status: analyze.ProviderStatusError,
		err:    errors.New("exit status 3"),
	}}
	res, err := p.Enrich(context.Background(), provider.Request{ProjectRoot: ".", Modules: []analyze.ModuleReport{{ModulePath: "example.com/mod", SelectedVersion: "v1.0.0"}}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status.Status != analyze.ProviderStatusOK || len(res.Findings) != 1 {
		t.Fatalf("expected findings from non-zero govulncheck output to be processed, status=%#v findings=%#v", res.Status, res.Findings)
	}
}

func TestGovulncheckTimeoutUsesDedicatedOption(t *testing.T) {
	got := govulncheckTimeout(analyze.Options{Timeout: time.Second, GovulncheckTimeout: 2 * time.Minute})
	if got != 2*time.Minute {
		t.Fatalf("timeout = %s, want 2m", got)
	}
}

func TestGovulncheckTimeoutDefaultsIndependently(t *testing.T) {
	got := govulncheckTimeout(analyze.Options{Timeout: time.Second})
	if got != 2*time.Minute {
		t.Fatalf("timeout = %s, want 2m", got)
	}
}
