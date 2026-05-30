package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	analyze "github.com/maksemen2/trustmod/internal/model"
	"github.com/maksemen2/trustmod/internal/provider"
)

func TestProviderChunksBatchRequestsAndMergesPartialResults(t *testing.T) {
	var hits atomic.Int32
	var maxQueries atomic.Int32
	var handlerErrors atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		var req batchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			handlerErrors.Add(1)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		n := int32(len(req.Queries))
		for {
			max := maxQueries.Load()
			if n <= max || maxQueries.CompareAndSwap(max, n) {
				break
			}
		}
		if len(req.Queries) > maxQueryBatchSize {
			handlerErrors.Add(1)
			http.Error(w, "batch too large", http.StatusBadRequest)
			return
		}
		for _, q := range req.Queries {
			if q.Package.Name == "example.com/fail" {
				http.Error(w, "bad batch", http.StatusBadRequest)
				return
			}
		}
		resp := batchResponse{Results: make([]queryResult, len(req.Queries))}
		for i, q := range req.Queries {
			if q.Package.Name == "example.com/vuln" {
				resp.Results[i].Vulns = []vulnerability{{ID: "GO-2026-0001", Summary: "test vulnerability"}}
			}
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	opts := analyze.Options{NoCache: true, Timeout: time.Second, Concurrency: 2}.WithDefaults()
	httpClient := provider.NewHTTPClient("osv", opts)
	httpClient.Client = srv.Client()
	p := &Provider{client: &Client{http: httpClient, endpoint: srv.URL}}

	modules := make([]analyze.ModuleReport, 0, maxQueryBatchSize+1)
	modules = append(modules, analyze.ModuleReport{ModulePath: "example.com/vuln", SelectedVersion: "v1.0.0"})
	for i := 1; i < maxQueryBatchSize; i++ {
		modules = append(modules, analyze.ModuleReport{ModulePath: "example.com/ok", SelectedVersion: "v1.0.0"})
	}
	modules = append(modules, analyze.ModuleReport{ModulePath: "example.com/fail", SelectedVersion: "v1.0.0"})

	res, err := p.Enrich(context.Background(), provider.Request{Modules: modules, Options: opts})
	if err != nil {
		t.Fatal(err)
	}
	if got := handlerErrors.Load(); got != 0 {
		t.Fatalf("handler errors = %d, want 0", got)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("requests = %d, want 2", got)
	}
	if got := maxQueries.Load(); got != maxQueryBatchSize {
		t.Fatalf("max queries per request = %d, want %d", got, maxQueryBatchSize)
	}
	if res.Status.Status != analyze.ProviderStatusUnavailable {
		t.Fatalf("status = %q, want %q", res.Status.Status, analyze.ProviderStatusUnavailable)
	}
	update := res.Modules["example.com/vuln"]
	if len(update.Findings) != 1 || update.Security == nil || update.Security.KnownVulnerabilities != 1 {
		t.Fatalf("successful chunk was not merged: %#v", update)
	}
}

func TestMergeBatchResponseUsesAdvisoryInFindingID(t *testing.T) {
	result := provider.Result{Modules: map[string]provider.ModuleUpdate{}}
	modules := []analyze.ModuleReport{{ModulePath: "example.com/vuln", SelectedVersion: "v1.0.0"}}
	resp := batchResponse{Results: []queryResult{{Vulns: []vulnerability{{ID: "GO-2026-0001"}, {ID: "GO-2026-0002"}}}}}
	mergeBatchResponse(&result, modules, resp)
	findings := result.Modules["example.com/vuln"].Findings
	if len(findings) != 2 {
		t.Fatalf("expected two findings, got %#v", findings)
	}
	if findings[0].ID == findings[1].ID {
		t.Fatalf("expected different advisory findings to have different IDs: %#v", findings)
	}
}
