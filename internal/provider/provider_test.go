package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	analyze "github.com/maksemen2/trustmod/internal/model"
)

func TestHTTPClientUsesOnlineReadThroughCache(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]string{"value": "ok"})
	}))
	defer srv.Close()

	opts := analyze.Options{CacheDir: t.TempDir(), CacheTTL: time.Hour}.WithDefaults()
	client := NewHTTPClient("test", opts)
	client.Client = srv.Client()

	var first map[string]string
	cached, status, err := client.DoJSON(context.Background(), http.MethodGet, srv.URL, nil, &first)
	if err != nil || cached || status != analyze.ProviderStatusOK || first["value"] != "ok" {
		t.Fatalf("first DoJSON cached=%v status=%q err=%v out=%v", cached, status, err, first)
	}
	var second map[string]string
	cached, status, err = client.DoJSON(context.Background(), http.MethodGet, srv.URL, nil, &second)
	if err != nil || !cached || status != analyze.ProviderStatusOK || second["value"] != "ok" {
		t.Fatalf("second DoJSON cached=%v status=%q err=%v out=%v", cached, status, err, second)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("server hits = %d, want 1", got)
	}
}

func TestHTTPClientCachesNotFoundAsNegativeResult(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		http.Error(w, "missing", http.StatusNotFound)
	}))
	defer srv.Close()

	opts := analyze.Options{CacheDir: t.TempDir(), CacheTTL: time.Hour}.WithDefaults()
	client := NewHTTPClient("test", opts)
	client.Client = srv.Client()

	var out map[string]string
	cached, status, err := client.DoJSON(context.Background(), http.MethodGet, srv.URL, nil, &out)
	if err == nil || cached || status != analyze.ProviderStatusUnavailable || !IsHTTPStatus(err, http.StatusNotFound) {
		t.Fatalf("first DoJSON cached=%v status=%q err=%v", cached, status, err)
	}
	cached, status, err = client.DoJSON(context.Background(), http.MethodGet, srv.URL, nil, &out)
	if err == nil || !cached || status != analyze.ProviderStatusUnavailable || !IsHTTPStatus(err, http.StatusNotFound) {
		t.Fatalf("second DoJSON cached=%v status=%q err=%v", cached, status, err)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("server hits = %d, want 1", got)
	}

	negativePath := filepath.Join(client.Cache.Dir, client.negativeCacheKey(http.MethodGet, srv.URL, nil)+".json")
	old := time.Now().Add(-negativeCacheTTL - time.Second)
	if chtimesErr := os.Chtimes(negativePath, old, old); chtimesErr != nil {
		t.Fatal(chtimesErr)
	}
	cached, status, err = client.DoJSON(context.Background(), http.MethodGet, srv.URL, nil, &out)
	if err == nil || cached || status != analyze.ProviderStatusUnavailable || !IsHTTPStatus(err, http.StatusNotFound) {
		t.Fatalf("expired negative cache DoJSON cached=%v status=%q err=%v", cached, status, err)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("server hits after negative cache expiry = %d, want 2", got)
	}
}

func TestHTTPClientDoesNotCacheRateLimitResponses(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) == 1 {
			http.Error(w, "rate limit", http.StatusTooManyRequests)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"value": "ok"})
	}))
	defer srv.Close()

	opts := analyze.Options{CacheDir: t.TempDir(), CacheTTL: time.Hour}.WithDefaults()
	client := NewHTTPClient("test", opts)
	client.Client = srv.Client()

	var out map[string]string
	cached, status, err := client.DoJSON(context.Background(), http.MethodGet, srv.URL, nil, &out)
	if err == nil || cached || status != analyze.ProviderStatusRateLimited {
		t.Fatalf("rate limited DoJSON cached=%v status=%q err=%v", cached, status, err)
	}
	cached, status, err = client.DoJSON(context.Background(), http.MethodGet, srv.URL, nil, &out)
	if err != nil || cached || status != analyze.ProviderStatusOK || out["value"] != "ok" {
		t.Fatalf("second DoJSON cached=%v status=%q err=%v out=%v", cached, status, err, out)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("server hits = %d, want 2", got)
	}
}

func TestHTTPClientSingleflightsConcurrentIdenticalRequests(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		time.Sleep(50 * time.Millisecond)
		_ = json.NewEncoder(w).Encode(map[string]string{"value": "ok"})
	}))
	defer srv.Close()

	opts := analyze.Options{CacheDir: t.TempDir(), CacheTTL: time.Hour}.WithDefaults()
	client := NewHTTPClient("test", opts)
	client.Client = srv.Client()

	const callers = 12
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(callers)
	for i := 0; i < callers; i++ {
		go func() {
			defer wg.Done()
			<-start
			var out map[string]string
			_, status, err := client.DoJSON(context.Background(), http.MethodGet, srv.URL, nil, &out)
			if err != nil || status != analyze.ProviderStatusOK || out["value"] != "ok" {
				t.Errorf("DoJSON status=%q err=%v out=%v", status, err, out)
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := hits.Load(); got != 1 {
		t.Fatalf("server hits = %d, want 1", got)
	}
}

func TestFinalizeSuccessStatusPreservesPartialFailure(t *testing.T) {
	res := &Result{
		Status:  analyze.ProviderStatus{Name: "test", Status: analyze.ProviderStatusOK},
		Modules: map[string]ModuleUpdate{},
	}
	MergeJobResult(res, JobResult{Status: analyze.ProviderStatusUnavailable, Err: errTestProviderFailure}, "")
	MergeJobResult(res, JobResult{Updates: []ModuleUpdate{{ModulePath: "example.com/mod"}}}, "")
	FinalizeSuccessStatus(res, 1)
	if res.Status.Status != analyze.ProviderStatusUnavailable {
		t.Fatalf("status = %q, want %q", res.Status.Status, analyze.ProviderStatusUnavailable)
	}
}

func TestFinalizeSuccessStatusPreservesOfflineCacheHit(t *testing.T) {
	res := &Result{
		Status:  analyze.ProviderStatus{Name: "test", Status: analyze.ProviderStatusOK},
		Modules: map[string]ModuleUpdate{},
	}
	ok := MergeJobResult(res, JobResult{
		Cached:  true,
		Status:  analyze.ProviderStatusOfflineCacheHit,
		Updates: []ModuleUpdate{{ModulePath: "example.com/mod"}},
	}, "")
	if !ok {
		t.Fatal("offline cache hit should count as a successful provider job")
	}
	FinalizeSuccessStatus(res, 1)
	if res.Status.Status != analyze.ProviderStatusOfflineCacheHit {
		t.Fatalf("status = %q, want %q", res.Status.Status, analyze.ProviderStatusOfflineCacheHit)
	}
	if !res.Status.Cached {
		t.Fatal("expected cached status to be preserved")
	}
}

var errTestProviderFailure = &HTTPStatusError{Code: http.StatusInternalServerError, Status: "500 Internal Server Error"}
