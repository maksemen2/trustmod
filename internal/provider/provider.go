package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/maksemen2/trustmod/internal/cache"
	analyze "github.com/maksemen2/trustmod/internal/model"
)

type Request struct {
	ProjectRoot string
	Modules     []analyze.ModuleReport
	Options     analyze.Options
}

type ModuleUpdate struct {
	ModulePath  string
	Version     string
	Licenses    []string
	Repository  string
	SourceHost  string
	Maintenance *analyze.MaintenanceSignals
	Security    *analyze.SecuritySignals
	Identity    *analyze.IdentitySignals
	Adoption    *analyze.AdoptionSignals
	Findings    []analyze.Finding
	Annotations map[string]interface{}
}

type Result struct {
	Status   analyze.ProviderStatus
	Modules  map[string]ModuleUpdate
	Findings []analyze.Finding
}

type JobResult struct {
	Cached  bool
	Status  string
	Err     error
	Updates []ModuleUpdate
}

type Provider interface {
	Name() string
	Enrich(ctx context.Context, req Request) (Result, error)
}

type HTTPClient struct {
	Name       string
	BaseURL    string
	CacheScope string
	UserAgent  string
	Timeout    time.Duration
	Offline    bool
	Cache      *cache.Store
	Client     *http.Client
	Gate       chan struct{}
}

const negativeCacheTTL = 5 * time.Minute

var httpFlights = newHTTPFlightGroup()

type HTTPStatusError struct {
	Code    int
	Status  string
	Headers http.Header
	Body    string
}

func (e *HTTPStatusError) Error() string {
	if e == nil {
		return ""
	}
	if e.Body == "" {
		return e.Status
	}
	return e.Status + ": " + summarizeBody(e.Body)
}

func NewHTTPClient(name string, opts analyze.Options) *HTTPClient {
	var store *cache.Store
	if !opts.NoCache {
		store, _ = cache.New(opts.CacheDir, opts.CacheTTL)
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	return &HTTPClient{
		Name:      name,
		UserAgent: fmt.Sprintf("trustmod/%s", opts.TrustmodVersion),
		Timeout:   timeout,
		Offline:   opts.Offline,
		Cache:     store,
		Client:    &http.Client{Timeout: timeout},
		Gate:      opts.HTTPGate,
	}
}

func Concurrency(opts analyze.Options) int {
	if opts.Concurrency <= 0 {
		return 8
	}
	return opts.Concurrency
}

func MergeJobResult(res *Result, job JobResult, rateLimitHint string) bool {
	res.Status.Cached = res.Status.Cached || job.Cached
	if job.Err != nil {
		if shouldReplaceProviderStatus(res.Status.Status, job.Status) {
			res.Status.Status = job.Status
			if job.Status == analyze.ProviderStatusRateLimited {
				res.Status.ErrorSummary = RateLimitSummary(job.Err) + rateLimitHint
			} else {
				res.Status.ErrorSummary = job.Err.Error()
			}
		}
		return false
	}
	if job.Status == analyze.ProviderStatusOfflineCacheHit && analyze.ProviderStatusIsSuccess(res.Status.Status) {
		res.Status.Status = analyze.ProviderStatusOfflineCacheHit
	}
	for i := range job.Updates {
		update := job.Updates[i]
		res.Modules[update.ModulePath] = update
	}
	return true
}

func FinalizeSuccessStatus(res *Result, successes int) {
	if successes > 0 && (res.Status.Status == "" || res.Status.Status == analyze.ProviderStatusOK) {
		res.Status.Status = analyze.ProviderStatusOK
		res.Status.ErrorSummary = ""
	}
}

func (c *HTTPClient) DoJSON(ctx context.Context, method, url string, body any, out any) (cached bool, status string, err error) {
	var bodyBytes []byte
	if body != nil {
		bodyBytes, err = json.Marshal(body)
		if err != nil {
			return false, analyze.ProviderStatusError, err
		}
	}
	key := c.cacheKey(method, url, bodyBytes)
	negativeKey := c.negativeCacheKey(method, url, bodyBytes)
	if c.Cache != nil {
		if data, ok, err := c.Cache.Get(key); err == nil && ok {
			if err := json.Unmarshal(data, out); err != nil {
				return true, analyze.ProviderStatusError, err
			}
			if c.Offline {
				return true, analyze.ProviderStatusOfflineCacheHit, nil
			}
			return true, analyze.ProviderStatusOK, nil
		}
		if neg, ok, err := c.cachedHTTPError(negativeKey); err == nil && ok {
			return true, analyze.ProviderStatusUnavailable, neg
		}
	}
	if c.Offline {
		return false, analyze.ProviderStatusOfflineCacheMiss, fmt.Errorf("%s offline cache miss", c.Name)
	}
	fetched := httpFlights.Do(key, func() httpFetchResult {
		return c.fetchJSONBytes(ctx, method, url, bodyBytes, negativeKey)
	})
	if fetched.err != nil {
		return false, fetched.status, fetched.err
	}
	if err := json.Unmarshal(fetched.data, out); err != nil {
		return false, analyze.ProviderStatusError, err
	}
	if c.Cache != nil && fetched.status == analyze.ProviderStatusOK {
		_ = c.Cache.Set(key, fetched.data)
	}
	return fetched.cached, fetched.status, nil
}

type httpFetchResult struct {
	data   []byte
	status string
	err    error
	cached bool
}

type httpFlightGroup struct {
	mu    sync.Mutex
	calls map[string]*httpFlightCall
}

type httpFlightCall struct {
	wg  sync.WaitGroup
	res httpFetchResult
}

func newHTTPFlightGroup() *httpFlightGroup {
	return &httpFlightGroup{calls: map[string]*httpFlightCall{}}
}

func (g *httpFlightGroup) Do(key string, fn func() httpFetchResult) httpFetchResult {
	g.mu.Lock()
	if call := g.calls[key]; call != nil {
		g.mu.Unlock()
		call.wg.Wait()
		return call.res
	}
	call := &httpFlightCall{}
	call.wg.Add(1)
	g.calls[key] = call
	g.mu.Unlock()

	call.res = fn()
	call.wg.Done()

	g.mu.Lock()
	delete(g.calls, key)
	g.mu.Unlock()
	return call.res
}

func (c *HTTPClient) fetchJSONBytes(ctx context.Context, method, url string, bodyBytes []byte, negativeKey string) httpFetchResult {
	var lastErr error
	lastStatus := analyze.ProviderStatusUnavailable
	for attempt := 0; attempt < 3; attempt++ {
		reqCtx, cancel := context.WithTimeout(ctx, c.Timeout)
		req, err := http.NewRequestWithContext(reqCtx, method, url, bytes.NewReader(bodyBytes))
		if err != nil {
			cancel()
			return httpFetchResult{status: analyze.ProviderStatusError, err: err}
		}
		req.Header.Set("User-Agent", c.UserAgent)
		req.Header.Set("Accept", "application/json")
		if bodyBytes != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		release, err := c.acquire(ctx)
		if err != nil {
			cancel()
			return httpFetchResult{status: analyze.ProviderStatusCancelled, err: err}
		}
		resp, err := c.Client.Do(req)
		release()
		if err != nil {
			cancel()
			if ctx.Err() != nil {
				return httpFetchResult{status: analyze.ProviderStatusCancelled, err: ctx.Err()}
			}
			if requestTimedOut(err) {
				lastStatus = analyze.ProviderStatusTimeout
			} else {
				lastStatus = analyze.ProviderStatusUnavailable
			}
			lastErr = err
			if !sleepOrDone(ctx, retryDelay(attempt)) {
				return httpFetchResult{status: analyze.ProviderStatusCancelled, err: ctx.Err()}
			}
			continue
		}
		data, readErr := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		_ = resp.Body.Close()
		cancel()
		if readErr != nil {
			return httpFetchResult{status: analyze.ProviderStatusError, err: readErr}
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			return httpFetchResult{status: analyze.ProviderStatusRateLimited, err: &HTTPStatusError{Code: resp.StatusCode, Status: resp.Status, Headers: resp.Header.Clone(), Body: string(data)}}
		}
		if resp.StatusCode >= 500 {
			lastStatus = analyze.ProviderStatusUnavailable
			lastErr = fmt.Errorf("%s returned %s", c.Name, resp.Status)
			if !sleepOrDone(ctx, retryDelay(attempt)) {
				return httpFetchResult{status: analyze.ProviderStatusCancelled, err: ctx.Err()}
			}
			continue
		}
		if resp.StatusCode == http.StatusForbidden && isRateLimitResponse(resp.Header, data) {
			return httpFetchResult{status: analyze.ProviderStatusRateLimited, err: &HTTPStatusError{Code: resp.StatusCode, Status: resp.Status, Headers: resp.Header.Clone(), Body: string(data)}}
		}
		if resp.StatusCode >= 400 {
			statusErr := &HTTPStatusError{Code: resp.StatusCode, Status: resp.Status, Headers: resp.Header.Clone(), Body: string(data)}
			if resp.StatusCode == http.StatusNotFound && c.Cache != nil {
				_ = c.Cache.Set(negativeKey, mustMarshalCachedHTTPError(statusErr))
			}
			return httpFetchResult{status: analyze.ProviderStatusUnavailable, err: statusErr}
		}
		return httpFetchResult{data: data, status: analyze.ProviderStatusOK}
	}
	if c.Cache != nil {
		if data, ok, err := c.Cache.Get(c.cacheKey(method, url, bodyBytes)); err == nil && ok {
			return httpFetchResult{data: data, status: analyze.ProviderStatusOfflineCacheHit, cached: true}
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("%s unavailable", c.Name)
	}
	return httpFetchResult{status: lastStatus, err: lastErr}
}

type cachedHTTPStatusError struct {
	Code    int         `json:"code"`
	Status  string      `json:"status"`
	Headers http.Header `json:"headers,omitempty"`
	Body    string      `json:"body,omitempty"`
}

func (c *HTTPClient) cacheKey(method, url string, body []byte) string {
	return cache.Key(c.Name, c.cacheScope(), method, url, string(body))
}

func (c *HTTPClient) negativeCacheKey(method, url string, body []byte) string {
	return cache.Key(c.Name, c.cacheScope(), "negative", method, url, string(body))
}

func (c *HTTPClient) cacheScope() string {
	if strings.TrimSpace(c.CacheScope) != "" {
		return strings.TrimSpace(c.CacheScope)
	}
	return "public"
}

func (c *HTTPClient) cachedHTTPError(key string) (*HTTPStatusError, bool, error) {
	if c.Cache == nil {
		return nil, false, nil
	}
	ttl := negativeCacheTTL
	if c.Cache.TTL > 0 && c.Cache.TTL < ttl {
		ttl = c.Cache.TTL
	}
	data, ok, err := c.Cache.GetWithTTL(key, ttl)
	if err != nil || !ok {
		return nil, ok, err
	}
	var cached cachedHTTPStatusError
	if err := json.Unmarshal(data, &cached); err != nil {
		return nil, true, err
	}
	return &HTTPStatusError{Code: cached.Code, Status: cached.Status, Headers: cached.Headers, Body: cached.Body}, true, nil
}

func mustMarshalCachedHTTPError(err *HTTPStatusError) []byte {
	data, marshalErr := json.Marshal(cachedHTTPStatusError{Code: err.Code, Status: err.Status, Headers: err.Headers, Body: err.Body})
	if marshalErr != nil {
		return []byte("{}")
	}
	return data
}

func (c *HTTPClient) acquire(ctx context.Context) (func(), error) {
	if c.Gate == nil {
		return func() {}, nil
	}
	select {
	case c.Gate <- struct{}{}:
		return func() { <-c.Gate }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func shouldReplaceProviderStatus(current, incoming string) bool {
	if incoming == "" {
		incoming = analyze.ProviderStatusError
	}
	return providerStatusRank(incoming) > providerStatusRank(current)
}

func providerStatusRank(status string) int {
	switch status {
	case analyze.ProviderStatusRateLimited:
		return 90
	case analyze.ProviderStatusCancelled:
		return 80
	case analyze.ProviderStatusTimeout:
		return 70
	case analyze.ProviderStatusUnavailable:
		return 60
	case analyze.ProviderStatusOfflineCacheMiss:
		return 50
	case analyze.ProviderStatusError:
		return 40
	case analyze.ProviderStatusOK, analyze.ProviderStatusOfflineCacheHit:
		return 0
	case "":
		return -1
	default:
		if analyze.ProviderStatusCountsAsError(status) {
			return 30
		}
		return 0
	}
}

func isRateLimitResponse(h http.Header, body []byte) bool {
	if h.Get("Retry-After") != "" {
		return true
	}
	if h.Get("X-RateLimit-Remaining") == "0" {
		return true
	}
	lower := strings.ToLower(string(body))
	return strings.Contains(lower, "rate limit") || strings.Contains(lower, "secondary rate limit")
}

func RateLimitSummary(err error) string {
	var statusErr *HTTPStatusError
	if !errors.As(err, &statusErr) || statusErr == nil {
		if err == nil {
			return ""
		}
		return err.Error()
	}
	retryAfter := statusErr.Headers.Get("Retry-After")
	if retryAfter != "" {
		return "rate limited; retry after " + retryAfter + " seconds"
	}
	reset := statusErr.Headers.Get("X-RateLimit-Reset")
	if reset != "" {
		if epoch, err := strconv.ParseInt(reset, 10, 64); err == nil {
			return "rate limited until " + time.Unix(epoch, 0).UTC().Format(time.RFC3339)
		}
	}
	return "rate limited by provider"
}

func IsHTTPStatus(err error, code int) bool {
	var statusErr *HTTPStatusError
	return errors.As(err, &statusErr) && statusErr != nil && statusErr.Code == code
}

func summarizeBody(body string) string {
	body = strings.TrimSpace(strings.ReplaceAll(body, "\n", " "))
	if len(body) > 160 {
		return body[:160] + "..."
	}
	return body
}

func retryDelay(attempt int) time.Duration {
	return time.Duration(100*(1<<attempt)) * time.Millisecond
}

func sleepOrDone(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func requestTimedOut(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	type timeout interface{ Timeout() bool }
	var timeoutErr timeout
	return errors.As(err, &timeoutErr) && timeoutErr.Timeout()
}
