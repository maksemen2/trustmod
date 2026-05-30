package packagescan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanModuleFindsCapabilities(t *testing.T) {
	dir := t.TempDir()
	src := `package demo

import (
	"os"
	"os/exec"
)

func run() {
	_ = os.WriteFile("x", []byte("y"), 0o600)
	_, _ = exec.Command("go", "version").Output()
}
`
	if err := os.WriteFile(filepath.Join(dir, "demo.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := ScanModule(context.Background(), "example.com/demo", "v1.0.0", dir, true)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	var fsWriteEvidence int
	for _, c := range res.Capabilities {
		seen[c.Name] = true
		if c.Name == "fs.write" {
			fsWriteEvidence = len(c.Evidence)
			if len(c.Evidence) == 0 || c.Evidence[0].File != "demo.go" || c.Evidence[0].Line == 0 {
				t.Fatalf("expected structured fs.write evidence, got %#v", c.Evidence)
			}
		}
	}
	if !seen["process.exec"] || !seen["fs.write"] {
		t.Fatalf("missing expected capabilities: %#v", res.Capabilities)
	}
	if fsWriteEvidence == 0 {
		t.Fatalf("missing fs.write evidence")
	}
}

func TestScanModuleDoesNotInferCapabilitiesFromBroadImports(t *testing.T) {
	dir := t.TempDir()
	src := `package demo

import (
	"crypto/md5"
	"database/sql/driver"
	"net"
	"os"
)

var _ driver.Value = ""

func host() ([]net.Interface, string, []byte) {
	ifaces, _ := net.Interfaces()
	name, _ := os.Hostname()
	sum := md5.Sum([]byte(name))
	return ifaces, name, sum[:]
}
`
	if err := os.WriteFile(filepath.Join(dir, "demo.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := ScanModule(context.Background(), "example.com/demo", "v1.0.0", dir, true)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, c := range res.Capabilities {
		seen[c.Name] = true
	}
	for _, name := range []string{"fs.write", "fs.read", "fs.delete", "env.read", "env.write", "net.client", "net.server", "database.client"} {
		if seen[name] {
			t.Fatalf("unexpected inferred capability %s from broad import: %#v", name, res.Capabilities)
		}
	}
	if !seen["crypto.weak"] {
		t.Fatalf("expected crypto.weak from md5 import")
	}
	for _, f := range res.Findings {
		if f.Code == "TM-CAP-006" {
			t.Fatalf("weak hash import should be context only, got finding: %#v", f)
		}
	}
}

func TestScanModuleExtractsNetworkDomains(t *testing.T) {
	dir := t.TempDir()
	src := `package demo

import (
	"context"
	"net"
	"net/http"
)

const apiBase = "https://api.example.com"

func fetch(ctx context.Context) {
	client := http.Client{}
	_, _ = http.Get(apiBase + "/v1/resource")
	_, _ = http.Post("https://logs.example.org/ingest", "application/json", nil)
	_, _ = http.NewRequestWithContext(ctx, "GET", "https://download.example.net/file", nil)
	_, _ = client.Get("https://client.example.io/ping")
	_, _ = net.Dial("tcp", "cache.example.com:443")
	_, _ = http.Get("https://api.example.com/v2/other")
}
`
	if err := os.WriteFile(filepath.Join(dir, "demo.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := ScanModule(context.Background(), "example.com/demo", "v1.0.0", dir, true)
	if err != nil {
		t.Fatal(err)
	}
	var gotDomains []string
	for _, c := range res.Capabilities {
		if c.Name == "net.client" {
			gotDomains = c.Domains
			break
		}
	}
	if gotDomains == nil {
		t.Fatalf("missing net.client capability: %#v", res.Capabilities)
	}
	want := []string{"api.example.com", "cache.example.com", "client.example.io", "download.example.net", "logs.example.org"}
	if strings.Join(gotDomains, ",") != strings.Join(want, ",") {
		t.Fatalf("domains = %#v, want %#v", gotDomains, want)
	}
	for _, f := range res.Findings {
		if f.Code != "TM-CAP-003" {
			continue
		}
		if !containsString(f.Evidence, "network domains: api.example.com, cache.example.com, client.example.io, download.example.net, logs.example.org") {
			t.Fatalf("network finding evidence missing domains: %#v", f.Evidence)
		}
		return
	}
	t.Fatalf("missing TM-CAP-003 finding: %#v", res.Findings)
}

func TestScanModuleDetectsFastHTTPNetwork(t *testing.T) {
	dir := t.TempDir()
	src := `package demo

import "github.com/valyala/fasthttp"

const defaultBotAPIServer = "https://api.telegram.org"

func fetch(request *fasthttp.Request, response *fasthttp.Response) {
	request.SetRequestURI(defaultBotAPIServer + "/bot123/sendMessage")
	_, _, _ = fasthttp.Get(nil, "https://files.example.com/archive")
	client := fasthttp.Client{}
	_ = client.Do(request, response)
}
`
	if err := os.WriteFile(filepath.Join(dir, "demo.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := ScanModule(context.Background(), "example.com/demo", "v1.0.0", dir, true)
	if err != nil {
		t.Fatal(err)
	}
	var gotDomains []string
	var directCalls int
	for i := range res.Capabilities {
		if res.Capabilities[i].Name == "net.client" {
			gotDomains = res.Capabilities[i].Domains
			directCalls = res.Capabilities[i].DirectCalls
			break
		}
	}
	if gotDomains == nil {
		t.Fatalf("missing net.client capability: %#v", res.Capabilities)
	}
	want := []string{"api.telegram.org", "files.example.com"}
	if strings.Join(gotDomains, ",") != strings.Join(want, ",") {
		t.Fatalf("domains = %#v, want %#v", gotDomains, want)
	}
	if directCalls < 3 {
		t.Fatalf("direct calls = %d, want at least 3", directCalls)
	}
}

func TestScanModuleDetectsHTTPClientMethodWithDynamicURL(t *testing.T) {
	dir := t.TempDir()
	src := `package demo

import "net/http"

func fetch(client *http.Client, request *http.Request, url string) {
	_, _ = client.Get(url)
	_, _ = client.Do(request)
}
`
	if err := os.WriteFile(filepath.Join(dir, "demo.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := ScanModule(context.Background(), "example.com/demo", "v1.0.0", dir, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range res.Capabilities {
		if c.Name != "net.client" {
			continue
		}
		if c.DirectCalls != 2 {
			t.Fatalf("direct calls = %d, want 2", c.DirectCalls)
		}
		if len(c.Domains) != 0 {
			t.Fatalf("domains = %#v, want none for dynamic URL", c.Domains)
		}
		return
	}
	t.Fatalf("missing net.client capability: %#v", res.Capabilities)
}

func TestScanModuleLimitsNetworkDomains(t *testing.T) {
	dir := t.TempDir()
	src := `package demo

import "net/http"

func fetch() {
	_, _ = http.Get("https://a.example.com")
	_, _ = http.Get("https://b.example.com")
	_, _ = http.Get("https://c.example.com")
	_, _ = http.Get("https://d.example.com")
	_, _ = http.Get("https://e.example.com")
	_, _ = http.Get("https://f.example.com")
	_, _ = http.Get("https://g.example.com")
	_, _ = http.Get("https://h.example.com")
	_, _ = http.Get("https://i.example.com")
}
`
	if err := os.WriteFile(filepath.Join(dir, "demo.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := ScanModule(context.Background(), "example.com/demo", "v1.0.0", dir, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range res.Capabilities {
		if c.Name != "net.client" {
			continue
		}
		if len(c.Domains) != maxStoredCapabilityDomains {
			t.Fatalf("stored domains = %d, want %d: %#v", len(c.Domains), maxStoredCapabilityDomains, c.Domains)
		}
		if c.DomainCount != 9 {
			t.Fatalf("domain count = %d, want 9", c.DomainCount)
		}
		return
	}
	t.Fatalf("missing net.client capability: %#v", res.Capabilities)
}

func TestScanModuleSkipsExamplesAndToolDirs(t *testing.T) {
	dir := t.TempDir()
	for _, sub := range []string{"_examples/demo", "examples/demo", "cmd/generator", "upgrade"} {
		if err := os.MkdirAll(filepath.Join(dir, filepath.FromSlash(sub)), 0o700); err != nil {
			t.Fatal(err)
		}
		src := `package main

import (
	"net/http"
	"os"
	"os/exec"
)

func main() {
	_, _ = exec.Command("go", "version").Output()
	_ = os.WriteFile("x", nil, 0o600)
	_ = http.ListenAndServe(":0", nil)
}
`
		if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(sub), "main.go"), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "uuid.go"), []byte("package demo\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := ScanModule(context.Background(), "example.com/demo", "v1.0.0", dir, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Capabilities) != 0 {
		t.Fatalf("expected examples/tool dirs to be skipped, got %#v", res.Capabilities)
	}
}

func TestScanModuleSkipsIgnoredGenerators(t *testing.T) {
	dir := t.TempDir()
	src := `//go:build ignore

package main

import (
	"os"
	"os/exec"
)

func main() {
	_, _ = exec.Command("go", "version").Output()
	_ = os.WriteFile("x", nil, 0o600)
}
`
	if err := os.WriteFile(filepath.Join(dir, "gen.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "lib.go"), []byte("package demo\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := ScanModule(context.Background(), "example.com/demo", "v1.0.0", dir, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Capabilities) != 0 {
		t.Fatalf("expected ignored generator to be skipped, got %#v", res.Capabilities)
	}
}

func TestScanFilesOnlyScansProvidedFiles(t *testing.T) {
	dir := t.TempDir()
	safe := `package demo

func ok() {}
`
	risky := `package demo

import "os/exec"

func run() {
	_, _ = exec.Command("go", "version").Output()
}
`
	if err := os.WriteFile(filepath.Join(dir, "safe.go"), []byte(safe), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "risky.go"), []byte(risky), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := ScanFiles(context.Background(), "example.com/demo", "v1.0.0", dir, []string{filepath.Join(dir, "safe.go")}, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.FilesScanned != 1 {
		t.Fatalf("FilesScanned = %d, want 1", res.FilesScanned)
	}
	if len(res.Capabilities) != 0 {
		t.Fatalf("expected risky file outside the package list to be ignored, got %#v", res.Capabilities)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
