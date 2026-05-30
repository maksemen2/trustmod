package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPrefersDotTrustmodYAML(t *testing.T) {
	dir := t.TempDir()
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if chdirErr := os.Chdir(oldwd); chdirErr != nil {
			t.Fatal(chdirErr)
		}
	}()
	if chdirErr := os.Chdir(dir); chdirErr != nil {
		t.Fatal(chdirErr)
	}
	if writeErr := os.WriteFile(".trustmod.yaml", []byte("default_profile: strict\nproviders:\n  github: false\n"), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	cfg, path, loaded, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if !loaded || path != ".trustmod.yaml" {
		t.Fatalf("expected .trustmod.yaml to load, loaded=%v path=%q", loaded, path)
	}
	if cfg.DefaultProfile != "strict" || cfg.Providers["github"] {
		t.Fatalf("unexpected config: %#v", cfg)
	}
}

func TestLoadExplicitPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom.yml")
	if err := os.WriteFile(path, []byte("output: json\nconcurrency: 3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, loadedPath, loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded || loadedPath != path {
		t.Fatalf("expected explicit path to load, loaded=%v path=%q", loaded, loadedPath)
	}
	if cfg.Output != "json" || cfg.Concurrency != 3 {
		t.Fatalf("unexpected config: %#v", cfg)
	}
}

func TestLoadExplicitMissingPathFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.yml")
	if _, _, _, err := Load(path); err == nil {
		t.Fatalf("expected explicit missing config to fail")
	}
}

func TestLoadFromUsesRootForImplicitDefaults(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".trustmod.yaml"), []byte("output: markdown\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, path, loaded, err := LoadFrom(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if !loaded || path != filepath.Join(dir, ".trustmod.yaml") {
		t.Fatalf("expected rooted default config to load, loaded=%v path=%q", loaded, path)
	}
	if cfg.Output != "markdown" {
		t.Fatalf("unexpected config: %#v", cfg)
	}
}
