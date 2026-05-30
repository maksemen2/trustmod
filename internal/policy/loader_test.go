package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadUsesPolicyFileProfileWhenNoOverride(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yml")
	data := []byte(`version: 1
profile: strict
fail_on: [BLOCK]
profiles:
  strict:
    fail_on: [BLOCK, REVIEW]
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	p, _, loaded, _, err := Load(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if !loaded {
		t.Fatalf("expected policy to load")
	}
	if p.Profile != "strict" {
		t.Fatalf("expected strict profile, got %q", p.Profile)
	}
	if len(p.FailOn) != 2 || p.FailOn[0] != "BLOCK" || p.FailOn[1] != "REVIEW" {
		t.Fatalf("expected strict profile fail_on override, got %#v", p.FailOn)
	}
}

func TestLoadProfileOverrideWinsOverPolicyFileProfile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yml")
	data := []byte(`version: 1
profile: strict
profiles:
  strict:
    fail_on: [BLOCK, REVIEW]
  backend-service:
    fail_on: [BLOCK]
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	p, _, _, _, err := Load(path, "backend-service")
	if err != nil {
		t.Fatal(err)
	}
	if p.Profile != "backend-service" {
		t.Fatalf("expected backend-service override, got %q", p.Profile)
	}
	if len(p.FailOn) != 1 || p.FailOn[0] != "BLOCK" {
		t.Fatalf("expected backend-service fail_on override, got %#v", p.FailOn)
	}
}
