package buildinfo

import (
	"runtime/debug"
	"testing"
)

func TestEnrichUsesModuleVersionAndVCSSettings(t *testing.T) {
	got := Enrich(Info{
		Version: "dev",
		Commit:  "unknown",
		Date:    "unknown",
	}, &debug.BuildInfo{
		Main: debug.Module{Version: "v1.2.3"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "abc123"},
			{Key: "vcs.time", Value: "2026-05-24T22:00:00Z"},
		},
	})

	if got.Version != "v1.2.3" {
		t.Fatalf("version = %q, want v1.2.3", got.Version)
	}
	if got.Commit != "abc123" {
		t.Fatalf("commit = %q, want abc123", got.Commit)
	}
	if got.Date != "2026-05-24T22:00:00Z" {
		t.Fatalf("date = %q, want VCS time", got.Date)
	}
}

func TestEnrichDoesNotOverrideExplicitBuildValues(t *testing.T) {
	base := Info{
		Version: "v9.9.9",
		Commit:  "release-commit",
		Date:    "release-date",
	}
	got := Enrich(base, &debug.BuildInfo{
		Main: debug.Module{Version: "v1.2.3"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "abc123"},
			{Key: "vcs.time", Value: "2026-05-24T22:00:00Z"},
		},
	})

	if got != base {
		t.Fatalf("build info was overridden: got %#v want %#v", got, base)
	}
}

func TestEnrichIgnoresDefaultBuildValues(t *testing.T) {
	got := Enrich(Info{
		Version: "dev",
		Commit:  "unknown",
		Date:    "unknown",
	}, &debug.BuildInfo{
		Main: debug.Module{Version: "(devel)"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "unknown"},
			{Key: "vcs.time", Value: ""},
		},
	})

	if got.Version != "dev" {
		t.Fatalf("version = %q, want dev", got.Version)
	}
	if got.Commit != "unknown" {
		t.Fatalf("commit = %q, want unknown", got.Commit)
	}
	if got.Date != "unknown" {
		t.Fatalf("date = %q, want unknown", got.Date)
	}
}
