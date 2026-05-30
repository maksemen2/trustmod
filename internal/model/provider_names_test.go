package model

import "testing"

func TestCanonicalProviderNameAliases(t *testing.T) {
	cases := map[string]string{
		"depsdev":           "deps.dev",
		"deps-dev":          "deps.dev",
		"git-hub":           "github",
		"openssf-scorecard": "scorecard",
		"go-vulncheck":      "govulncheck",
	}
	for in, want := range cases {
		got, ok := CanonicalProviderName(in)
		if !ok || got != want {
			t.Fatalf("CanonicalProviderName(%q) = %q, %v; want %q, true", in, got, ok, want)
		}
	}
}

func TestNormalizeProviderNameKeepsUnknownLowercase(t *testing.T) {
	if got := NormalizeProviderName(" Custom.Provider "); got != "custom.provider" {
		t.Fatalf("NormalizeProviderName = %q", got)
	}
}
