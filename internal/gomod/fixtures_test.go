package gomod

import "testing"

func TestSemverHelpers(t *testing.T) {
	if MajorVersion("v2.3.4") != 2 {
		t.Fatalf("expected v2 major")
	}
	if !IsPseudoVersion("v0.0.0-20240203120000-abcdefabcdef") {
		t.Fatalf("expected pseudo-version")
	}
	if !MajorVersionPathMismatch("example.com/mod", "v2.0.0") {
		t.Fatalf("expected v2 path mismatch")
	}
}

func TestPrivateMatcher(t *testing.T) {
	m := PrivateMatcher{Patterns: "corp.example.com/*,*.internal.example.com,example.net/private/", Main: []string{"example.com/app"}}
	for _, mod := range []string{"corp.example.com/lib/subpkg", "api.internal.example.com/team/lib", "example.net/private/pkg", "example.com/app/internal"} {
		if !m.IsPrivate(mod) {
			t.Fatalf("expected %s private", mod)
		}
	}
	if m.IsPrivate("github.com/go-chi/chi/v5") {
		t.Fatalf("public module matched private patterns")
	}
	if m.IsPrivate("corp.example.com") {
		t.Fatalf("pattern with a wildcard path element should not match a shorter module path")
	}
}
