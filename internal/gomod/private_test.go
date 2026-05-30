package gomod

import "testing"

func TestPrivateMatcherUsesGoPrefixPatternSemantics(t *testing.T) {
	t.Setenv("GOPRIVATE", "*.corp.example.com,corp.example.com/*")
	t.Setenv("GONOPROXY", "")
	t.Setenv("GONOSUMDB", "")

	matcher := NewPrivateMatcher(nil)
	for _, modulePath := range []string{
		"git.corp.example.com/team/mod",
		"corp.example.com/team/mod",
		"corp.example.com/team/mod/sub",
	} {
		if !matcher.IsPrivate(modulePath) {
			t.Fatalf("%q should be private", modulePath)
		}
	}
	if matcher.IsPrivate("github.com/acme/mod") {
		t.Fatal("github.com/acme/mod should not be private")
	}
}

func TestPrivateMatcherTreatsMainModulesAsPrivate(t *testing.T) {
	t.Setenv("GOPRIVATE", "")
	t.Setenv("GONOPROXY", "")
	t.Setenv("GONOSUMDB", "")

	matcher := NewPrivateMatcher([]string{"example.com/root"})
	for _, modulePath := range []string{"example.com/root", "example.com/root/sub"} {
		if !matcher.IsPrivate(modulePath) {
			t.Fatalf("%q should be private", modulePath)
		}
	}
}
