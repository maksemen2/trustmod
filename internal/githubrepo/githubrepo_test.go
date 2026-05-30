package githubrepo

import "testing"

func TestFromModuleStripsMajorSuffixAndKeepsSubdir(t *testing.T) {
	repo, ok := FromModule("github.com/acme/project/sub/pkg/v2")
	if !ok {
		t.Fatal("expected GitHub module")
	}
	if repo.Owner != "acme" || repo.Name != "project" || repo.Subdir != "sub/pkg" {
		t.Fatalf("unexpected repo: %#v", repo)
	}
}

func TestNormalizeURL(t *testing.T) {
	got, ok := NormalizeURL("github.com/acme/project.git/tree/main")
	if !ok || got != "https://github.com/acme/project" {
		t.Fatalf("NormalizeURL() = %q, %v", got, ok)
	}
}

func TestRefForPseudoVersionUsesCommit(t *testing.T) {
	got, ok := RefForVersion("v0.0.0-20200622213623-75b288015ac9")
	if !ok || got != "75b288015ac9" {
		t.Fatalf("RefForVersion() = %q, %v", got, ok)
	}
}
