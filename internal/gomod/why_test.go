package gomod

import "testing"

func TestParseWhyModulesOutput(t *testing.T) {
	out := `# github.com/spf13/cobra
github.com/maksemen2/trustmod/internal/cli
github.com/spf13/cobra

# golang.org/x/mod
github.com/maksemen2/trustmod/internal/gomod
golang.org/x/mod/modfile
`

	paths := parseWhyModulesOutput([]string{"github.com/spf13/cobra", "golang.org/x/mod"}, out)
	if got := len(paths["github.com/spf13/cobra"]); got != 2 {
		t.Fatalf("cobra path length = %d, want 2", got)
	}
	if got := paths["golang.org/x/mod"][1]; got != "golang.org/x/mod/modfile" {
		t.Fatalf("unexpected x/mod leaf: %q", got)
	}
}
