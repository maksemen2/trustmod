package cache

import "testing"

func TestKeyStable(t *testing.T) {
	a := Key("osv", "github.com/a/b", "v1.0.0")
	b := Key("osv", "github.com/a/b", "v1.0.0")
	c := Key("osv", "github.com/a/b", "v1.0.1")
	if a != b || a == c {
		t.Fatalf("unexpected key stability")
	}
}
