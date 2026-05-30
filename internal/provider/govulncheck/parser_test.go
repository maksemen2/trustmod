package govulncheck

import "testing"

func TestParseIgnoresOSVOnlyMessages(t *testing.T) {
	out := []byte(`{"osv":{"id":"GO-2024-0001","summary":"module advisory","affected":[{"package":{"name":"example.com/mod"}}]}}` + "\n")
	if got := Parse(out); len(got) != 0 {
		t.Fatalf("expected OSV metadata without finding to be ignored, got %#v", got)
	}
}

func TestParseFindingMessage(t *testing.T) {
	out := []byte(
		`{"osv":{"id":"GO-2024-0001","summary":"reachable vuln","affected":[{"package":{"name":"example.com/mod"}}]}}` + "\n" +
			`{"finding":{"osv":"GO-2024-0001","fixed_version":"v1.2.3","trace":[{"module":"example.com/mod","version":"v1.0.0","package":"example.com/mod/pkg","function":"Bad","position":{"filename":"pkg/bad.go","line":12}},{"module":"example.com/app","version":"","package":"example.com/app","function":"main"}]}}` + "\n")
	got := Parse(out)
	if len(got) != 1 {
		t.Fatalf("expected one finding, got %d", len(got))
	}
	f := got[0]
	if !f.Reachable {
		t.Fatalf("expected finding with trace to be reachable")
	}
	if f.OSV != "GO-2024-0001" || f.Module != "example.com/mod" || f.Version != "v1.0.0" || f.FixedVersion != "v1.2.3" {
		t.Fatalf("unexpected finding fields: %#v", f)
	}
	if f.Symbol != "example.com/mod/pkg.Bad" {
		t.Fatalf("unexpected symbol %q", f.Symbol)
	}
	if len(f.Trace) != 2 {
		t.Fatalf("expected trace lines, got %#v", f.Trace)
	}
}
