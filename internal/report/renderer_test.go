package report

import "testing"

func TestProjectRendererFor(t *testing.T) {
	for _, format := range []string{"", "human", "json", "markdown", "md", "sarif", "junit"} {
		if _, ok := ProjectRendererFor(format); !ok {
			t.Fatalf("ProjectRendererFor(%q) returned ok=false", format)
		}
	}
	if _, ok := ProjectRendererFor("bogus"); ok {
		t.Fatalf("ProjectRendererFor should reject unknown formats")
	}
}

func TestCompareRendererFor(t *testing.T) {
	for _, format := range []string{"", "human", "json", "markdown", "md"} {
		if _, ok := CompareRendererFor(format); !ok {
			t.Fatalf("CompareRendererFor(%q) returned ok=false", format)
		}
	}
	for _, format := range []string{"sarif", "junit", "bogus"} {
		if _, ok := CompareRendererFor(format); ok {
			t.Fatalf("CompareRendererFor(%q) should reject unsupported format", format)
		}
	}
}

func TestGraphRendererFor(t *testing.T) {
	for _, format := range []string{"", "human", "text", "json", "dot"} {
		if _, ok := GraphRendererFor(format); !ok {
			t.Fatalf("GraphRendererFor(%q) returned ok=false", format)
		}
	}
	if _, ok := GraphRendererFor("sarif"); ok {
		t.Fatalf("GraphRendererFor should reject unsupported formats")
	}
}
