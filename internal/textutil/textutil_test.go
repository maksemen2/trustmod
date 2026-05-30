package textutil

import "testing"

func TestDashIfEmpty(t *testing.T) {
	if got := DashIfEmpty(""); got != "-" {
		t.Fatalf("DashIfEmpty empty = %q", got)
	}
	if got := DashIfEmpty("x"); got != "x" {
		t.Fatalf("DashIfEmpty value = %q", got)
	}
}

func TestSingleLine(t *testing.T) {
	if got := SingleLine("hello\nworld", 8); got != "hello wo..." {
		t.Fatalf("SingleLine = %q", got)
	}
}

func TestEscapeMarkdownPipes(t *testing.T) {
	if got := EscapeMarkdownPipes("a|b"); got != "a\\|b" {
		t.Fatalf("EscapeMarkdownPipes = %q", got)
	}
}
