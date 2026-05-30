package bitset

import "testing"

func TestBitsSetClearMergeAndCount(t *testing.T) {
	a := New(130)
	b := New(130)

	a.Set(1)
	a.Set(64)
	b.Set(64)
	b.Set(129)

	a.Merge(b)
	if got := a.Count(); got != 3 {
		t.Fatalf("count after merge = %d, want 3", got)
	}

	a.Clear(64)
	if got := a.Count(); got != 2 {
		t.Fatalf("count after clear = %d, want 2", got)
	}
}
