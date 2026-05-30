package collect

import (
	"context"
	"sort"
	"sync/atomic"
	"testing"
	"time"
)

func TestSetAddAndHas(t *testing.T) {
	s := NewSet("a")
	if !s.Has("a") {
		t.Fatal("expected initial value")
	}
	if s.Add("a") {
		t.Fatal("duplicate add should return false")
	}
	if !s.Add("b") || !s.Has("b") {
		t.Fatal("expected new value to be added")
	}
}

func TestAppendUniqueSortedStrings(t *testing.T) {
	got := AppendUniqueSortedStrings([]string{"b"}, " a ", "", "b", "c")
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %#v, want %#v", got, want)
		}
	}
}

func TestFirstNonEmpty(t *testing.T) {
	if got := FirstNonEmpty("", " ", "x"); got != " " {
		t.Fatalf("FirstNonEmpty = %q, want space", got)
	}
}

func TestFirstNonBlank(t *testing.T) {
	if got := FirstNonBlank("", " ", "x"); got != "x" {
		t.Fatalf("FirstNonBlank = %q, want x", got)
	}
}

func TestOverlapsTrimmed(t *testing.T) {
	if !OverlapsTrimmed([]string{" a "}, []string{"a"}) {
		t.Fatal("expected trimmed overlap")
	}
	if OverlapsTrimmed([]string{""}, []string{""}) {
		t.Fatal("empty strings should not overlap")
	}
}

func TestUniqueTrimmedStrings(t *testing.T) {
	got := UniqueTrimmedStrings([]string{" a ", "", "b", "a"})
	want := []string{"a", "b"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %#v, want %#v", got, want)
		}
	}
}

func TestSplitCommaList(t *testing.T) {
	got := SplitCommaList("a, b,, c ")
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %#v, want %#v", got, want)
		}
	}
}

func TestUpsert(t *testing.T) {
	type entry struct {
		key   string
		value int
	}
	got := Upsert([]entry{{key: "a", value: 1}}, entry{key: "a", value: 2}, func(existing, incoming entry) bool {
		return existing.key == incoming.key
	})
	if len(got) != 1 || got[0].value != 2 {
		t.Fatalf("unexpected upsert result: %#v", got)
	}
}

func TestFilterInPlace(t *testing.T) {
	got := FilterInPlace([]int{1, 2, 3, 4}, func(v int) bool { return v%2 == 0 })
	if len(got) != 2 || got[0] != 2 || got[1] != 4 {
		t.Fatalf("unexpected filter result: %#v", got)
	}
}

func TestChunks(t *testing.T) {
	got := Chunks([]int{1, 2, 3, 4, 5}, 2)
	if len(got) != 3 || len(got[0]) != 2 || len(got[2]) != 1 {
		t.Fatalf("unexpected chunks: %#v", got)
	}
}

func TestGroupBy(t *testing.T) {
	groups, skipped := GroupBy([]string{"a1", "a2", "b1", ""}, func(v string) (byte, bool) {
		if v == "" {
			return 0, false
		}
		return v[0], true
	})
	if skipped != 1 || len(groups) != 2 {
		t.Fatalf("unexpected groups=%#v skipped=%d", groups, skipped)
	}
	if groups[0].Key != 'a' || len(groups[0].Items) != 2 {
		t.Fatalf("unexpected first group: %#v", groups[0])
	}
}

func TestUniqueBy(t *testing.T) {
	got := UniqueBy([]string{"a1", "a2", "b1"}, func(v string) byte { return v[0] })
	if len(got) != 2 || got[0] != "a1" || got[1] != "b1" {
		t.Fatalf("unexpected unique result: %#v", got)
	}
}

func TestParallelMap(t *testing.T) {
	got := ParallelMap(context.Background(), []int{1, 2, 3}, 2, func(_ context.Context, _ int, v int) int {
		return v * 2
	})
	sort.Ints(got)
	if len(got) != 3 || got[0] != 2 || got[1] != 4 || got[2] != 6 {
		t.Fatalf("unexpected parallel map result: %#v", got)
	}
}

func TestParallelMapHonorsConcurrency(t *testing.T) {
	items := make([]int, 20)
	var active atomic.Int32
	var maxActive atomic.Int32
	got := ParallelMap(context.Background(), items, 3, func(_ context.Context, _ int, v int) int {
		current := active.Add(1)
		for {
			max := maxActive.Load()
			if current <= max || maxActive.CompareAndSwap(max, current) {
				break
			}
		}
		time.Sleep(2 * time.Millisecond)
		active.Add(-1)
		return v
	})
	if len(got) != len(items) {
		t.Fatalf("results = %d, want %d", len(got), len(items))
	}
	if got := maxActive.Load(); got > 3 {
		t.Fatalf("max active workers = %d, want <= 3", got)
	}
}

func TestParallelMapVisitsAllItemsAfterContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var calls atomic.Int32
	var sawLiveContext atomic.Bool
	got := ParallelMap(ctx, []int{1, 2, 3, 4}, 2, func(ctx context.Context, _ int, v int) int {
		if ctx.Err() == nil {
			sawLiveContext.Store(true)
		}
		calls.Add(1)
		return v
	})
	if sawLiveContext.Load() {
		t.Fatal("expected cancelled context in every call")
	}
	if len(got) != 4 || calls.Load() != 4 {
		t.Fatalf("got len=%d calls=%d, want all items visited", len(got), calls.Load())
	}
}
