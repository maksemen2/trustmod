package cache

import (
	"bytes"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestStoreSetConcurrentSameKey(t *testing.T) {
	store, err := New(t.TempDir(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	const writers = 16
	var wg sync.WaitGroup
	wg.Add(writers)
	for i := 0; i < writers; i++ {
		go func() {
			defer wg.Done()
			_ = store.Set("same-key", []byte("value-"+strconv.Itoa(i)))
		}()
	}
	wg.Wait()

	data, ok, err := store.Get("same-key")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected cache value")
	}
	if !bytes.HasPrefix(data, []byte("value-")) {
		t.Fatalf("unexpected cached data: %q", data)
	}
}
