package collect

import (
	"context"
	"sort"
	"strings"
	"sync"
)

type Set[T comparable] map[T]struct{}

func NewSet[T comparable](values ...T) Set[T] {
	s := make(Set[T], len(values))
	for _, value := range values {
		s[value] = struct{}{}
	}
	return s
}

func (s Set[T]) Add(value T) bool {
	if _, ok := s[value]; ok {
		return false
	}
	s[value] = struct{}{}
	return true
}

func (s Set[T]) Has(value T) bool {
	_, ok := s[value]
	return ok
}

func (s Set[T]) Delete(value T) {
	delete(s, value)
}

func AppendUnique[T comparable](in []T, values ...T) []T {
	if len(values) == 0 {
		return in
	}
	seen := NewSet(in...)
	for _, value := range values {
		if seen.Add(value) {
			in = append(in, value)
		}
	}
	return in
}

func AppendUniqueSortedStrings(in []string, values ...string) []string {
	if len(values) == 0 {
		return in
	}
	seen := NewSet[string]()
	for _, value := range in {
		seen.Add(value)
	}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || !seen.Add(value) {
			continue
		}
		in = append(in, value)
	}
	sort.Strings(in)
	return in
}

func FirstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func FirstNonBlank(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func OverlapsTrimmed(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	seen := NewSet[string]()
	for _, value := range a {
		value = strings.TrimSpace(value)
		if value != "" {
			seen.Add(value)
		}
	}
	for _, value := range b {
		if seen.Has(strings.TrimSpace(value)) {
			return true
		}
	}
	return false
}

func UniqueTrimmedStrings(values []string) []string {
	seen := NewSet[string]()
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || !seen.Add(value) {
			continue
		}
		out = append(out, value)
	}
	return out
}

func SplitCommaList(value string) []string {
	var out []string
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func Upsert[T any](entries []T, entry T, same func(existing T, incoming T) bool) []T {
	for i := range entries {
		if same(entries[i], entry) {
			entries[i] = entry
			return entries
		}
	}
	return append(entries, entry)
}

func FilterInPlace[T any](entries []T, keep func(T) bool) []T {
	out := entries[:0]
	for _, entry := range entries {
		if keep(entry) {
			out = append(out, entry)
		}
	}
	return out
}

func Chunks[T any](in []T, size int) [][]T {
	if size <= 0 || len(in) <= size {
		return [][]T{in}
	}
	chunks := make([][]T, 0, (len(in)+size-1)/size)
	for len(in) > 0 {
		end := size
		if end > len(in) {
			end = len(in)
		}
		chunks = append(chunks, in[:end])
		in = in[end:]
	}
	return chunks
}

type Group[K comparable, T any] struct {
	Key   K
	Items []T
}

func GroupBy[T any, K comparable](items []T, key func(T) (K, bool)) ([]Group[K, T], int) {
	index := map[K]int{}
	groups := make([]Group[K, T], 0, len(items))
	skipped := 0
	for _, item := range items {
		k, ok := key(item)
		if !ok {
			skipped++
			continue
		}
		if i, ok := index[k]; ok {
			groups[i].Items = append(groups[i].Items, item)
			continue
		}
		index[k] = len(groups)
		groups = append(groups, Group[K, T]{Key: k, Items: []T{item}})
	}
	return groups, skipped
}

func UniqueBy[T any, K comparable](items []T, key func(T) K) []T {
	seen := NewSet[K]()
	out := items[:0]
	for _, item := range items {
		if seen.Add(key(item)) {
			out = append(out, item)
		}
	}
	return out
}

func ParallelMap[T any, R any](ctx context.Context, items []T, concurrency int, fn func(context.Context, int, T) R) []R {
	results := make([]R, len(items))
	if len(items) == 0 {
		return results
	}
	if concurrency <= 0 || concurrency > len(items) {
		concurrency = len(items)
	}
	jobs := make(chan int)
	var wg sync.WaitGroup
	wg.Add(concurrency)
	for worker := 0; worker < concurrency; worker++ {
		go func() {
			defer wg.Done()
			for i := range jobs {
				results[i] = fn(ctx, i, items[i])
			}
		}()
	}
	for i := range items {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return results
}
