package fsutil

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWritePrivateFileCreatingDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "file.txt")
	if err := WritePrivateFileCreatingDir(path, []byte("ok")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "ok" {
		t.Fatalf("unexpected file contents: %q", data)
	}
}

func TestWritePrivateFileTightensExistingMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows chmod only maps the read-only bit")
	}
	path := filepath.Join(t.TempDir(), "file.txt")
	//nolint:gosec // Intentionally broad to verify WritePrivateFile tightens an existing file.
	if err := os.WriteFile(path, []byte("old"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := WritePrivateFile(path, []byte("new")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != PrivateFileMode {
		t.Fatalf("mode = %#o, want %#o", got, PrivateFileMode)
	}
}
