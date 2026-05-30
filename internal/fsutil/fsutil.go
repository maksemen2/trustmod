package fsutil

import (
	"os"
	"path/filepath"
)

const (
	PrivateDirMode  os.FileMode = 0o700
	PrivateFileMode os.FileMode = 0o600
)

func EnsurePrivateDir(path string) error {
	if err := os.MkdirAll(path, PrivateDirMode); err != nil {
		return err
	}
	return os.Chmod(path, PrivateDirMode)
}

func WritePrivateFile(path string, data []byte) error {
	if err := os.WriteFile(path, data, PrivateFileMode); err != nil {
		return err
	}
	return os.Chmod(path, PrivateFileMode)
}

func WritePrivateFileCreatingDir(path string, data []byte) error {
	if err := EnsurePrivateDir(filepath.Dir(path)); err != nil {
		return err
	}
	return WritePrivateFile(path, data)
}

func CreatePrivateFile(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, PrivateFileMode)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, PrivateFileMode); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func AppendPrivateFile(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, PrivateFileMode)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, PrivateFileMode); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}
