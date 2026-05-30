package cache

import (
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/maksemen2/trustmod/internal/fsutil"
)

type Store struct {
	Dir string
	TTL time.Duration
}

func New(dir string, ttl time.Duration) (*Store, error) {
	if dir == "" {
		dir = DefaultDir()
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	if err := fsutil.EnsurePrivateDir(dir); err != nil {
		return nil, err
	}
	return &Store{Dir: dir, TTL: ttl}, nil
}

func DefaultDir() string {
	if v := os.Getenv("TRUSTMOD_CACHE_DIR"); v != "" {
		return v
	}
	if d, err := os.UserCacheDir(); err == nil {
		return filepath.Join(d, "trustmod")
	}
	return filepath.Join(os.TempDir(), "trustmod-cache")
}

func (s *Store) Get(key string) ([]byte, bool, error) {
	return s.GetWithTTL(key, s.TTL)
}

func (s *Store) GetWithTTL(key string, ttl time.Duration) ([]byte, bool, error) {
	if s == nil {
		return nil, false, nil
	}
	path := filepath.Join(s.Dir, key+".json")
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, err
	}
	if ttl > 0 && time.Since(info.ModTime()) > ttl {
		return nil, false, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

func (s *Store) Set(key string, data []byte) error {
	if s == nil {
		return nil
	}
	if err := fsutil.EnsurePrivateDir(s.Dir); err != nil {
		return err
	}
	dst := filepath.Join(s.Dir, key+".json")
	tmp, err := os.CreateTemp(s.Dir, key+".*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := os.Chmod(tmpPath, fsutil.PrivateFileMode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, dst)
}

func (s *Store) Clean() error {
	if s == nil || s.Dir == "" {
		return nil
	}
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if filepath.Ext(e.Name()) == ".json" {
			if err := os.Remove(filepath.Join(s.Dir, e.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Store) Prune() (int, error) {
	if s == nil || s.Dir == "" {
		return 0, nil
	}
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	removed := 0
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		path := filepath.Join(s.Dir, e.Name())
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if s.TTL > 0 && time.Since(info.ModTime()) > s.TTL {
			if err := os.Remove(path); err != nil {
				return removed, err
			}
			removed++
		}
	}
	return removed, nil
}

func (s *Store) Stats() (files int, bytes int64, err error) {
	if s == nil || s.Dir == "" {
		return 0, 0, nil
	}
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, 0, nil
		}
		return 0, 0, err
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files++
		bytes += info.Size()
	}
	return files, bytes, nil
}
