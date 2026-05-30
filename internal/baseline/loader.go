package baseline

import (
	"errors"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

func Load(path string) (Baseline, string, bool, error) {
	if path == "" {
		path = filepath.Join(".trustmod", "baseline.yml")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Empty(), path, false, nil
		}
		return Empty(), path, false, err
	}
	var b Baseline
	if err := yaml.Unmarshal(data, &b); err != nil {
		return Empty(), path, false, err
	}
	if b.Version == 0 {
		b.Version = 1
	}
	return b, path, true, nil
}
