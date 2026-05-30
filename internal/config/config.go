package config

import (
	"errors"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Config struct {
	DefaultProfile     string            `yaml:"default_profile" json:"default_profile"`
	CacheTTL           string            `yaml:"cache_ttl" json:"cache_ttl"`
	CacheDir           string            `yaml:"cache_dir" json:"cache_dir"`
	NoCache            bool              `yaml:"no_cache" json:"no_cache"`
	PolicyPath         string            `yaml:"policy_path" json:"policy_path"`
	BaselinePath       string            `yaml:"baseline_path" json:"baseline_path"`
	RulesPath          string            `yaml:"rules_path" json:"rules_path"`
	Timeout            string            `yaml:"timeout" json:"timeout"`
	GovulncheckTimeout string            `yaml:"govulncheck_timeout" json:"govulncheck_timeout"`
	Concurrency        int               `yaml:"concurrency" json:"concurrency"`
	Providers          map[string]bool   `yaml:"providers" json:"providers"`
	Output             string            `yaml:"output" json:"output"`
	CWD                string            `yaml:"cwd" json:"cwd"`
	FailOn             []string          `yaml:"fail_on" json:"fail_on"`
	AllowPrivateRemote bool              `yaml:"allow_private_remote" json:"allow_private_remote"`
	Offline            bool              `yaml:"offline" json:"offline"`
	StrictData         bool              `yaml:"strict_data" json:"strict_data"`
	IncludeTests       bool              `yaml:"include_tests" json:"include_tests"`
	IncludeTools       bool              `yaml:"include_tools" json:"include_tools"`
	Tags               string            `yaml:"tags" json:"tags"`
	NoColor            bool              `yaml:"no_color" json:"no_color"`
	GovulncheckPath    string            `yaml:"govulncheck_path" json:"govulncheck_path"`
	Extra              map[string]string `yaml:"extra,omitempty" json:"extra,omitempty"`
}

func Load(path string) (Config, string, bool, error) {
	return LoadFrom("", path)
}

func LoadFrom(root, path string) (Config, string, bool, error) {
	explicit := path != ""
	if path == "" {
		path = os.Getenv("TRUSTMOD_CONFIG")
		explicit = path != ""
	}
	paths := []string{path}
	if path == "" {
		paths = DefaultPaths()
	}
	for _, candidate := range paths {
		if candidate == "" {
			continue
		}
		if !explicit {
			candidate = rootedPath(root, candidate)
		}
		data, err := os.ReadFile(candidate)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				if explicit {
					return Config{}, candidate, false, err
				}
				continue
			}
			return Config{}, candidate, false, err
		}
		var c Config
		if err := yaml.Unmarshal(data, &c); err != nil {
			return Config{}, candidate, false, err
		}
		return c, candidate, true, nil
	}
	if len(paths) == 0 {
		return Config{}, rootedPath(root, DefaultPath()), false, nil
	}
	return Config{}, rootedPath(root, paths[0]), false, nil
}

func rootedPath(root, path string) string {
	if root == "" || path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(root, path)
}
