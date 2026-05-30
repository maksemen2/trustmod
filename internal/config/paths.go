package config

import "path/filepath"

func DefaultPath() string {
	return ".trustmod.yaml"
}

func DefaultPaths() []string {
	return []string{
		".trustmod.yaml",
		".trustmod.yml",
		filepath.Join(".trustmod", "config.yml"),
	}
}

func LegacyDefaultPath() string {
	return filepath.Join(".trustmod", "config.yml")
}

func DefaultPolicyPath() string {
	return filepath.Join(".trustmod", "policy.yml")
}

func DefaultBaselinePath() string {
	return filepath.Join(".trustmod", "baseline.yml")
}

func DefaultRulesPath() string {
	return filepath.Join(".trustmod", "rules.yml")
}
