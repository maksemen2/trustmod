package gomod

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

type Project struct {
	Root          string
	Mode          string
	GoModPath     string
	GoWorkPath    string
	ModulePath    string
	GoVersion     string
	MainModules   []string
	Direct        map[string]bool
	Requirements  map[string]string
	Replacements  map[string]Replacement
	Tools         map[string]bool
	WorkspaceDirs []string
}

type Replacement struct {
	OldPath    string
	OldVersion string
	NewPath    string
	NewVersion string
	Local      bool
}

func FindProject(start string) (*Project, error) {
	if start == "" {
		start = "."
	}
	if strings.HasSuffix(start, string(filepath.Separator)+"...") || strings.HasSuffix(start, "/...") {
		start = strings.TrimSuffix(strings.TrimSuffix(start, "..."), string(filepath.Separator))
		start = strings.TrimSuffix(start, "/")
	}
	abs, err := filepath.Abs(start)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(abs)
	if err == nil && !info.IsDir() {
		abs = filepath.Dir(abs)
	}
	dir := abs
	for {
		work := filepath.Join(dir, "go.work")
		mod := filepath.Join(dir, "go.mod")
		if fileExists(work) {
			p, err := fromWorkspace(dir, work)
			if err != nil {
				return nil, err
			}
			return p, nil
		}
		if fileExists(mod) {
			p, err := fromModule(dir, mod)
			if err != nil {
				return nil, err
			}
			return p, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return &Project{Root: abs, Mode: "detached", Direct: map[string]bool{}, Requirements: map[string]string{}, Replacements: map[string]Replacement{}, Tools: map[string]bool{}}, nil
		}
		dir = parent
	}
}

func fromModule(root, modPath string) (*Project, error) {
	parsed, err := ParseGoModFile(modPath)
	if err != nil {
		return nil, err
	}
	return &Project{
		Root:         root,
		Mode:         "single-module",
		GoModPath:    modPath,
		ModulePath:   parsed.ModulePath,
		GoVersion:    parsed.GoVersion,
		MainModules:  []string{parsed.ModulePath},
		Direct:       parsed.Direct,
		Requirements: parsed.Requirements,
		Replacements: parsed.Replacements,
		Tools:        toolSet(parsed.Tools),
	}, nil
}

func fromWorkspace(root, workPath string) (*Project, error) {
	dirs, err := ParseGoWorkFile(workPath)
	if err != nil {
		return nil, err
	}
	p := &Project{
		Root:          root,
		Mode:          "workspace",
		GoWorkPath:    workPath,
		Direct:        map[string]bool{},
		Requirements:  map[string]string{},
		Replacements:  map[string]Replacement{},
		Tools:         map[string]bool{},
		WorkspaceDirs: dirs,
	}
	for _, d := range dirs {
		modPath := filepath.Join(root, filepath.FromSlash(d), "go.mod")
		if !fileExists(modPath) {
			continue
		}
		parsed, err := ParseGoModFile(modPath)
		if err != nil {
			return nil, err
		}
		p.MainModules = append(p.MainModules, parsed.ModulePath)
		if p.GoVersion == "" {
			p.GoVersion = parsed.GoVersion
		}
		for k, v := range parsed.Direct {
			p.Direct[k] = v
		}
		for k, v := range parsed.Requirements {
			p.Requirements[k] = v
		}
		for k, v := range parsed.Replacements {
			p.Replacements[k] = v
		}
		for _, tool := range parsed.Tools {
			p.Tools[tool] = true
		}
	}
	if len(p.MainModules) == 0 {
		return nil, errors.New("go.work did not reference any readable go.mod files")
	}
	return p, nil
}

func toolSet(tools []string) map[string]bool {
	out := map[string]bool{}
	for _, tool := range tools {
		if tool != "" {
			out[tool] = true
		}
	}
	return out
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
