package gomod

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/mod/modfile"
)

type ParsedGoMod struct {
	ModulePath   string
	GoVersion    string
	Direct       map[string]bool
	Requirements map[string]string
	Replacements map[string]Replacement
	Tools        []string
}

func ParseGoModFile(path string) (*ParsedGoMod, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseGoMod(path, data)
}

func ParseGoMod(path string, data []byte) (*ParsedGoMod, error) {
	mf, err := modfile.Parse(path, data, nil)
	if err != nil {
		return nil, err
	}
	out := &ParsedGoMod{
		Direct:       map[string]bool{},
		Requirements: map[string]string{},
		Replacements: map[string]Replacement{},
	}
	if mf.Module != nil {
		out.ModulePath = mf.Module.Mod.Path
	}
	if mf.Go != nil {
		out.GoVersion = mf.Go.Version
	}
	for _, req := range mf.Require {
		out.Requirements[req.Mod.Path] = req.Mod.Version
		if !req.Indirect {
			out.Direct[req.Mod.Path] = true
		}
	}
	for _, rep := range mf.Replace {
		newPath := rep.New.Path
		local := isLocalReplace(newPath)
		out.Replacements[rep.Old.Path] = Replacement{
			OldPath:    rep.Old.Path,
			OldVersion: rep.Old.Version,
			NewPath:    newPath,
			NewVersion: rep.New.Version,
			Local:      local,
		}
	}
	out.Tools = parseToolDirectives(data)
	return out, nil
}

func ParseGoModBytes(data []byte) (*ParsedGoMod, error) {
	return ParseGoMod("go.mod", data)
}

func isLocalReplace(path string) bool {
	if path == "" {
		return false
	}
	if filepath.IsAbs(path) {
		return true
	}
	return strings.HasPrefix(path, ".") || strings.HasPrefix(path, "..") || strings.HasPrefix(path, "/")
}

func parseToolDirectives(data []byte) []string {
	var tools []string
	inBlock := false
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if i := strings.Index(line, "//"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		if line == "tool (" {
			inBlock = true
			continue
		}
		if inBlock && line == ")" {
			inBlock = false
			continue
		}
		if strings.HasPrefix(line, "tool ") {
			fields := strings.Fields(strings.TrimPrefix(line, "tool "))
			if len(fields) > 0 {
				tools = append(tools, fields[0])
			}
			continue
		}
		if inBlock {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				tools = append(tools, fields[0])
			}
		}
	}
	return tools
}
