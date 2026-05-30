package gomod

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/maksemen2/trustmod/internal/command"
)

type Module struct {
	Path       string       `json:"Path"`
	Version    string       `json:"Version"`
	Query      string       `json:"Query"`
	Versions   []string     `json:"Versions"`
	Replace    *Module      `json:"Replace"`
	Time       *time.Time   `json:"Time"`
	Update     *Module      `json:"Update"`
	Main       bool         `json:"Main"`
	Indirect   bool         `json:"Indirect"`
	Dir        string       `json:"Dir"`
	GoMod      string       `json:"GoMod"`
	GoVersion  string       `json:"GoVersion"`
	Retracted  []string     `json:"Retracted"`
	Deprecated string       `json:"Deprecated"`
	Error      *ModuleError `json:"Error"`
}

type ModuleError struct {
	Err string `json:"Err"`
}

type Package struct {
	ImportPath   string   `json:"ImportPath"`
	Name         string   `json:"Name"`
	Dir          string   `json:"Dir"`
	Standard     bool     `json:"Standard"`
	Module       *Module  `json:"Module"`
	Imports      []string `json:"Imports"`
	TestImports  []string `json:"TestImports"`
	XTestImports []string `json:"XTestImports"`
	GoFiles      []string `json:"GoFiles"`
	CgoFiles     []string `json:"CgoFiles"`
	DepsErrors   []struct {
		ImportStack []string
		Err         string
	} `json:"DepsErrors"`
	Error *struct {
		Err string
	} `json:"Error"`
}

type ListPackageOptions struct {
	IncludeTests bool
	Tags         string
}

func ListModules(ctx context.Context, dir string, timeout time.Duration) ([]Module, error) {
	out, err := GoStdout(ctx, dir, timeout, "list", "-m", "-json", "all")
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(strings.NewReader(out))
	var mods []Module
	for {
		var m Module
		if err := dec.Decode(&m); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		mods = append(mods, m)
	}
	return mods, nil
}

func ListPackages(ctx context.Context, dir string, timeout time.Duration, opts ListPackageOptions, patterns ...string) ([]Package, error) {
	if len(patterns) == 0 {
		patterns = []string{"./..."}
	}
	args := []string{"list", "-deps"}
	if opts.IncludeTests {
		args = append(args, "-test")
	}
	if strings.TrimSpace(opts.Tags) != "" {
		args = append(args, "-tags", opts.Tags)
	}
	args = append(args, "-json")
	args = append(args, patterns...)
	out, err := GoStdout(ctx, dir, timeout, args...)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(strings.NewReader(out))
	var pkgs []Package
	for {
		var p Package
		if err := dec.Decode(&p); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, nil
}

func Go(ctx context.Context, dir string, timeout time.Duration, args ...string) (string, error) {
	ctx = commandContext(ctx)
	out, err := command.CombinedOutput(ctx, dir, timeout, "go", args...)
	if command.IsTimeout(err) {
		return string(out), err
	}
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		msg = summarizeCommandOutput(msg)
		return string(out), fmt.Errorf("go %s failed: %s", strings.Join(args, " "), msg)
	}
	return string(out), nil
}

func GoStdout(ctx context.Context, dir string, timeout time.Duration, args ...string) (string, error) {
	ctx = commandContext(ctx)
	out, stderr, err := command.Output(ctx, dir, timeout, "go", args...)
	if command.IsTimeout(err) {
		return string(out), err
	}
	if err != nil {
		msg := strings.TrimSpace(string(stderr))
		if msg == "" {
			msg = strings.TrimSpace(string(out))
		}
		if msg == "" {
			msg = err.Error()
		}
		msg = summarizeCommandOutput(msg)
		return string(out), fmt.Errorf("go %s failed: %s", strings.Join(args, " "), msg)
	}
	return string(out), nil
}

func summarizeCommandOutput(msg string) string {
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return msg
	}
	lines := strings.Split(msg, "\n")
	kept := make([]string, 0, min(4, len(lines)))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "{") || strings.HasPrefix(line, "\"") || strings.HasPrefix(line, "}") {
			continue
		}
		kept = append(kept, line)
		if len(kept) >= 4 {
			break
		}
	}
	if len(kept) > 0 {
		msg = strings.Join(kept, "; ")
	}
	if len(msg) > 1000 {
		return msg[:1000] + "..."
	}
	return msg
}
