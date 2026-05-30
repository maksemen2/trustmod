package govulncheck

import (
	"context"
	"os/exec"
	"time"

	"github.com/maksemen2/trustmod/internal/command"
	analyze "github.com/maksemen2/trustmod/internal/model"
)

type Runner interface {
	Run(ctx context.Context, dir string) ([]byte, string, error)
}

type CommandRunner struct {
	opts analyze.Options
}

func NewRunner(opts analyze.Options) Runner {
	return CommandRunner{opts: opts}
}

func (r CommandRunner) Run(ctx context.Context, dir string) ([]byte, string, error) {
	path := r.opts.GovulncheckPath
	if path == "" {
		found, err := exec.LookPath("govulncheck")
		if err != nil {
			return nil, analyze.ProviderStatusUnavailable, err
		}
		path = found
	}
	timeout := govulncheckTimeout(r.opts)
	out, err := command.CombinedOutput(ctx, dir, timeout, path, "-format", "json", "./...")
	if command.IsTimeout(err) {
		return out, analyze.ProviderStatusTimeout, err
	}
	if err != nil {
		return out, analyze.ProviderStatusError, err
	}
	return out, analyze.ProviderStatusOK, nil
}

func govulncheckTimeout(opts analyze.Options) time.Duration {
	if opts.GovulncheckTimeout > 0 {
		return opts.GovulncheckTimeout
	}
	return 2 * time.Minute
}
