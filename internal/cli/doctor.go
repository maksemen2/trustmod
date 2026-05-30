package cli

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/maksemen2/trustmod/internal/cache"
	"github.com/maksemen2/trustmod/internal/fsutil"
	"github.com/maksemen2/trustmod/internal/git"
	"github.com/maksemen2/trustmod/internal/gomod"
	"github.com/maksemen2/trustmod/internal/policy"
	"github.com/spf13/cobra"
)

func newDoctorCommand(opts *globalOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check local trustmod prerequisites",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := commandContext(cmd)
			fmt.Fprintln(cmd.OutOrStdout(), "trustmod doctor")
			cwd := opts.defaultPath()
			if out, err := gomod.Go(ctx, cwd, opts.timeout, "version"); err == nil {
				fmt.Fprintf(cmd.OutOrStdout(), "go:      ok (%s)\n", trimNL(out))
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "go:      error (%s)\n", err)
			}
			if _, err := exec.LookPath("git"); err == nil {
				fmt.Fprintf(cmd.OutOrStdout(), "git:     ok (worktree=%s)\n", boolString(git.InsideWorktree(ctx, cwd)))
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "git:     unavailable")
			}
			if _, err := exec.LookPath("govulncheck"); err == nil {
				fmt.Fprintln(cmd.OutOrStdout(), "govulncheck: ok")
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "govulncheck: unavailable")
			}
			if opts.configLoadedPath != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "config:  ok (%s)\n", opts.configLoadedPath)
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "config:  default")
			}
			if _, loadedPath, loaded, warnings, err := policy.Load(opts.policyPath, opts.profile); err != nil {
				fmt.Fprintf(cmd.OutOrStdout(), "policy:  error (%s)\n", err)
			} else if loaded {
				fmt.Fprintf(cmd.OutOrStdout(), "policy:  ok (%s, warnings=%d)\n", loadedPath, len(warnings))
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "policy:  default (%s not found)\n", loadedPath)
			}
			if opts.noCache {
				fmt.Fprintln(cmd.OutOrStdout(), "cache:   disabled")
			} else if store, err := cache.New(opts.cacheDir, opts.cacheTTL); err == nil {
				testPath := filepath.Join(store.Dir, ".doctor-write-test")
				if writeErr := fsutil.WritePrivateFile(testPath, []byte("ok")); writeErr == nil {
					_ = os.Remove(testPath)
					fmt.Fprintf(cmd.OutOrStdout(), "cache:   writable (%s)\n", store.Dir)
				} else {
					fmt.Fprintf(cmd.OutOrStdout(), "cache:   not writable (%s)\n", writeErr)
				}
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "cache:   error (%s)\n", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "offline: %s\n", boolString(opts.offline))
			fmt.Fprintf(cmd.OutOrStdout(), "private remote: %s\n", boolString(opts.allowPrivateRemote))
			if opts.githubToken != "" || os.Getenv("GITHUB_TOKEN") != "" || os.Getenv("TRUSTMOD_GITHUB_TOKEN") != "" {
				fmt.Fprintln(cmd.OutOrStdout(), "github token: present")
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "github token: not set")
			}
			if opts.offline {
				fmt.Fprintln(cmd.OutOrStdout(), "providers: skipped (offline)")
			} else {
				for _, p := range providerProbes() {
					status := probeProvider(p.method, p.url, p.body, opts.timeout)
					fmt.Fprintf(cmd.OutOrStdout(), "%s: %s\n", p.name, status)
				}
			}
			return nil
		},
	}
}

func trimNL(s string) string {
	return strings.TrimRight(s, "\r\n")
}

type providerProbe struct {
	name   string
	method string
	url    string
	body   []byte
}

func providerProbes() []providerProbe {
	return []providerProbe{
		{name: "osv", method: "POST", url: "https://api.osv.dev/v1/querybatch", body: []byte(`{"queries":[{"package":{"ecosystem":"Go","name":"github.com/google/uuid"},"version":"v1.6.0"}]}`)},
		{name: "deps.dev", method: "GET", url: "https://api.deps.dev/v3alpha/systems/go/packages/github.com%2Fgoogle%2Fuuid/versions/v1.6.0"},
		{name: "github", method: "GET", url: "https://api.github.com/repos/google/uuid"},
		{name: "scorecard", method: "GET", url: "https://api.scorecard.dev/projects/github.com/google/uuid"},
	}
}

func probeProvider(method, url string, body []byte, timeout time.Duration) string {
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return "error (" + err.Error() + ")"
	}
	req.Header.Set("User-Agent", "trustmod/doctor")
	req.Header.Set("Accept", "application/json")
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return "unavailable (" + err.Error() + ")"
	}
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests || resp.Header.Get("X-RateLimit-Remaining") == "0" {
		return "rate_limited"
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return "ok"
	}
	return fmt.Sprintf("unavailable (%s)", resp.Status)
}
