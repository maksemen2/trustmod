package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/maksemen2/trustmod/internal/config"
	"github.com/maksemen2/trustmod/internal/fsutil"
	"github.com/spf13/cobra"
)

func newInitCommand(opts *globalOptions) *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create starter trustmod config, policy, baseline, and rules files",
		RunE: func(cmd *cobra.Command, args []string) error {
			target := opts.defaultCWD()
			trustDir := filepath.Join(target, ".trustmod")
			if err := fsutil.EnsurePrivateDir(trustDir); err != nil {
				return userFileExitError(err)
			}
			files := map[string]string{
				filepath.Join(target, config.DefaultPath()):         defaultConfigYAML(),
				filepath.Join(target, config.DefaultPolicyPath()):   defaultPolicyYAML(),
				filepath.Join(target, config.DefaultBaselinePath()): defaultBaselineYAML(),
				filepath.Join(target, config.DefaultRulesPath()):    defaultRulesYAML(),
			}
			for path, data := range files {
				if !force {
					if _, err := os.Stat(path); err == nil {
						fmt.Fprintf(cmd.OutOrStdout(), "exists: %s\n", path)
						continue
					} else if !errors.Is(err, os.ErrNotExist) {
						return userFileExitError(err)
					}
				}
				if err := fsutil.WritePrivateFile(path, []byte(data)); err != nil {
					return userFileExitError(err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "created: %s\n", path)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "overwrite existing files")
	return cmd
}

func defaultConfigYAML() string {
	return `default_profile: backend-service
output: human
cache_ttl: 24h
cache_dir: ""
policy_path: .trustmod/policy.yml
baseline_path: .trustmod/baseline.yml
rules_path: .trustmod/rules.yml
timeout: 20s
govulncheck_timeout: 2m
concurrency: 8
fail_on: [BLOCK]
allow_private_remote: false
offline: false
strict_data: false
no_cache: false
include_tests: false
include_tools: false
tags: ""
no_color: false
govulncheck_path: ""
providers:
  osv: true
  deps.dev: true
  github: true
  scorecard: true
  govulncheck: false
`
}

func defaultPolicyYAML() string {
	return `version: 1
profile: backend-service
fail_on:
  - BLOCK
licenses:
  banned:
    - AGPL-3.0
    - GPL-3.0
thresholds:
  risk_review: 30
  risk_block: 101
  transitive_review: 20
providers:
  required: []
deny:
  modules: []
allow:
  modules: []
  finding_codes: []
profiles:
  strict:
    strict: true
    fail_on: [BLOCK, REVIEW]
    thresholds:
      risk_review: 20
      risk_block: 80
      transitive_review: 10
    providers:
      required: [osv]
`
}

func defaultBaselineYAML() string {
	return fmt.Sprintf("version: 1\ncreated_at: %q\naccepted_findings: []\naccepted_modules: []\n", time.Now().UTC().Format(time.RFC3339))
}

func defaultRulesYAML() string {
	return `version: 1
rules:
  - id: org-shell-installer
    code: TM-CUSTOM-001
    title: Shell installer command
    description: Custom rule matched a shell command that downloads remote content.
    severity: high
    verdict: REVIEW
    confidence: high
    remediation:
      - Review the installer command and prefer a pinned, checksummed artifact.
    match:
      require_all: true
      selectors:
        - os/exec.Command
      strings:
        - curl
        - "| sh"
`
}
