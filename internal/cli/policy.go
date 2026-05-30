package cli

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/maksemen2/trustmod/internal/analyze"
	"github.com/maksemen2/trustmod/internal/config"
	"github.com/maksemen2/trustmod/internal/fsutil"
	"github.com/maksemen2/trustmod/internal/policy"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func newPolicyCommand(opts *globalOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Work with trustmod policy files",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "validate [file]",
		Short: "Validate a policy YAML file",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := opts.policyPath
			if len(args) > 0 {
				path = args[0]
			}
			p, loadedPath, loaded, warnings, err := policy.Load(path, opts.profile)
			if err != nil {
				return configExitError(err)
			}
			if !loaded {
				return configExitError(fmt.Errorf("policy file not found: %s", loadedPath))
			}
			warnings = append(warnings, policy.Validate(p)...)
			if len(warnings) == 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "policy ok: %s\n", loadedPath)
				return nil
			}
			for _, w := range warnings {
				fmt.Fprintf(cmd.OutOrStdout(), "warning: %s\n", w)
			}
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "init [file]",
		Short: "Write a starter policy YAML",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := filepath.Join(opts.defaultCWD(), config.DefaultPolicyPath())
			if len(args) > 0 {
				path = args[0]
			}
			if err := fsutil.EnsurePrivateDir(filepath.Dir(path)); err != nil {
				return userFileExitError(err)
			}
			if err := fsutil.WritePrivateFile(path, []byte(defaultPolicyYAML())); err != nil {
				return userFileExitError(err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "created: %s\n", path)
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "print-default",
		Short: "Print the built-in default policy",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := yaml.Marshal(policy.Default(opts.profile))
			if err != nil {
				return err
			}
			fmt.Fprint(cmd.OutOrStdout(), string(data))
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "explain",
		Short: "Explain how the active policy computes verdicts",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			p, loadedPath, loaded, warnings, err := policy.Load(opts.policyPath, opts.profile)
			if err != nil {
				return configExitError(err)
			}
			p = opts.applyPolicyOverrides(p)
			fmt.Fprintf(cmd.OutOrStdout(), "policy: %s\nloaded: %t\nprofile: %s\nstrict: %t\nfail_on: %v\n", loadedPath, loaded, p.Profile, p.Strict, p.FailOn)
			fmt.Fprintf(cmd.OutOrStdout(), "risk thresholds: review=%d block=%d\n", p.Thresholds.RiskReview, p.Thresholds.RiskBlock)
			fmt.Fprintf(cmd.OutOrStdout(), "transitive review threshold: %d\n", p.Thresholds.TransitiveReview)
			if len(p.Providers.Required) > 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "required providers: %v\n", p.Providers.Required)
			}
			if len(p.Providers.Disabled) > 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "disabled providers: %v\n", p.Providers.Disabled)
			}
			for _, w := range warnings {
				fmt.Fprintf(cmd.OutOrStdout(), "warning: %s\n", w)
			}
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "test [json-report]",
		Short: "Evaluate a report against the active policy",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, _, _, _, err := policy.Load(opts.policyPath, opts.profile)
			if err != nil {
				return configExitError(err)
			}
			p = opts.applyPolicyOverrides(p)
			r := analyze.ProjectReport{SchemaVersion: analyze.SchemaVersion, Verdict: analyze.VerdictAllow}
			if len(args) > 0 {
				data, err := readUserFile(args[0])
				if err != nil {
					return err
				}
				if err := json.Unmarshal(data, &r); err != nil {
					return userFileExitError(err)
				}
			}
			policy.EvaluateProject(&r, p)
			fmt.Fprintf(cmd.OutOrStdout(), "verdict: %s\nexitCodeRecommendation: %d\nfindings: %d\n", r.Verdict, r.ExitCodeRecommendation, len(r.Findings))
			if r.ExitCodeRecommendation != 0 {
				return policyExitError()
			}
			return nil
		},
	})
	return cmd
}
