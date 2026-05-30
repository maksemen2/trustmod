package cli

import (
	"fmt"
	"time"

	"github.com/maksemen2/trustmod/internal/baseline"
	"github.com/maksemen2/trustmod/internal/collect"
	"github.com/maksemen2/trustmod/internal/fsutil"
	"github.com/maksemen2/trustmod/internal/textutil"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func newBaselineCommand(opts *globalOptions) *cobra.Command {
	cmd := &cobra.Command{Use: "baseline", Short: "Work with trustmod baselines"}
	cmd.AddCommand(&cobra.Command{
		Use:   "create [path]",
		Short: "Create a baseline from current audit findings",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			outPath := baselinePath(opts)
			if len(args) > 0 {
				outPath = args[0]
			}
			a, err := opts.analyzer()
			if err != nil {
				return err
			}
			r, err := a.Audit(commandContext(cmd), opts.defaultPath())
			if err != nil {
				return err
			}
			b := baseline.Baseline{Version: 1, CreatedAt: time.Now().UTC().Format(time.RFC3339)}
			for i := range r.Findings {
				f := r.Findings[i]
				if f.ModulePath == "" || f.VerdictImpact == "ALLOW" {
					continue
				}
				b.AcceptedFindings = append(b.AcceptedFindings, baseline.AcceptedFinding{
					Module:     f.ModulePath,
					Version:    f.ModuleVersion,
					Code:       f.Code,
					Reason:     "Accepted from existing baseline creation. Review before committing.",
					ApprovedBy: "trustmod-user",
				})
			}
			data, err := yaml.Marshal(b)
			if err != nil {
				return err
			}
			if err := fsutil.WritePrivateFileCreatingDir(outPath, data); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "created: %s (%d accepted findings)\n", outPath, len(b.AcceptedFindings))
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "list [file]",
		Short: "List baseline entries",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := opts.baselinePath
			if len(args) > 0 {
				path = args[0]
			}
			b, loadedPath, loaded, err := baseline.Load(path)
			if err != nil {
				return configExitError(err)
			}
			if !loaded {
				return configExitError(fmt.Errorf("baseline file not found: %s", loadedPath))
			}
			fmt.Fprintf(cmd.OutOrStdout(), "baseline: %s\naccepted findings: %d\naccepted modules: %d\n", loadedPath, len(b.AcceptedFindings), len(b.AcceptedModules))
			for _, entry := range b.AcceptedFindings {
				fmt.Fprintf(cmd.OutOrStdout(), "finding: module=%s version=%s code=%s approved_by=%s expires=%s reason=%s\n", entry.Module, textutil.DashIfEmpty(entry.Version), entry.Code, textutil.DashIfEmpty(entry.ApprovedBy), textutil.DashIfEmpty(entry.Expires), entry.Reason)
			}
			for _, entry := range b.AcceptedModules {
				fmt.Fprintf(cmd.OutOrStdout(), "module: module=%s version=%s approved_by=%s expires=%s reason=%s\n", entry.Module, textutil.DashIfEmpty(entry.Version), textutil.DashIfEmpty(entry.ApprovedBy), textutil.DashIfEmpty(entry.Expires), entry.Reason)
			}
			return nil
		},
	})
	cmd.AddCommand(newBaselineApproveCommand(opts))
	cmd.AddCommand(newBaselineRevokeCommand(opts))
	cmd.AddCommand(newBaselinePruneCommand(opts))
	return cmd
}

func newBaselineApproveCommand(opts *globalOptions) *cobra.Command {
	var version, code, reason, approvedBy, expires string
	var moduleWide bool
	cmd := &cobra.Command{
		Use:   "approve <module>",
		Short: "Add a baseline exception",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := baselinePath(opts)
			b, _, _, err := baseline.Load(path)
			if err != nil {
				return configExitError(err)
			}
			if reason == "" {
				reason = "Accepted by trustmod baseline approve"
			}
			if approvedBy == "" {
				approvedBy = "trustmod-user"
			}
			if code != "" && !moduleWide {
				entry := baseline.AcceptedFinding{Module: args[0], Version: version, Code: code, Reason: reason, ApprovedBy: approvedBy, Expires: expires}
				b.AcceptedFindings = upsertAcceptedFinding(b.AcceptedFindings, entry)
				if err := saveBaseline(path, b); err != nil {
					return configExitError(err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "approved finding: %s %s %s\n", args[0], version, code)
				return nil
			}
			entry := baseline.AcceptedModule{Module: args[0], Version: version, Reason: reason, ApprovedBy: approvedBy, Expires: expires}
			b.AcceptedModules = upsertAcceptedModule(b.AcceptedModules, entry)
			if err := saveBaseline(path, b); err != nil {
				return configExitError(err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "approved module: %s %s\n", args[0], version)
			return nil
		},
	}
	cmd.Flags().StringVar(&version, "version", "", "module version constraint")
	cmd.Flags().StringVar(&code, "code", "", "finding code to approve")
	cmd.Flags().StringVar(&reason, "reason", "", "approval reason")
	cmd.Flags().StringVar(&approvedBy, "approved-by", "", "approver name")
	cmd.Flags().StringVar(&expires, "expires", "", "expiry date, YYYY-MM-DD or RFC3339")
	cmd.Flags().BoolVar(&moduleWide, "module", false, "approve the module instead of a specific finding")
	return cmd
}

func newBaselineRevokeCommand(opts *globalOptions) *cobra.Command {
	var version, code string
	cmd := &cobra.Command{
		Use:   "revoke <module>",
		Short: "Remove baseline exceptions",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := baselinePath(opts)
			b, _, loaded, err := baseline.Load(path)
			if err != nil {
				return configExitError(err)
			}
			if !loaded {
				return configExitError(fmt.Errorf("baseline file not found: %s", path))
			}
			beforeFindings := len(b.AcceptedFindings)
			beforeModules := len(b.AcceptedModules)
			b.AcceptedFindings = revokeAcceptedFindings(b.AcceptedFindings, args[0], version, code)
			b.AcceptedModules = revokeAcceptedModules(b.AcceptedModules, args[0], version, code)
			if err := saveBaseline(path, b); err != nil {
				return configExitError(err)
			}
			removed := beforeFindings - len(b.AcceptedFindings) + beforeModules - len(b.AcceptedModules)
			fmt.Fprintf(cmd.OutOrStdout(), "revoked: %d\n", removed)
			return nil
		},
	}
	cmd.Flags().StringVar(&version, "version", "", "module version constraint")
	cmd.Flags().StringVar(&code, "code", "", "finding code to revoke")
	return cmd
}

func newBaselinePruneCommand(opts *globalOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "prune [file]",
		Short: "Remove expired baseline exceptions",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := baselinePath(opts)
			if len(args) > 0 {
				path = args[0]
			}
			b, _, loaded, err := baseline.Load(path)
			if err != nil {
				return configExitError(err)
			}
			if !loaded {
				return configExitError(fmt.Errorf("baseline file not found: %s", path))
			}
			now := time.Now().UTC()
			before := len(b.AcceptedFindings) + len(b.AcceptedModules)
			b.AcceptedFindings = keepActiveFindings(b.AcceptedFindings, now)
			b.AcceptedModules = keepActiveModules(b.AcceptedModules, now)
			if err := saveBaseline(path, b); err != nil {
				return configExitError(err)
			}
			after := len(b.AcceptedFindings) + len(b.AcceptedModules)
			fmt.Fprintf(cmd.OutOrStdout(), "pruned: %d\n", before-after)
			return nil
		},
	}
}

func baselinePath(opts *globalOptions) string {
	if opts.baselinePath != "" {
		return opts.baselinePath
	}
	return baseline.DefaultPath
}

func saveBaseline(path string, b baseline.Baseline) error {
	if b.Version == 0 {
		b.Version = 1
	}
	if b.CreatedAt == "" {
		b.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	data, err := yaml.Marshal(b)
	if err != nil {
		return err
	}
	return fsutil.WritePrivateFileCreatingDir(path, data)
}

func upsertAcceptedFinding(entries []baseline.AcceptedFinding, entry baseline.AcceptedFinding) []baseline.AcceptedFinding {
	return collect.Upsert(entries, entry, func(existing, incoming baseline.AcceptedFinding) bool {
		return existing.Module == incoming.Module && existing.Version == incoming.Version && existing.Code == incoming.Code
	})
}

func upsertAcceptedModule(entries []baseline.AcceptedModule, entry baseline.AcceptedModule) []baseline.AcceptedModule {
	return collect.Upsert(entries, entry, func(existing, incoming baseline.AcceptedModule) bool {
		return existing.Module == incoming.Module && existing.Version == incoming.Version
	})
}

func revokeAcceptedFindings(entries []baseline.AcceptedFinding, module, version, code string) []baseline.AcceptedFinding {
	return collect.FilterInPlace(entries, func(e baseline.AcceptedFinding) bool {
		return e.Module != module || version != "" && e.Version != version || code != "" && e.Code != code
	})
}

func revokeAcceptedModules(entries []baseline.AcceptedModule, module, version, code string) []baseline.AcceptedModule {
	if code != "" {
		return entries
	}
	return collect.FilterInPlace(entries, func(e baseline.AcceptedModule) bool {
		return e.Module != module || version != "" && e.Version != version
	})
}

func keepActiveFindings(entries []baseline.AcceptedFinding, now time.Time) []baseline.AcceptedFinding {
	b := baseline.Baseline{AcceptedFindings: entries}
	expired := collect.NewSet(b.ExpiredFindings(now)...)
	return collect.FilterInPlace(entries, func(e baseline.AcceptedFinding) bool {
		return !expired.Has(e)
	})
}

func keepActiveModules(entries []baseline.AcceptedModule, now time.Time) []baseline.AcceptedModule {
	b := baseline.Baseline{AcceptedModules: entries}
	expired := collect.NewSet(b.ExpiredModules(now)...)
	return collect.FilterInPlace(entries, func(e baseline.AcceptedModule) bool {
		return !expired.Has(e)
	})
}
