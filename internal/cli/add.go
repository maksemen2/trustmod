package cli

import (
	"fmt"

	"github.com/maksemen2/trustmod/internal/analyze"
	"github.com/maksemen2/trustmod/internal/gomod"
	"github.com/spf13/cobra"
)

func newAddCommand(opts *globalOptions) *cobra.Command {
	var allowReview bool
	var allowBlock bool
	var dryRun bool
	var force bool
	var requireAllow bool
	var explain bool
	var keepTemp bool
	var tidy bool
	cmd := &cobra.Command{
		Use:   "add <module[@version]>",
		Short: "Review and add a Go module with go get",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			aopts := opts.analyzeOptions()
			aopts.KeepTemp = keepTemp
			a, err := analyze.NewAnalyzer(aopts)
			if err != nil {
				return err
			}
			r, err := a.CheckModule(commandContext(cmd), args[0])
			if err != nil {
				return analysisExitError(err)
			}
			verdict := r.Verdict
			if len(r.Modules) > 0 {
				verdict = r.Modules[0].Verdict
			}
			if force {
				allowBlock = true
				allowReview = true
			}
			if !dryRun && requireAllow && verdict != analyze.VerdictAllow {
				applyCommandExitRecommendation(opts, r)
				_ = renderProject(opts, r)
				return exitError{code: ExitPolicyFailure, err: fmt.Errorf("module verdict is %s; --require-allow only permits ALLOW", verdict)}
			}
			if !dryRun && verdict == analyze.VerdictBlock && !allowBlock {
				applyCommandExitRecommendation(opts, r)
				_ = renderProject(opts, r)
				return exitError{code: ExitPolicyFailure, err: fmt.Errorf("module verdict is BLOCK; pass --force to run go get anyway")}
			}
			if !dryRun && verdict == analyze.VerdictReview && !allowReview && !allowBlock {
				applyCommandExitRecommendation(opts, r)
				_ = renderProject(opts, r)
				return exitError{code: ExitPolicyFailure, err: fmt.Errorf("module verdict is REVIEW; pass --allow-review to run go get anyway")}
			}
			applyCommandExitRecommendation(opts, r)
			if explain {
				if err := renderProject(opts, r); err != nil {
					return err
				}
			} else if err := renderProject(opts, r); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "would run: go get %s\n", args[0])
			if tidy {
				fmt.Fprintln(cmd.OutOrStdout(), "would run: go mod tidy")
			}
			if dryRun {
				fmt.Fprintln(cmd.OutOrStdout(), "dry run: no changes written")
				return projectExitError(opts, r)
			}
			ctx := commandContext(cmd)
			if opts.offline {
				ctx = gomod.WithOffline(ctx)
			}
			if _, err := gomod.Go(ctx, opts.defaultPath(), opts.timeout, "get", args[0]); err != nil {
				return analysisExitError(err)
			}
			if tidy {
				if _, err := gomod.Go(ctx, opts.defaultPath(), opts.timeout, "mod", "tidy"); err != nil {
					return analysisExitError(err)
				}
			}
			fmt.Fprintln(cmd.OutOrStdout(), "added: "+args[0])
			return nil
		},
	}
	cmd.Flags().BoolVar(&allowReview, "allow-review", false, "allow go get when verdict is REVIEW")
	cmd.Flags().BoolVar(&allowBlock, "allow-block", false, "allow go get when verdict is BLOCK")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show commands without mutating go.mod")
	cmd.Flags().BoolVar(&force, "force", false, "allow go get even when verdict is BLOCK")
	cmd.Flags().BoolVar(&requireAllow, "require-allow", false, "mutate only when verdict is ALLOW")
	cmd.Flags().BoolVar(&explain, "explain", false, "print the full review before adding")
	cmd.Flags().BoolVar(&keepTemp, "keep-temp", false, "keep temporary check directory for debugging")
	cmd.Flags().BoolVar(&tidy, "tidy", false, "run go mod tidy after go get")
	return cmd
}
