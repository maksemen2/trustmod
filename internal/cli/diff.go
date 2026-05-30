package cli

import (
	"github.com/maksemen2/trustmod/internal/analyze"
	"github.com/spf13/cobra"
)

func newDiffCommand(opts *globalOptions) *cobra.Command {
	var base string
	var baseRef string
	var head string
	var deep bool
	var onlyNew bool
	var changedFilesOnly bool
	var commentFormat string
	cmd := &cobra.Command{
		Use:   "diff [path]",
		Short: "Review dependency changes against a git base ref",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := opts.defaultPath()
			if len(args) > 0 {
				path = args[0]
			}
			a, err := opts.analyzer()
			if err != nil {
				return err
			}
			if baseRef != "" {
				base = baseRef
			}
			_ = commentFormat
			r, err := a.Diff(commandContext(cmd), analyzeDiff(path, base, head, deep, onlyNew, changedFilesOnly))
			if err != nil {
				return analysisExitError(err)
			}
			if onlyNew {
				filterProjectReport(r, false, true)
				reevaluateProject(opts, r)
			}
			applyCommandExitRecommendation(opts, r)
			if err := renderProject(opts, r); err != nil {
				return err
			}
			return projectExitError(opts, r)
		},
	}
	cmd.Flags().StringVar(&base, "base", "main", "git base ref")
	cmd.Flags().StringVar(&baseRef, "base-ref", "", "alias for --base")
	cmd.Flags().StringVar(&head, "head", "HEAD", "git head ref")
	cmd.Flags().BoolVar(&deep, "deep", false, "run full current-project analysis and mark dependency deltas")
	cmd.Flags().BoolVar(&onlyNew, "only-new", false, "show only findings marked new in diff")
	cmd.Flags().StringVar(&commentFormat, "comment-format", "github", "markdown comment style")
	cmd.Flags().BoolVar(&changedFilesOnly, "changed-files-only", false, "skip analysis when changed files contain no Go module files")
	return cmd
}

func analyzeDiff(path, base, head string, deep, onlyNew, changedFilesOnly bool) analyze.DiffOptions {
	return analyze.DiffOptions{Path: path, Base: base, Head: head, Deep: deep, OnlyNew: onlyNew, ChangedFilesOnly: changedFilesOnly}
}
