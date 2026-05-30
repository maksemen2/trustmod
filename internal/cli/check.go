package cli

import (
	"github.com/maksemen2/trustmod/internal/analyze"
	"github.com/spf13/cobra"
)

func newCheckCommand(opts *globalOptions) *cobra.Command {
	var compareTo string
	var latest bool
	cmd := &cobra.Command{
		Use:   "check <module[@version]>",
		Short: "Review a Go module before adding it",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := opts.analyzer()
			if err != nil {
				return err
			}
			spec := args[0]
			if latest {
				module, _ := analyze.ModuleSpecParts(spec)
				spec = module + "@latest"
			}
			r, err := a.CheckModule(commandContext(cmd), spec)
			if err != nil {
				return analysisExitError(err)
			}
			applyCommandExitRecommendation(opts, r)
			if err := renderProject(opts, r); err != nil {
				return err
			}
			if compareTo != "" {
				modules := append([]string{spec}, splitCSV(compareTo)...)
				cr, err := a.Compare(commandContext(cmd), analyze.CompareOptions{Modules: modules})
				if err != nil {
					return analysisExitError(err)
				}
				if err := renderCompare(opts, cr); err != nil {
					return err
				}
			}
			return projectExitError(opts, r)
		},
	}
	cmd.Flags().StringVar(&compareTo, "compare-to", "", "comma-separated modules to compare against")
	cmd.Flags().BoolVar(&latest, "latest", false, "force @latest for the checked module")
	return cmd
}
