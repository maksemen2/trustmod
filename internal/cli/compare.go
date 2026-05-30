package cli

import (
	"github.com/maksemen2/trustmod/internal/analyze"
	"github.com/spf13/cobra"
)

func newCompareCommand(opts *globalOptions) *cobra.Command {
	var useCase string
	var latest bool
	var includeCapabilities bool
	cmd := &cobra.Command{
		Use:   "compare <module[@version]> <module[@version]>...",
		Short: "Compare multiple Go modules under the current policy",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := opts.analyzer()
			if err != nil {
				return err
			}
			r, err := a.Compare(commandContext(cmd), analyze.CompareOptions{Modules: args, UseCase: useCase, Latest: latest, IncludeCapabilities: includeCapabilities})
			if err != nil {
				return analysisExitError(err)
			}
			return renderCompare(opts, r)
		},
	}
	cmd.Flags().StringVar(&useCase, "use-case", "", "describe the dependency use case")
	cmd.Flags().BoolVar(&latest, "latest", false, "force @latest for all compared modules")
	cmd.Flags().BoolVar(&includeCapabilities, "include-capabilities", false, "include capability details in machine-readable compare output")
	return cmd
}
