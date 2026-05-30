package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newVersionCommand(opts *globalOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print trustmod version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "trustmod %s\ncommit: %s\ndate: %s\n", opts.build.Version, opts.build.Commit, opts.build.Date)
		},
	}
}
