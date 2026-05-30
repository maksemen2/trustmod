package cli

import (
	"fmt"

	"github.com/maksemen2/trustmod/internal/cache"
	"github.com/spf13/cobra"
)

func newCacheCommand(opts *globalOptions) *cobra.Command {
	cmd := &cobra.Command{Use: "cache", Short: "Inspect or clear trustmod cache"}
	cmd.AddCommand(&cobra.Command{
		Use:   "path",
		Short: "Print cache directory",
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := opts.cacheDir
			if dir == "" {
				dir = cache.DefaultDir()
			}
			fmt.Fprintln(cmd.OutOrStdout(), dir)
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "stats",
		Short: "Print cache entry count and size",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := cache.New(opts.cacheDir, opts.cacheTTL)
			if err != nil {
				return err
			}
			files, bytes, err := store.Stats()
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "cache: %s\nentries: %d\nbytes: %d\n", store.Dir, files, bytes)
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:     "clear",
		Aliases: []string{"clean"},
		Short:   "Remove cached provider responses",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := cache.New(opts.cacheDir, opts.cacheTTL)
			if err != nil {
				return err
			}
			if err := store.Clean(); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "cache cleared")
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "prune",
		Short: "Remove expired cached provider responses",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := cache.New(opts.cacheDir, opts.cacheTTL)
			if err != nil {
				return err
			}
			removed, err := store.Prune()
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "cache pruned: %d removed\n", removed)
			return nil
		},
	})
	return cmd
}
