package cli

import (
	"fmt"
	"io"

	"github.com/maksemen2/trustmod/internal/analyze"
	"github.com/maksemen2/trustmod/internal/collect"
	"github.com/maksemen2/trustmod/internal/gomod"
	"github.com/maksemen2/trustmod/internal/report"
	"github.com/spf13/cobra"
)

func newGraphCommand(opts *globalOptions) *cobra.Command {
	var module string
	cmd := &cobra.Command{
		Use:   "graph [path]",
		Short: "Print module dependency graph",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := opts.defaultPath()
			if len(args) > 0 {
				path = args[0]
			}
			ctx := commandContext(cmd)
			if opts.offline {
				ctx = gomod.WithOffline(ctx)
			}
			g, err := gomod.ModGraph(ctx, path, opts.timeout)
			if err != nil {
				return analysisExitError(err)
			}
			if module != "" {
				g = filterGraph(g, module)
			}
			renderer, ok := report.GraphRendererFor(opts.format)
			if !ok {
				return usageExitError(fmt.Errorf("format %q is not supported for graph", opts.format))
			}
			return renderToOutput(opts.outFile, func(w io.Writer) error {
				return renderer.RenderGraph(w, g)
			})
		},
	}
	cmd.Flags().StringVar(&module, "module", "", "show only edges touching this module")
	return cmd
}

func filterGraph(g analyze.DependencyGraph, module string) analyze.DependencyGraph {
	seenNodes := collect.NewSet[string]()
	out := analyze.DependencyGraph{Notes: append([]string(nil), g.Notes...)}
	for _, e := range g.Edges {
		if e.From != module && e.To != module {
			continue
		}
		out.Edges = append(out.Edges, e)
		seenNodes.Add(e.From)
		seenNodes.Add(e.To)
	}
	for _, n := range g.Nodes {
		if seenNodes.Has(n.ID) {
			out.Nodes = append(out.Nodes, n)
		}
	}
	return out
}
