package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	analyze "github.com/maksemen2/trustmod/internal/model"
)

type GraphRenderer interface {
	RenderGraph(io.Writer, analyze.DependencyGraph) error
}

func GraphRendererFor(format string) (GraphRenderer, bool) {
	switch normalizeFormat(format) {
	case "human", "text":
		return textGraphRenderer{}, true
	case "json":
		return jsonGraphRenderer{}, true
	case "dot":
		return dotGraphRenderer{}, true
	default:
		return nil, false
	}
}

type textGraphRenderer struct{}

func (textGraphRenderer) RenderGraph(w io.Writer, g analyze.DependencyGraph) error {
	for _, e := range g.Edges {
		fmt.Fprintf(w, "%s -> %s\n", e.From, e.To)
	}
	return nil
}

type jsonGraphRenderer struct{}

func (jsonGraphRenderer) RenderGraph(w io.Writer, g analyze.DependencyGraph) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(g)
}

type dotGraphRenderer struct{}

func (dotGraphRenderer) RenderGraph(w io.Writer, g analyze.DependencyGraph) error {
	var b strings.Builder
	b.WriteString("digraph deps {\n")
	for _, n := range g.Nodes {
		fmt.Fprintf(&b, "  %q;\n", n.ID)
	}
	for _, e := range g.Edges {
		fmt.Fprintf(&b, "  %q -> %q;\n", e.From, e.To)
	}
	b.WriteString("}\n")
	_, err := w.Write([]byte(b.String()))
	return err
}
