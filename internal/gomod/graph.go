package gomod

import (
	"context"
	"strings"
	"time"

	"github.com/maksemen2/trustmod/internal/collect"
	analyze "github.com/maksemen2/trustmod/internal/model"
)

func ModGraph(ctx context.Context, dir string, timeout time.Duration) (analyze.DependencyGraph, error) {
	project, projectErr := FindProject(dir)
	out, err := Go(ctx, dir, timeout, "mod", "graph")
	if err != nil {
		return analyze.DependencyGraph{}, err
	}
	var direct map[string]bool
	var private PrivateMatcher
	if projectErr == nil && project != nil {
		direct = project.Direct
		for _, main := range project.MainModules {
			direct[main] = true
		}
		private = NewPrivateMatcher(project.MainModules)
	}
	nodeSeen := collect.NewSet[string]()
	var graph analyze.DependencyGraph
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		fromPath, fromVersion := splitNode(fields[0])
		toPath, toVersion := splitNode(fields[1])
		if nodeSeen.Add(fields[0]) {
			graph.Nodes = append(graph.Nodes, graphNode(fromPath, fromVersion, direct, private))
		}
		if nodeSeen.Add(fields[1]) {
			graph.Nodes = append(graph.Nodes, graphNode(toPath, toVersion, direct, private))
		}
		graph.Edges = append(graph.Edges, analyze.GraphEdge{From: fromPath, To: toPath, Type: "module-requires"})
	}
	return graph, nil
}

func graphNode(path, version string, direct map[string]bool, private PrivateMatcher) analyze.GraphNode {
	return analyze.GraphNode{
		ID:      path,
		Version: version,
		Direct:  direct[path],
		Private: private.IsPrivate(path),
	}
}

func splitNode(s string) (string, string) {
	if i := strings.LastIndex(s, "@"); i > 0 {
		return s[:i], s[i+1:]
	}
	return s, ""
}
