package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/maksemen2/trustmod/internal/analyze"
	"github.com/maksemen2/trustmod/internal/baseline"
	"github.com/maksemen2/trustmod/internal/fsutil"
	"github.com/maksemen2/trustmod/internal/policy"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func newAuditCommand(opts *globalOptions) *cobra.Command {
	var onlyDirect bool
	var onlyNew bool
	var updateBaseline bool
	var sarifOutput string
	var markdownOutput string
	cmd := &cobra.Command{
		Use:   "audit [packages...]",
		Short: "Audit dependencies in the current Go module or workspace",
		RunE: func(cmd *cobra.Command, args []string) error {
			path, patterns := auditTarget(opts, args)
			a, err := opts.analyzer()
			if err != nil {
				return err
			}
			r, err := a.AuditPackages(commandContext(cmd), path, patterns)
			if err != nil {
				return analysisExitError(err)
			}
			if onlyDirect || onlyNew {
				filterProjectReport(r, onlyDirect, onlyNew)
				reevaluateProject(opts, r)
			}
			updatedBaseline := 0
			if updateBaseline {
				n, err := writeBaselineFromReport(opts.baselinePath, r)
				if err != nil {
					return configExitError(err)
				}
				updatedBaseline = n
			}
			if sarifOutput != "" {
				if err := writeProjectArtifact(sarifOutput, "sarif", r); err != nil {
					return err
				}
			}
			if markdownOutput != "" {
				if err := writeProjectArtifact(markdownOutput, "markdown", r); err != nil {
					return err
				}
			}
			applyCommandExitRecommendation(opts, r)
			if err := renderProject(opts, r); err != nil {
				return err
			}
			if updateBaseline && opts.format == "human" && opts.outFile == "" {
				fmt.Fprintf(cmd.OutOrStdout(), "updated baseline: %s (%d accepted findings)\n", baselinePath(opts), updatedBaseline)
			}
			return projectExitError(opts, r)
		},
	}
	cmd.Flags().BoolVar(&onlyDirect, "only-direct", false, "show only direct module findings")
	cmd.Flags().BoolVar(&onlyNew, "only-new", false, "show only findings marked new in diff")
	cmd.Flags().BoolVar(&updateBaseline, "update-baseline", false, "write current non-allow findings to the baseline")
	cmd.Flags().StringVar(&sarifOutput, "sarif-output", "", "write a SARIF report to this path")
	cmd.Flags().StringVar(&markdownOutput, "markdown-output", "", "write a Markdown report to this path")
	return cmd
}

func auditTarget(opts *globalOptions, args []string) (string, []string) {
	if len(args) == 1 && looksProjectRoot(args[0]) {
		return args[0], nil
	}
	return opts.defaultPath(), append([]string(nil), args...)
}

func looksProjectRoot(path string) bool {
	if path == "" || strings.Contains(path, "...") {
		return false
	}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return false
	}
	for _, name := range []string{"go.mod", "go.work"} {
		if _, err := os.Stat(filepath.Join(path, name)); err == nil {
			return true
		}
	}
	return false
}

func filterProjectReport(pr *analyze.ProjectReport, onlyDirect, onlyNew bool) {
	if pr == nil || (!onlyDirect && !onlyNew) {
		return
	}
	modules := pr.Modules[:0]
	for i := range pr.Modules {
		m := pr.Modules[i]
		if onlyDirect && !m.Direct {
			continue
		}
		if onlyNew && !moduleHasNewFinding(m) {
			continue
		}
		modules = append(modules, m)
	}
	pr.Modules = modules
	findings := pr.Findings[:0]
	for i := range pr.Findings {
		f := pr.Findings[i]
		if onlyDirect && !f.Direct {
			continue
		}
		if onlyNew && !f.NewInDiff {
			continue
		}
		findings = append(findings, f)
	}
	pr.Findings = findings
}

func moduleHasNewFinding(m analyze.ModuleReport) bool {
	for i := range m.Findings {
		f := m.Findings[i]
		if f.NewInDiff {
			return true
		}
	}
	return false
}

func writeBaselineFromReport(path string, r *analyze.ProjectReport) (int, error) {
	if path == "" {
		path = baseline.DefaultPath
	}
	b := baseline.Empty()
	for i := range r.Findings {
		f := r.Findings[i]
		if f.ModulePath == "" || f.VerdictImpact == analyze.VerdictAllow {
			continue
		}
		b.AcceptedFindings = append(b.AcceptedFindings, baseline.AcceptedFinding{
			Module:     f.ModulePath,
			Version:    f.ModuleVersion,
			Code:       f.Code,
			Reason:     "Accepted from trustmod audit --update-baseline. Review before committing.",
			ApprovedBy: "trustmod-user",
		})
	}
	data, err := yaml.Marshal(b)
	if err != nil {
		return 0, err
	}
	if err := fsutil.WritePrivateFileCreatingDir(path, data); err != nil {
		return 0, err
	}
	return len(b.AcceptedFindings), nil
}

func reevaluateProject(opts *globalOptions, r *analyze.ProjectReport) {
	pol, _, _, _, err := policy.Load(opts.policyPath, opts.profile)
	if err != nil {
		return
	}
	if len(opts.failOn) > 0 {
		pol.FailOn = nil
		for _, v := range opts.failOn {
			v = strings.ToUpper(strings.TrimSpace(v))
			if v != "" {
				pol.FailOn = append(pol.FailOn, v)
			}
		}
	}
	policy.EvaluateProject(r, pol)
}
