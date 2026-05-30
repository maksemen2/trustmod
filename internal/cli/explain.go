package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/maksemen2/trustmod/internal/analyze"
	"github.com/maksemen2/trustmod/internal/findings"
	"github.com/spf13/cobra"
)

func newExplainCommand(_ *globalOptions) *cobra.Command {
	var reportPath string
	cmd := &cobra.Command{
		Use:   "explain <finding-code>",
		Short: "Explain a trustmod finding code",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if reportPath != "" {
				return explainFromReport(cmd, reportPath, args[0])
			}
			def, ok := findings.Lookup(strings.ToUpper(args[0]))
			if !ok {
				return usageExitError(fmt.Errorf("unknown finding code %s", args[0]))
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n\nCategory: %s\nSeverity: %s\nImpact:   %s\n\n%s\n\nRemediation:\n", def.Code, def.Title, def.Category, def.Severity, def.VerdictImpact, def.Description)
			for _, step := range def.Remediation {
				fmt.Fprintf(cmd.OutOrStdout(), "  - %s\n", step)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&reportPath, "report", "", "JSON report to explain finding IDs or module verdicts")
	return cmd
}

func explainFromReport(cmd *cobra.Command, path, query string) error {
	data, err := readUserFile(path)
	if err != nil {
		return err
	}
	var r analyze.ProjectReport
	if err := json.Unmarshal(data, &r); err != nil {
		return userFileExitError(err)
	}
	for i := range r.Findings {
		f := r.Findings[i]
		if f.ID == query || strings.EqualFold(f.Code, query) {
			printFinding(cmd, f)
			return nil
		}
	}
	for i := range r.Modules {
		m := r.Modules[i]
		if m.ModulePath == query {
			fmt.Fprintf(cmd.OutOrStdout(), "%s\n\nVerdict: %s\nRisk: %d/100\n", m.ModulePath, m.Verdict, m.RiskScore)
			if len(m.RiskContributions) > 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "\nRisk contributions:")
				for _, c := range m.RiskContributions {
					fmt.Fprintf(cmd.OutOrStdout(), "  - %s: %d (%s)\n", c.Code, c.Points, c.Reason)
				}
			}
			if len(m.Findings) > 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "\nFindings:")
				for i := range m.Findings {
					f := m.Findings[i]
					fmt.Fprintf(cmd.OutOrStdout(), "  - %s %s\n", f.Code, f.Title)
				}
			}
			return nil
		}
	}
	return usageExitError(fmt.Errorf("report item not found: %s", query))
}

func printFinding(cmd *cobra.Command, f analyze.Finding) {
	fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n\nModule: %s %s\nSeverity: %s\nConfidence: %s\nImpact: %s\nSource: %s\n\n%s\n", f.Code, f.Title, f.ModulePath, f.ModuleVersion, f.Severity, f.Confidence, f.VerdictImpact, f.Source, f.Description)
	if len(f.Evidence) > 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "\nEvidence:")
		for _, e := range f.Evidence {
			fmt.Fprintf(cmd.OutOrStdout(), "  - %s\n", e)
		}
	}
	if len(f.Remediation) > 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "\nRemediation:")
		for _, step := range f.Remediation {
			fmt.Fprintf(cmd.OutOrStdout(), "  - %s\n", step)
		}
	}
}
