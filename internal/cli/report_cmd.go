package cli

import (
	"encoding/json"
	"fmt"

	"github.com/maksemen2/trustmod/internal/analyze"
	"github.com/spf13/cobra"
)

func newReportCommand(opts *globalOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "report <json-report>",
		Short: "Render an existing trustmod JSON report in another format",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := readUserFile(args[0])
			if err != nil {
				return err
			}
			kind, err := reportKind(data)
			if err != nil {
				return userFileExitError(err)
			}
			switch kind {
			case "project":
				var r analyze.ProjectReport
				if err := json.Unmarshal(data, &r); err != nil {
					return userFileExitError(err)
				}
				return renderProject(opts, &r)
			case "compare":
				var r analyze.CompareReport
				if err := json.Unmarshal(data, &r); err != nil {
					return userFileExitError(err)
				}
				return renderCompare(opts, &r)
			default:
				return usageExitError(fmt.Errorf("unsupported report schema %q", kind))
			}
		},
	}
}

func reportKind(data []byte) (string, error) {
	var header struct {
		SchemaVersion string            `json:"schemaVersion"`
		Entries       []json.RawMessage `json:"entries"`
		Modules       []json.RawMessage `json:"modules"`
		Verdict       *string           `json:"verdict"`
	}
	if err := json.Unmarshal(data, &header); err != nil {
		return "", err
	}
	switch header.SchemaVersion {
	case analyze.SchemaVersion, "trustmod.report/v1":
		if len(header.Entries) > 0 && len(header.Modules) == 0 && header.Verdict == nil {
			return "compare", nil
		}
		return "project", nil
	case analyze.CompareSchemaVersion:
		return "compare", nil
	case "":
		if len(header.Entries) > 0 && len(header.Modules) == 0 && header.Verdict == nil {
			return "compare", nil
		}
		return "project", nil
	default:
		return header.SchemaVersion, nil
	}
}
