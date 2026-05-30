package githubaction

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"gopkg.in/yaml.v3"
)

type actionMetadata struct {
	Name        string                  `yaml:"name"`
	Description string                  `yaml:"description"`
	Inputs      map[string]actionInput  `yaml:"inputs"`
	Outputs     map[string]actionOutput `yaml:"outputs"`
	Runs        actionRuns              `yaml:"runs"`
}

type actionInput struct {
	Description string `yaml:"description"`
	Required    bool   `yaml:"required"`
	Default     string `yaml:"default"`
}

type actionOutput struct {
	Description string `yaml:"description"`
	Value       string `yaml:"value"`
}

type actionRuns struct {
	Using string       `yaml:"using"`
	Steps []actionStep `yaml:"steps"`
}

type actionStep struct {
	ID    string            `yaml:"id"`
	Name  string            `yaml:"name"`
	If    string            `yaml:"if"`
	Shell string            `yaml:"shell"`
	Run   string            `yaml:"run"`
	Uses  string            `yaml:"uses"`
	Env   map[string]string `yaml:"env"`
}

func TestActionMetadata(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "action.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var meta actionMetadata
	if err := yaml.Unmarshal(data, &meta); err != nil {
		t.Fatal(err)
	}
	if meta.Name == "" || meta.Description == "" {
		t.Fatal("action metadata must include name and description")
	}
	if meta.Runs.Using != "composite" {
		t.Fatalf("runs.using = %q, want composite", meta.Runs.Using)
	}
	if len(meta.Runs.Steps) == 0 {
		t.Fatal("composite action must define at least one step")
	}
	if len(meta.Inputs) == 0 {
		t.Fatal("action must define inputs")
	}

	stepIDs := map[string]bool{}
	for i, step := range meta.Runs.Steps {
		if step.Name == "" {
			t.Fatalf("step %d is missing a name", i)
		}
		if step.Run != "" && step.Shell == "" {
			t.Fatalf("step %q runs a script but does not set shell", step.Name)
		}
		if step.ID != "" {
			if stepIDs[step.ID] {
				t.Fatalf("duplicate step id %q", step.ID)
			}
			stepIDs[step.ID] = true
		}
		assertKnownInputRefs(t, meta.Inputs, step.If)
		for _, value := range step.Env {
			assertKnownInputRefs(t, meta.Inputs, value)
		}
	}
	for outputName, output := range meta.Outputs {
		if output.Description == "" || output.Value == "" {
			t.Fatalf("output %q must include description and value", outputName)
		}
		assertKnownStepOutputRef(t, stepIDs, output.Value)
	}
}

func assertKnownInputRefs(t *testing.T, inputs map[string]actionInput, expr string) {
	t.Helper()
	for _, match := range dotInputRefPattern.FindAllStringSubmatch(expr, -1) {
		if _, ok := inputs[match[1]]; !ok {
			t.Fatalf("unknown action input reference %q in %q", match[1], expr)
		}
	}
	for _, match := range bracketInputRefPattern.FindAllStringSubmatch(expr, -1) {
		if _, ok := inputs[match[1]]; !ok {
			t.Fatalf("unknown action input reference %q in %q", match[1], expr)
		}
	}
}

func assertKnownStepOutputRef(t *testing.T, stepIDs map[string]bool, expr string) {
	t.Helper()
	matches := stepOutputRefPattern.FindAllStringSubmatch(expr, -1)
	if len(matches) == 0 {
		t.Fatalf("output value %q must reference a step output", expr)
	}
	for _, match := range matches {
		if !stepIDs[match[1]] {
			t.Fatalf("unknown step output reference %q in %q", match[1], expr)
		}
	}
}

var (
	dotInputRefPattern     = regexp.MustCompile(`inputs\.([A-Za-z_][A-Za-z0-9_-]*)`)
	bracketInputRefPattern = regexp.MustCompile(`inputs\[['"]([^'"]+)['"]\]`)
	stepOutputRefPattern   = regexp.MustCompile(`steps\.([A-Za-z_][A-Za-z0-9_-]*)\.outputs(?:\.|\[['"])`)
)
