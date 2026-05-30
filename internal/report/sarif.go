package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/maksemen2/trustmod/internal/findings"
	analyze "github.com/maksemen2/trustmod/internal/model"
	"github.com/maksemen2/trustmod/internal/pathutil"
)

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	ShortDescription sarifMessage    `json:"shortDescription"`
	FullDescription  sarifMessage    `json:"fullDescription"`
	Help             sarifMessage    `json:"help"`
	Properties       sarifProperties `json:"properties"`
}

type sarifProperties struct {
	Category string `json:"category"`
	Severity string `json:"severity"`
}

type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	Level      string          `json:"level"`
	Message    sarifMessage    `json:"message"`
	Locations  []sarifLocation `json:"locations,omitempty"`
	Properties map[string]any  `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine,omitempty"`
}

func SARIFProject(r *analyze.ProjectReport) ([]byte, error) {
	defs := findings.All()
	rules := make([]sarifRule, 0, len(defs))
	ruleIDs := map[string]bool{}
	for i := range defs {
		def := defs[i]
		rules = append(rules, sarifRule{
			ID:               def.Code,
			Name:             def.Title,
			ShortDescription: sarifMessage{Text: def.Title},
			FullDescription:  sarifMessage{Text: def.Description},
			Help:             sarifMessage{Text: join(def.Remediation)},
			Properties:       sarifProperties{Category: def.Category, Severity: string(def.Severity)},
		})
		ruleIDs[def.Code] = true
	}
	for i := range r.Findings {
		f := r.Findings[i]
		if f.Code == "" || ruleIDs[f.Code] {
			continue
		}
		rules = append(rules, sarifRule{
			ID:               f.Code,
			Name:             f.Title,
			ShortDescription: sarifMessage{Text: f.Title},
			FullDescription:  sarifMessage{Text: f.Description},
			Help:             sarifMessage{Text: join(f.Remediation)},
			Properties:       sarifProperties{Category: f.Category, Severity: string(f.Severity)},
		})
		ruleIDs[f.Code] = true
	}
	results := make([]sarifResult, 0, len(r.Findings))
	capLocations := capabilityLocations(r.ProjectRoot, r.Modules)
	for i := range r.Findings {
		f := r.Findings[i]
		res := sarifResult{
			RuleID:  f.Code,
			Level:   findings.SARIFLevel(f.Severity),
			Message: sarifMessage{Text: f.Title + ": " + f.Description},
			Properties: map[string]any{
				"verdictImpact": f.VerdictImpact,
				"confidence":    f.Confidence,
				"modulePath":    f.ModulePath,
				"moduleVersion": f.ModuleVersion,
			},
		}
		if f.File != "" {
			loc := sarifLocation{PhysicalLocation: sarifPhysicalLocation{ArtifactLocation: sarifArtifactLocation{URI: sarifURI(r.ProjectRoot, f.File, "")}}}
			if f.Line > 0 {
				loc.PhysicalLocation.Region = &sarifRegion{StartLine: f.Line}
			}
			res.Locations = []sarifLocation{loc}
		} else if locations := capLocations[capabilityLocationKey{module: f.ModulePath, code: f.Code}]; len(locations) > 0 {
			res.Locations = locations
		}
		results = append(results, res)
	}
	log := sarifLog{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{
			Tool:    sarifTool{Driver: sarifDriver{Name: "trustmod", InformationURI: "https://github.com/maksemen2/trustmod", Rules: rules}},
			Results: results,
		}},
	}
	return json.MarshalIndent(log, "", "  ")
}

type capabilityLocationKey struct {
	module string
	code   string
}

func capabilityLocations(projectRoot string, mods []analyze.ModuleReport) map[capabilityLocationKey][]sarifLocation {
	out := map[capabilityLocationKey][]sarifLocation{}
	seen := map[capabilityLocationKey]map[string]bool{}
	for i := range mods {
		m := mods[i]
		for j := range m.Capabilities {
			capability := m.Capabilities[j]
			if capability.FindingCode == "" {
				continue
			}
			key := capabilityLocationKey{module: m.ModulePath, code: capability.FindingCode}
			if seen[key] == nil {
				seen[key] = map[string]bool{}
			}
			for _, evidence := range capability.Evidence {
				loc, ok := sarifLocationFromEvidence(projectRoot, evidence)
				if !ok {
					continue
				}
				dedupe := loc.PhysicalLocation.ArtifactLocation.URI
				if loc.PhysicalLocation.Region != nil {
					dedupe += ":" + strconv.Itoa(loc.PhysicalLocation.Region.StartLine)
				}
				if seen[key][dedupe] {
					continue
				}
				seen[key][dedupe] = true
				out[key] = append(out[key], loc)
			}
		}
	}
	return out
}

func sarifLocationFromEvidence(projectRoot string, e analyze.SourceLocation) (sarifLocation, bool) {
	uri := sarifURI(projectRoot, e.File, e.URL)
	if uri == "" {
		return sarifLocation{}, false
	}
	loc := sarifLocation{PhysicalLocation: sarifPhysicalLocation{ArtifactLocation: sarifArtifactLocation{URI: uri}}}
	if e.Line > 0 {
		loc.PhysicalLocation.Region = &sarifRegion{StartLine: e.Line}
	}
	return loc, true
}

func sarifURI(projectRoot, filePath, explicitURI string) string {
	if explicitURI = strings.TrimSpace(explicitURI); explicitURI != "" {
		return explicitURI
	}
	filePath = strings.TrimSpace(filePath)
	if filePath == "" {
		return ""
	}
	if strings.Contains(filePath, "://") {
		return filePath
	}

	cleanPath := filepath.Clean(filePath)
	cwd, err := os.Getwd()
	if err != nil {
		return filepath.ToSlash(cleanPath)
	}
	if filepath.IsAbs(cleanPath) {
		if rel, ok := pathutil.RelativeInside(cwd, cleanPath); ok {
			return filepath.ToSlash(rel)
		}
		return filepath.ToSlash(cleanPath)
	}

	projectRootAbs := projectRoot
	if projectRootAbs == "" {
		projectRootAbs = cwd
	} else if !filepath.IsAbs(projectRootAbs) {
		projectRootAbs = filepath.Join(cwd, projectRootAbs)
	}

	if projectRel, ok := pathutil.RelativeInside(cwd, projectRootAbs); ok && projectRel != "." && pathutil.HasPrefix(cleanPath, projectRel) {
		return filepath.ToSlash(cleanPath)
	}
	if rel, ok := pathutil.RelativeInside(cwd, filepath.Join(projectRootAbs, cleanPath)); ok {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(cleanPath)
}

func join(v []string) string {
	out := ""
	for i, s := range v {
		if i > 0 {
			out += "\n"
		}
		out += s
	}
	return out
}
