package report

import (
	"encoding/xml"
	"strings"

	analyze "github.com/maksemen2/trustmod/internal/model"
)

type junitSuite struct {
	XMLName  xml.Name    `xml:"testsuite"`
	Name     string      `xml:"name,attr"`
	Tests    int         `xml:"tests,attr"`
	Failures int         `xml:"failures,attr"`
	Skipped  int         `xml:"skipped,attr"`
	Cases    []junitCase `xml:"testcase"`
}

type junitCase struct {
	Name    string        `xml:"name,attr"`
	Class   string        `xml:"classname,attr"`
	Failure *junitFailure `xml:"failure,omitempty"`
	Skipped *junitSkipped `xml:"skipped,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Text    string `xml:",chardata"`
}

type junitSkipped struct {
	Message string `xml:"message,attr"`
	Text    string `xml:",chardata"`
}

func JUnitProject(r *analyze.ProjectReport) ([]byte, error) {
	s := junitSuite{Name: "trustmod", Tests: len(r.Findings)}
	for i := range r.Findings {
		f := r.Findings[i]
		tc := junitCase{Name: f.Code + " " + f.ModulePath, Class: f.Category}
		switch f.VerdictImpact {
		case analyze.VerdictBlock:
			tc.Failure = &junitFailure{Message: f.Title, Text: junitFailureText(f)}
			s.Failures++
		case analyze.VerdictReview:
			tc.Skipped = &junitSkipped{Message: f.Title, Text: junitFailureText(f)}
			s.Skipped++
		}
		s.Cases = append(s.Cases, tc)
	}
	return xml.MarshalIndent(s, "", "  ")
}

func junitFailureText(f analyze.Finding) string {
	lines := []string{
		"description: " + f.Description,
		"module: " + f.ModulePath + " " + f.ModuleVersion,
		"verdict: " + string(f.VerdictImpact),
		"severity: " + string(f.Severity),
		"confidence: " + string(f.Confidence),
	}
	if len(f.Evidence) > 0 {
		lines = append(lines, "evidence: "+strings.Join(f.Evidence, "; "))
	}
	if len(f.References) > 0 {
		lines = append(lines, "references: "+strings.Join(f.References, "; "))
	}
	return strings.Join(lines, "\n")
}
