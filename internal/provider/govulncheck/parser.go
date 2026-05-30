package govulncheck

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/maksemen2/trustmod/internal/collect"
)

type FindingMessage struct {
	OSV          string
	Summary      string
	Module       string
	Version      string
	Symbol       string
	FixedVersion string
	Reachable    bool
	Trace        []string
}

type jsonMessage struct {
	OSV     *osvMessage     `json:"osv"`
	Finding *findingMessage `json:"finding"`
}

type osvMessage struct {
	ID       string `json:"id"`
	Summary  string `json:"summary"`
	Affected []struct {
		Package struct {
			Name string `json:"name"`
		} `json:"package"`
	} `json:"affected"`
}

type findingMessage struct {
	OSV             string  `json:"osv"`
	FixedVersion    string  `json:"fixed_version"`
	FixedVersionAlt string  `json:"fixedVersion"`
	Trace           []frame `json:"trace"`
}

type frame struct {
	Module   string `json:"module"`
	Version  string `json:"version"`
	Package  string `json:"package"`
	Function string `json:"function"`
	Receiver string `json:"receiver"`
	Position *struct {
		Filename string `json:"filename"`
		Line     int    `json:"line"`
	} `json:"position"`
}

func Parse(data []byte) []FindingMessage {
	var findings []findingMessage
	summaries := map[string]string{}
	modules := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		var msg jsonMessage
		if err := json.Unmarshal(scanner.Bytes(), &msg); err != nil {
			continue
		}
		if msg.OSV != nil && msg.OSV.ID != "" {
			summaries[msg.OSV.ID] = msg.OSV.Summary
			if len(msg.OSV.Affected) > 0 {
				modules[msg.OSV.ID] = msg.OSV.Affected[0].Package.Name
			}
		}
		if msg.Finding != nil && msg.Finding.OSV != "" {
			findings = append(findings, *msg.Finding)
		}
	}
	out := make([]FindingMessage, 0, len(findings))
	for _, finding := range findings {
		fm := FindingMessage{
			OSV:          finding.OSV,
			Summary:      summaries[finding.OSV],
			Module:       modules[finding.OSV],
			FixedVersion: collect.FirstNonEmpty(finding.FixedVersion, finding.FixedVersionAlt),
			Reachable:    len(finding.Trace) > 0,
		}
		for _, frame := range finding.Trace {
			if fm.Module == "" && frame.Module != "" && frame.Module != "stdlib" {
				fm.Module = frame.Module
			}
			if fm.Version == "" && frame.Version != "" {
				fm.Version = frame.Version
			}
			if fm.Symbol == "" {
				fm.Symbol = symbol(frame)
			}
			if line := traceLine(frame); line != "" {
				fm.Trace = append(fm.Trace, line)
			}
		}
		out = append(out, fm)
	}
	return out
}

func symbol(f frame) string {
	if f.Function == "" {
		return ""
	}
	fn := f.Function
	if f.Receiver != "" {
		fn = f.Receiver + "." + fn
	}
	if f.Package != "" {
		return f.Package + "." + fn
	}
	return fn
}

func traceLine(f frame) string {
	parts := []string{}
	if f.Module != "" {
		if f.Version != "" {
			parts = append(parts, f.Module+"@"+f.Version)
		} else {
			parts = append(parts, f.Module)
		}
	}
	if sym := symbol(f); sym != "" {
		parts = append(parts, sym)
	} else if f.Package != "" {
		parts = append(parts, f.Package)
	}
	if f.Position != nil && f.Position.Filename != "" {
		loc := f.Position.Filename
		if f.Position.Line > 0 {
			loc += ":" + strconv.Itoa(f.Position.Line)
		}
		parts = append(parts, loc)
	}
	return strings.Join(parts, " ")
}
