package baseline

import "time"

type Baseline struct {
	Version          int               `yaml:"version" json:"version"`
	CreatedAt        string            `yaml:"created_at" json:"created_at"`
	AcceptedFindings []AcceptedFinding `yaml:"accepted_findings" json:"accepted_findings"`
	AcceptedModules  []AcceptedModule  `yaml:"accepted_modules" json:"accepted_modules"`
}

type AcceptedFinding struct {
	Module     string `yaml:"module" json:"module"`
	Version    string `yaml:"version,omitempty" json:"version,omitempty"`
	Code       string `yaml:"code" json:"code"`
	Reason     string `yaml:"reason" json:"reason"`
	ApprovedBy string `yaml:"approved_by" json:"approved_by"`
	Expires    string `yaml:"expires,omitempty" json:"expires,omitempty"`
}

type AcceptedModule struct {
	Module     string `yaml:"module" json:"module"`
	Version    string `yaml:"version,omitempty" json:"version,omitempty"`
	Reason     string `yaml:"reason" json:"reason"`
	ApprovedBy string `yaml:"approved_by" json:"approved_by"`
	Expires    string `yaml:"expires,omitempty" json:"expires,omitempty"`
}

func Empty() Baseline {
	return Baseline{Version: 1, CreatedAt: time.Now().UTC().Format(time.RFC3339)}
}
