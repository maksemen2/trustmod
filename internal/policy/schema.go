package policy

import analyze "github.com/maksemen2/trustmod/internal/model"

type Policy struct {
	Version    int                `yaml:"version" json:"version"`
	Profile    string             `yaml:"profile" json:"profile"`
	Strict     bool               `yaml:"strict" json:"strict"`
	FailOn     []string           `yaml:"fail_on" json:"fail_on"`
	Allow      RuleSet            `yaml:"allow" json:"allow"`
	Deny       RuleSet            `yaml:"deny" json:"deny"`
	Licenses   Licenses           `yaml:"licenses" json:"licenses"`
	Thresholds Thresholds         `yaml:"thresholds" json:"thresholds"`
	Providers  Providers          `yaml:"providers" json:"providers"`
	Profiles   map[string]Profile `yaml:"profiles" json:"profiles"`
}

type Profile struct {
	Strict     *bool      `yaml:"strict" json:"strict"`
	FailOn     []string   `yaml:"fail_on" json:"fail_on"`
	Allow      RuleSet    `yaml:"allow" json:"allow"`
	Deny       RuleSet    `yaml:"deny" json:"deny"`
	Licenses   Licenses   `yaml:"licenses" json:"licenses"`
	Thresholds Thresholds `yaml:"thresholds" json:"thresholds"`
	Providers  Providers  `yaml:"providers" json:"providers"`
}

type RuleSet struct {
	Modules      []string `yaml:"modules" json:"modules"`
	FindingCodes []string `yaml:"finding_codes" json:"finding_codes"`
	Capabilities []string `yaml:"capabilities" json:"capabilities"`
}

type Licenses struct {
	Allowed []string `yaml:"allowed" json:"allowed"`
	Banned  []string `yaml:"banned" json:"banned"`
}

type Thresholds struct {
	RiskReview       int `yaml:"risk_review" json:"risk_review"`
	RiskBlock        int `yaml:"risk_block" json:"risk_block"`
	TransitiveReview int `yaml:"transitive_review" json:"transitive_review"`
	PackageReview    int `yaml:"package_review" json:"package_review"`
}

type Providers struct {
	Required []string `yaml:"required" json:"required"`
	Disabled []string `yaml:"disabled" json:"disabled"`
}

func (p Policy) Summary(path string, loaded bool, warnings []string) analyze.PolicySummary {
	failOn := make([]analyze.Verdict, 0, len(p.FailOn))
	for _, v := range p.FailOn {
		switch v {
		case string(analyze.VerdictBlock):
			failOn = append(failOn, analyze.VerdictBlock)
		case string(analyze.VerdictReview):
			failOn = append(failOn, analyze.VerdictReview)
		}
	}
	if len(failOn) == 0 {
		failOn = []analyze.Verdict{analyze.VerdictBlock}
	}
	return analyze.PolicySummary{Path: path, Profile: p.Profile, FailOn: failOn, Strict: p.Strict, Loaded: loaded, Warnings: warnings}
}
