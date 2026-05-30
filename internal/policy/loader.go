package policy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

func Load(path, profile string) (Policy, string, bool, []string, error) {
	profile = strings.TrimSpace(profile)
	profileOverride := profile != ""
	if path == "" {
		path = os.Getenv("TRUSTMOD_POLICY")
	}
	if path == "" {
		path = filepath.Join(".trustmod", "policy.yml")
	}
	base := Default("")
	if profileOverride {
		base = Default(profile)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			applyProfile(&base, base.Profile)
			return base, path, false, nil, nil
		}
		return base, path, false, nil, err
	}
	if err := yaml.Unmarshal(data, &base); err != nil {
		return base, path, false, nil, err
	}
	if profileOverride {
		base.Profile = profile
	}
	if base.Profile == "" {
		base.Profile = Default("").Profile
	}
	applyProfile(&base, base.Profile)
	warnings := Validate(base)
	return base, path, true, warnings, nil
}

func applyProfile(p *Policy, name string) {
	if name == "" {
		name = p.Profile
	}
	prof, ok := p.Profiles[name]
	if !ok {
		return
	}
	p.Profile = name
	if prof.Strict != nil {
		p.Strict = *prof.Strict
	}
	if len(prof.FailOn) > 0 {
		p.FailOn = prof.FailOn
	}
	mergeRuleSet(&p.Allow, prof.Allow)
	mergeRuleSet(&p.Deny, prof.Deny)
	if len(prof.Licenses.Allowed) > 0 {
		p.Licenses.Allowed = prof.Licenses.Allowed
	}
	if len(prof.Licenses.Banned) > 0 {
		p.Licenses.Banned = prof.Licenses.Banned
	}
	if prof.Thresholds.RiskReview > 0 {
		p.Thresholds.RiskReview = prof.Thresholds.RiskReview
	}
	if prof.Thresholds.RiskBlock > 0 {
		p.Thresholds.RiskBlock = prof.Thresholds.RiskBlock
	}
	if prof.Thresholds.TransitiveReview > 0 {
		p.Thresholds.TransitiveReview = prof.Thresholds.TransitiveReview
	}
	if prof.Thresholds.PackageReview > 0 {
		p.Thresholds.PackageReview = prof.Thresholds.PackageReview
	}
	if len(prof.Providers.Required) > 0 {
		p.Providers.Required = prof.Providers.Required
	}
	if len(prof.Providers.Disabled) > 0 {
		p.Providers.Disabled = prof.Providers.Disabled
	}
}

func mergeRuleSet(dst *RuleSet, src RuleSet) {
	dst.Modules = append(dst.Modules, src.Modules...)
	dst.FindingCodes = append(dst.FindingCodes, src.FindingCodes...)
	dst.Capabilities = append(dst.Capabilities, src.Capabilities...)
}
