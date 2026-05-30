package policy

func Default(profile string) Policy {
	if profile == "" {
		profile = "backend-service"
	}
	return Policy{
		Version: 1,
		Profile: profile,
		FailOn:  []string{"BLOCK"},
		Licenses: Licenses{
			Banned: []string{"AGPL-3.0", "GPL-3.0"},
		},
		Thresholds: Thresholds{
			RiskReview:       30,
			RiskBlock:        101,
			TransitiveReview: 20,
			PackageReview:    80,
		},
		Providers: Providers{},
		Profiles: map[string]Profile{
			"backend-service": {
				Thresholds: Thresholds{RiskReview: 30, RiskBlock: 101, TransitiveReview: 20, PackageReview: 80},
			},
			"strict": {
				Strict:     boolPtr(true),
				FailOn:     []string{"BLOCK", "REVIEW"},
				Thresholds: Thresholds{RiskReview: 20, RiskBlock: 80, TransitiveReview: 10, PackageReview: 50},
				Providers:  Providers{Required: []string{"osv"}},
			},
			"library": {
				Thresholds: Thresholds{RiskReview: 25, RiskBlock: 75, TransitiveReview: 12, PackageReview: 60},
			},
		},
	}
}

func boolPtr(v bool) *bool { return &v }
