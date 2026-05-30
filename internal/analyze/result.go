package analyze

import "github.com/maksemen2/trustmod/internal/model"

const (
	SchemaVersion        = model.SchemaVersion
	CompareSchemaVersion = model.CompareSchemaVersion
)

type Verdict = model.Verdict

const (
	VerdictAllow  = model.VerdictAllow
	VerdictReview = model.VerdictReview
	VerdictBlock  = model.VerdictBlock
)

func MaxVerdict(values ...Verdict) Verdict {
	return model.MaxVerdict(values...)
}

func verdictRank(v Verdict) int {
	switch v {
	case VerdictBlock:
		return 3
	case VerdictReview:
		return 2
	case VerdictAllow:
		return 1
	default:
		return 0
	}
}

type Severity = model.Severity

const (
	SeverityCritical = model.SeverityCritical
	SeverityHigh     = model.SeverityHigh
	SeverityMedium   = model.SeverityMedium
	SeverityLow      = model.SeverityLow
	SeverityInfo     = model.SeverityInfo
)

type Confidence = model.Confidence

const (
	ConfidenceHigh   = model.ConfidenceHigh
	ConfidenceMedium = model.ConfidenceMedium
	ConfidenceLow    = model.ConfidenceLow
)

type Finding = model.Finding
type Replacement = model.Replacement
type Capability = model.Capability
type SourceLocation = model.SourceLocation
type DependencyFootprint = model.DependencyFootprint
type MaintenanceSignals = model.MaintenanceSignals
type SecuritySignals = model.SecuritySignals
type IdentitySignals = model.IdentitySignals
type AdoptionSignals = model.AdoptionSignals
type ProviderStatus = model.ProviderStatus

const (
	ProviderStatusOK                        = model.ProviderStatusOK
	ProviderStatusDisabled                  = model.ProviderStatusDisabled
	ProviderStatusNotRequested              = model.ProviderStatusNotRequested
	ProviderStatusSkippedPrivate            = model.ProviderStatusSkippedPrivate
	ProviderStatusSkippedNoPublicModules    = model.ProviderStatusSkippedNoPublicModules
	ProviderStatusSkippedNoEligibleVersions = model.ProviderStatusSkippedNoEligibleVersions
	ProviderStatusSkippedUnsupportedHost    = model.ProviderStatusSkippedUnsupportedHost
	ProviderStatusSkippedNoProviderData     = model.ProviderStatusSkippedNoProviderData
	ProviderStatusUnavailable               = model.ProviderStatusUnavailable
	ProviderStatusRateLimited               = model.ProviderStatusRateLimited
	ProviderStatusTimeout                   = model.ProviderStatusTimeout
	ProviderStatusError                     = model.ProviderStatusError
	ProviderStatusCancelled                 = model.ProviderStatusCancelled
	ProviderStatusOfflineCacheHit           = model.ProviderStatusOfflineCacheHit
	ProviderStatusOfflineCacheMiss          = model.ProviderStatusOfflineCacheMiss
)

func ProviderStatusCountsAsError(status string) bool {
	return model.ProviderStatusCountsAsError(status)
}

func ProviderStatusSatisfiesRequirement(status string) bool {
	return model.ProviderStatusSatisfiesRequirement(status)
}

type RiskContribution = model.RiskContribution
type ModuleReport = model.ModuleReport
type GraphNode = model.GraphNode
type GraphEdge = model.GraphEdge
type DependencyGraph = model.DependencyGraph
type DiffModuleChange = model.DiffModuleChange
type DiffReport = model.DiffReport
type PolicySummary = model.PolicySummary
type BaselineSummary = model.BaselineSummary
type GoEnvSummary = model.GoEnvSummary
type Summary = model.Summary
type ProjectReport = model.ProjectReport
type CompareEntry = model.CompareEntry
type CompareReport = model.CompareReport
