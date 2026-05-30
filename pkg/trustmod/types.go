package trustmod

import "github.com/maksemen2/trustmod/internal/model"

type Verdict = model.Verdict
type Severity = model.Severity
type Confidence = model.Confidence
type Finding = model.Finding
type Capability = model.Capability
type SourceLocation = model.SourceLocation
type ModuleReport = model.ModuleReport
type ProjectReport = model.ProjectReport
type CompareReport = model.CompareReport
type ProviderStatus = model.ProviderStatus
type Options = model.Options
type DiffOptions = model.DiffOptions
type CompareOptions = model.CompareOptions

const (
	VerdictAllow  = model.VerdictAllow
	VerdictReview = model.VerdictReview
	VerdictBlock  = model.VerdictBlock
)
