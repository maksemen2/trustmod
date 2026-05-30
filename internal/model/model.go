package model

import "time"

const (
	SchemaVersion        = "trustmod.report.v1"
	CompareSchemaVersion = "trustmod.compare.v1"
)

type Verdict string

const (
	VerdictAllow  Verdict = "ALLOW"
	VerdictReview Verdict = "REVIEW"
	VerdictBlock  Verdict = "BLOCK"
)

func MaxVerdict(values ...Verdict) Verdict {
	out := VerdictAllow
	for _, v := range values {
		if verdictRank(v) > verdictRank(out) {
			out = v
		}
	}
	return out
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

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

type Finding struct {
	ID               string     `json:"id" yaml:"id"`
	Code             string     `json:"code" yaml:"code"`
	Title            string     `json:"title" yaml:"title"`
	Description      string     `json:"description" yaml:"description"`
	Category         string     `json:"category" yaml:"category"`
	Severity         Severity   `json:"severity" yaml:"severity"`
	Confidence       Confidence `json:"confidence" yaml:"confidence"`
	VerdictImpact    Verdict    `json:"verdictImpact" yaml:"verdictImpact"`
	ModulePath       string     `json:"modulePath,omitempty" yaml:"modulePath,omitempty"`
	ModuleVersion    string     `json:"moduleVersion,omitempty" yaml:"moduleVersion,omitempty"`
	PackagePath      string     `json:"packagePath,omitempty" yaml:"packagePath,omitempty"`
	File             string     `json:"file,omitempty" yaml:"file,omitempty"`
	Line             int        `json:"line,omitempty" yaml:"line,omitempty"`
	Source           string     `json:"source" yaml:"source"`
	Evidence         []string   `json:"evidence,omitempty" yaml:"evidence,omitempty"`
	Remediation      []string   `json:"remediation,omitempty" yaml:"remediation,omitempty"`
	References       []string   `json:"references,omitempty" yaml:"references,omitempty"`
	FirstSeen        *time.Time `json:"firstSeen,omitempty" yaml:"firstSeen,omitempty"`
	NewInDiff        bool       `json:"newInDiff" yaml:"newInDiff"`
	Direct           bool       `json:"direct" yaml:"direct"`
	Reachable        *bool      `json:"reachable,omitempty" yaml:"reachable,omitempty"`
	PolicyRule       string     `json:"policyRule,omitempty" yaml:"policyRule,omitempty"`
	BaselineAccepted bool       `json:"baselineAccepted,omitempty" yaml:"baselineAccepted,omitempty"`
}

type Replacement struct {
	Path    string `json:"path" yaml:"path"`
	Version string `json:"version,omitempty" yaml:"version,omitempty"`
	Local   bool   `json:"local" yaml:"local"`
}

type Capability struct {
	Name          string           `json:"name" yaml:"name"`
	FindingCode   string           `json:"findingCode,omitempty" yaml:"findingCode,omitempty"`
	DirectCalls   int              `json:"directCalls" yaml:"directCalls"`
	IndirectCalls int              `json:"indirectCalls" yaml:"indirectCalls"`
	Domains       []string         `json:"domains,omitempty" yaml:"domains,omitempty"`
	DomainCount   int              `json:"domainCount,omitempty" yaml:"domainCount,omitempty"`
	LocalEvidence []string         `json:"localEvidence,omitempty" yaml:"localEvidence,omitempty"`
	Evidence      []SourceLocation `json:"evidence,omitempty" yaml:"evidence,omitempty"`
	Source        string           `json:"source" yaml:"source"`
	Confidence    Confidence       `json:"confidence" yaml:"confidence"`
	NewInDiff     bool             `json:"newInDiff" yaml:"newInDiff"`
}

type SourceLocation struct {
	File      string `json:"file,omitempty" yaml:"file,omitempty"`
	Line      int    `json:"line,omitempty" yaml:"line,omitempty"`
	Text      string `json:"text,omitempty" yaml:"text,omitempty"`
	URL       string `json:"url,omitempty" yaml:"url,omitempty"`
	LocalPath string `json:"-" yaml:"-"`
}

type DependencyFootprint struct {
	DirectModules       int      `json:"directModules" yaml:"directModules"`
	TransitiveModules   int      `json:"transitiveModules" yaml:"transitiveModules"`
	ProductionPackages  int      `json:"productionPackages" yaml:"productionPackages"`
	TestPackages        int      `json:"testPackages" yaml:"testPackages"`
	ToolPackages        int      `json:"toolPackages" yaml:"toolPackages"`
	NewModules          int      `json:"newModules,omitempty" yaml:"newModules,omitempty"`
	RemovedModules      int      `json:"removedModules,omitempty" yaml:"removedModules,omitempty"`
	UpdatedModules      int      `json:"updatedModules,omitempty" yaml:"updatedModules,omitempty"`
	ShortestModulePaths []string `json:"shortestModulePaths,omitempty" yaml:"shortestModulePaths,omitempty"`
}

type MaintenanceSignals struct {
	RepositoryArchived   bool       `json:"repositoryArchived,omitempty" yaml:"repositoryArchived,omitempty"`
	RepositoryArchivedAt *time.Time `json:"repositoryArchivedAt,omitempty" yaml:"repositoryArchivedAt,omitempty"`
	LastCommitAt         *time.Time `json:"lastCommitAt,omitempty" yaml:"lastCommitAt,omitempty"`
	LastReleaseAt        *time.Time `json:"lastReleaseAt,omitempty" yaml:"lastReleaseAt,omitempty"`
	ScorecardScore       *float64   `json:"scorecardScore,omitempty" yaml:"scorecardScore,omitempty"`
	Stars                *int       `json:"stars,omitempty" yaml:"stars,omitempty"`
}

type SecuritySignals struct {
	KnownVulnerabilities int  `json:"knownVulnerabilities" yaml:"knownVulnerabilities"`
	ReachableFindings    int  `json:"reachableFindings" yaml:"reachableFindings"`
	ChecksumVerified     bool `json:"checksumVerified" yaml:"checksumVerified"`
}

type IdentitySignals struct {
	CanonicalModulePath string `json:"canonicalModulePath,omitempty" yaml:"canonicalModulePath,omitempty"`
	Repository          string `json:"repository,omitempty" yaml:"repository,omitempty"`
	Host                string `json:"host,omitempty" yaml:"host,omitempty"`
}

type AdoptionSignals struct {
	Dependents *int `json:"dependents,omitempty" yaml:"dependents,omitempty"`
	Stars      *int `json:"stars,omitempty" yaml:"stars,omitempty"`
}

type ProviderStatus struct {
	Name         string     `json:"name" yaml:"name"`
	Enabled      bool       `json:"enabled" yaml:"enabled"`
	Status       string     `json:"status" yaml:"status"`
	FetchedAt    *time.Time `json:"fetchedAt,omitempty" yaml:"fetchedAt,omitempty"`
	Cached       bool       `json:"cached" yaml:"cached"`
	ErrorSummary string     `json:"errorSummary,omitempty" yaml:"errorSummary,omitempty"`
	Source       string     `json:"source,omitempty" yaml:"source,omitempty"`
	Queried      int        `json:"queried,omitempty" yaml:"queried,omitempty"`
	Skipped      int        `json:"skipped,omitempty" yaml:"skipped,omitempty"`
}

type RiskContribution struct {
	Code   string `json:"code" yaml:"code"`
	Reason string `json:"reason" yaml:"reason"`
	Points int    `json:"points" yaml:"points"`
}

type ModuleReport struct {
	ModulePath          string                 `json:"modulePath" yaml:"modulePath"`
	Version             string                 `json:"version,omitempty" yaml:"version,omitempty"`
	SelectedVersion     string                 `json:"selectedVersion,omitempty" yaml:"selectedVersion,omitempty"`
	RequestedVersion    string                 `json:"requestedVersion,omitempty" yaml:"requestedVersion,omitempty"`
	Replacement         *Replacement           `json:"replacement,omitempty" yaml:"replacement,omitempty"`
	Direct              bool                   `json:"direct" yaml:"direct"`
	Indirect            bool                   `json:"indirect" yaml:"indirect"`
	TestOnly            bool                   `json:"testOnly" yaml:"testOnly"`
	ToolOnly            bool                   `json:"toolOnly" yaml:"toolOnly"`
	Private             bool                   `json:"private" yaml:"private"`
	LocalReplace        bool                   `json:"localReplace" yaml:"localReplace"`
	Retracted           bool                   `json:"retracted" yaml:"retracted"`
	Deprecated          bool                   `json:"deprecated" yaml:"deprecated"`
	PseudoVersion       bool                   `json:"pseudoVersion" yaml:"pseudoVersion"`
	MajorVersion        int                    `json:"majorVersion" yaml:"majorVersion"`
	SemverStatus        string                 `json:"semverStatus" yaml:"semverStatus"`
	Licenses            []string               `json:"licenses,omitempty" yaml:"licenses,omitempty"`
	Repository          string                 `json:"repository,omitempty" yaml:"repository,omitempty"`
	SourceHost          string                 `json:"sourceHost,omitempty" yaml:"sourceHost,omitempty"`
	LocalDir            string                 `json:"-" yaml:"-"`
	Findings            []Finding              `json:"findings,omitempty" yaml:"findings,omitempty"`
	Capabilities        []Capability           `json:"capabilities,omitempty" yaml:"capabilities,omitempty"`
	DependencyFootprint DependencyFootprint    `json:"dependencyFootprint" yaml:"dependencyFootprint"`
	Maintenance         MaintenanceSignals     `json:"maintenance" yaml:"maintenance"`
	Security            SecuritySignals        `json:"security" yaml:"security"`
	Identity            IdentitySignals        `json:"identity" yaml:"identity"`
	Adoption            AdoptionSignals        `json:"adoption" yaml:"adoption"`
	DataAvailability    []ProviderStatus       `json:"dataAvailability,omitempty" yaml:"dataAvailability,omitempty"`
	Verdict             Verdict                `json:"verdict" yaml:"verdict"`
	RiskScore           int                    `json:"riskScore" yaml:"riskScore"`
	RiskContributions   []RiskContribution     `json:"riskContributions,omitempty" yaml:"riskContributions,omitempty"`
	ProviderAnnotations map[string]interface{} `json:"providerAnnotations,omitempty" yaml:"providerAnnotations,omitempty"`
}

type GraphNode struct {
	ID      string `json:"id" yaml:"id"`
	Version string `json:"version,omitempty" yaml:"version,omitempty"`
	Direct  bool   `json:"direct" yaml:"direct"`
	Private bool   `json:"private" yaml:"private"`
}

type GraphEdge struct {
	From string `json:"from" yaml:"from"`
	To   string `json:"to" yaml:"to"`
	Type string `json:"type" yaml:"type"`
}

type DependencyGraph struct {
	Nodes []GraphNode `json:"nodes" yaml:"nodes"`
	Edges []GraphEdge `json:"edges" yaml:"edges"`
	Notes []string    `json:"notes,omitempty" yaml:"notes,omitempty"`
}

type DiffModuleChange struct {
	ModulePath string `json:"modulePath" yaml:"modulePath"`
	From       string `json:"from,omitempty" yaml:"from,omitempty"`
	To         string `json:"to,omitempty" yaml:"to,omitempty"`
	Direct     bool   `json:"direct" yaml:"direct"`
}

type DiffReport struct {
	Base           string             `json:"base" yaml:"base"`
	NewModules     []DiffModuleChange `json:"newModules,omitempty" yaml:"newModules,omitempty"`
	UpdatedModules []DiffModuleChange `json:"updatedModules,omitempty" yaml:"updatedModules,omitempty"`
	RemovedModules []DiffModuleChange `json:"removedModules,omitempty" yaml:"removedModules,omitempty"`
	Notes          []string           `json:"notes,omitempty" yaml:"notes,omitempty"`
}

type PolicySummary struct {
	Path     string    `json:"path,omitempty" yaml:"path,omitempty"`
	Profile  string    `json:"profile" yaml:"profile"`
	FailOn   []Verdict `json:"failOn" yaml:"failOn"`
	Strict   bool      `json:"strict" yaml:"strict"`
	Loaded   bool      `json:"loaded" yaml:"loaded"`
	Warnings []string  `json:"warnings,omitempty" yaml:"warnings,omitempty"`
}

type BaselineSummary struct {
	Path              string `json:"path,omitempty" yaml:"path,omitempty"`
	Loaded            bool   `json:"loaded" yaml:"loaded"`
	AcceptedFindings  int    `json:"acceptedFindings" yaml:"acceptedFindings"`
	AcceptedModules   int    `json:"acceptedModules" yaml:"acceptedModules"`
	ExpiredExceptions int    `json:"expiredExceptions" yaml:"expiredExceptions"`
}

type GoEnvSummary struct {
	GoVersion  string   `json:"goVersion,omitempty" yaml:"goVersion,omitempty"`
	GOMOD      string   `json:"GOMOD,omitempty" yaml:"GOMOD,omitempty"`
	GOWORK     string   `json:"GOWORK,omitempty" yaml:"GOWORK,omitempty"`
	GOMODCACHE string   `json:"GOMODCACHE,omitempty" yaml:"GOMODCACHE,omitempty"`
	GOPRIVATE  []string `json:"GOPRIVATE,omitempty" yaml:"GOPRIVATE,omitempty"`
	GONOPROXY  []string `json:"GONOPROXY,omitempty" yaml:"GONOPROXY,omitempty"`
	GONOSUMDB  []string `json:"GONOSUMDB,omitempty" yaml:"GONOSUMDB,omitempty"`
}

type Summary struct {
	Modules              int `json:"modules" yaml:"modules"`
	DirectModules        int `json:"directModules" yaml:"directModules"`
	TransitiveModules    int `json:"transitiveModules" yaml:"transitiveModules"`
	Findings             int `json:"findings" yaml:"findings"`
	BlockingFindings     int `json:"blockingFindings" yaml:"blockingFindings"`
	ReviewFindings       int `json:"reviewFindings" yaml:"reviewFindings"`
	BaselineAccepted     int `json:"baselineAccepted" yaml:"baselineAccepted"`
	PrivateModules       int `json:"privateModules" yaml:"privateModules"`
	NewFindings          int `json:"newFindings,omitempty" yaml:"newFindings,omitempty"`
	NewModules           int `json:"newModules,omitempty" yaml:"newModules,omitempty"`
	UpdatedModules       int `json:"updatedModules,omitempty" yaml:"updatedModules,omitempty"`
	RemovedModules       int `json:"removedModules,omitempty" yaml:"removedModules,omitempty"`
	ProviderErrors       int `json:"providerErrors" yaml:"providerErrors"`
	Capabilities         int `json:"capabilities" yaml:"capabilities"`
	KnownVulnerabilities int `json:"knownVulnerabilities" yaml:"knownVulnerabilities"`
}

type ProjectReport struct {
	SchemaVersion          string           `json:"schemaVersion" yaml:"schemaVersion"`
	TrustmodVersion        string           `json:"trustmodVersion" yaml:"trustmodVersion"`
	GeneratedAt            time.Time        `json:"generatedAt" yaml:"generatedAt"`
	ProjectRoot            string           `json:"projectRoot" yaml:"projectRoot"`
	ModuleMode             string           `json:"moduleMode" yaml:"moduleMode"`
	MainModules            []string         `json:"mainModules" yaml:"mainModules"`
	GoVersion              string           `json:"goVersion,omitempty" yaml:"goVersion,omitempty"`
	GoEnvSummary           GoEnvSummary     `json:"goEnvSummary" yaml:"goEnvSummary"`
	Policy                 PolicySummary    `json:"policy" yaml:"policy"`
	Baseline               BaselineSummary  `json:"baseline" yaml:"baseline"`
	Providers              []ProviderStatus `json:"providers" yaml:"providers"`
	Modules                []ModuleReport   `json:"modules" yaml:"modules"`
	DependencyGraph        DependencyGraph  `json:"dependencyGraph" yaml:"dependencyGraph"`
	Diff                   *DiffReport      `json:"diff,omitempty" yaml:"diff,omitempty"`
	Summary                Summary          `json:"summary" yaml:"summary"`
	Findings               []Finding        `json:"findings,omitempty" yaml:"findings,omitempty"`
	Verdict                Verdict          `json:"verdict" yaml:"verdict"`
	ExitCodeRecommendation int              `json:"exitCodeRecommendation" yaml:"exitCodeRecommendation"`
	Notes                  []string         `json:"notes,omitempty" yaml:"notes,omitempty"`
}

type CompareEntry struct {
	Module             ModuleReport `json:"module" yaml:"module"`
	DirectDependencies int          `json:"directDependencies" yaml:"directDependencies"`
	TransitiveDeps     int          `json:"transitiveDependencies" yaml:"transitiveDependencies"`
	KeyNotes           []string     `json:"keyNotes,omitempty" yaml:"keyNotes,omitempty"`
}

type CompareReport struct {
	SchemaVersion  string         `json:"schemaVersion" yaml:"schemaVersion"`
	GeneratedAt    time.Time      `json:"generatedAt" yaml:"generatedAt"`
	Profile        string         `json:"profile" yaml:"profile"`
	UseCase        string         `json:"useCase,omitempty" yaml:"useCase,omitempty"`
	Entries        []CompareEntry `json:"entries" yaml:"entries"`
	Recommendation string         `json:"recommendation,omitempty" yaml:"recommendation,omitempty"`
	Caveat         string         `json:"caveat" yaml:"caveat"`
}
