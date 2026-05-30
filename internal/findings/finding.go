package findings

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	analyze "github.com/maksemen2/trustmod/internal/model"
)

type Definition struct {
	Code          string
	Title         string
	Category      string
	Severity      analyze.Severity
	VerdictImpact analyze.Verdict
	Confidence    analyze.Confidence
	Remediation   []string
	Description   string
}

func New(code, modulePath, moduleVersion, source string) analyze.Finding {
	def, ok := Lookup(code)
	if !ok {
		def = Definition{
			Code:          code,
			Title:         "Uncatalogued trustmod finding",
			Category:      "data",
			Severity:      analyze.SeverityInfo,
			VerdictImpact: analyze.VerdictReview,
			Confidence:    analyze.ConfidenceLow,
			Description:   "trustmod emitted a finding that is not in the local catalog.",
			Remediation:   []string{"Update trustmod or review this finding manually."},
		}
	}
	id := stableID(code, modulePath, moduleVersion, source, def.Title)
	return analyze.Finding{
		ID:            id,
		Code:          def.Code,
		Title:         def.Title,
		Description:   def.Description,
		Category:      def.Category,
		Severity:      def.Severity,
		Confidence:    def.Confidence,
		VerdictImpact: def.VerdictImpact,
		ModulePath:    modulePath,
		ModuleVersion: moduleVersion,
		Source:        source,
		Remediation:   append([]string(nil), def.Remediation...),
	}
}

func WithStableID(f analyze.Finding, parts ...string) analyze.Finding {
	f.ID = stableID(parts...)
	return f
}

func stableID(parts ...string) string {
	h := sha256.New()
	_, _ = h.Write([]byte(strings.Join(parts, "\x00")))
	return "fnd_" + hex.EncodeToString(h.Sum(nil))[:16]
}
