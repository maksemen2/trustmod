package trustmod

import (
	"context"

	"github.com/maksemen2/trustmod/internal/analyze"
)

type Analyzer struct {
	inner *analyze.Analyzer
}

func NewAnalyzer(opts Options) (*Analyzer, error) {
	a, err := analyze.NewAnalyzer(opts)
	if err != nil {
		return nil, err
	}
	return &Analyzer{inner: a}, nil
}

func (a *Analyzer) Audit(ctx context.Context, path string) (*ProjectReport, error) {
	return a.inner.Audit(ctx, path)
}

func (a *Analyzer) CheckModule(ctx context.Context, module string) (*ProjectReport, error) {
	return a.inner.CheckModule(ctx, module)
}

func (a *Analyzer) Diff(ctx context.Context, opts DiffOptions) (*ProjectReport, error) {
	return a.inner.Diff(ctx, opts)
}

func (a *Analyzer) Compare(ctx context.Context, opts CompareOptions) (*CompareReport, error) {
	return a.inner.Compare(ctx, opts)
}
