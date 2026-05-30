package govulncheck

import (
	"bytes"
	"context"
	"time"

	"github.com/maksemen2/trustmod/internal/findings"
	analyze "github.com/maksemen2/trustmod/internal/model"
	"github.com/maksemen2/trustmod/internal/provider"
)

type Provider struct {
	runner Runner
}

func New(opts analyze.Options) *Provider {
	return &Provider{runner: NewRunner(opts)}
}

func (p *Provider) Name() string { return "govulncheck" }

func (p *Provider) Enrich(ctx context.Context, req provider.Request) (provider.Result, error) {
	now := time.Now().UTC()
	res := provider.Result{
		Status:  analyze.ProviderStatus{Name: p.Name(), Enabled: true, Status: analyze.ProviderStatusOK, FetchedAt: &now, Source: "local govulncheck", Queried: len(req.Modules)},
		Modules: map[string]provider.ModuleUpdate{},
	}
	if req.Options.Offline {
		res.Status.Status = analyze.ProviderStatusNotRequested
		res.Status.ErrorSummary = "govulncheck skipped in offline mode"
		return res, nil
	}
	out, status, err := p.runner.Run(ctx, req.ProjectRoot)
	res.Status.Status = status
	messages := Parse(out)
	if err != nil {
		if len(messages) == 0 {
			res.Status.ErrorSummary = err.Error()
			if status == analyze.ProviderStatusUnavailable {
				f := findings.New("TM-SEC-004", "", "", "govulncheck")
				f.Evidence = []string{"govulncheck executable was not found on PATH"}
				res.Findings = append(res.Findings, f)
			}
			return res, nil
		}
		res.Status.Status = analyze.ProviderStatusOK
	}
	if len(out) > 0 && len(messages) == 0 && status == analyze.ProviderStatusOK {
		if hasGovulncheckFindingEnvelope(out) {
			res.Status.Status = analyze.ProviderStatusError
			res.Status.ErrorSummary = "govulncheck JSON contained unsupported finding records"
			f := findings.New("TM-SEC-004", "", "", "govulncheck")
			f.Evidence = []string{"govulncheck JSON output could not be mapped to trustmod findings"}
			res.Findings = append(res.Findings, f)
			return res, nil
		}
	}
	for i := range messages {
		msg := messages[i]
		code := "TM-SEC-002"
		if msg.Reachable {
			code = "TM-SEC-001"
		}
		f := findings.New(code, msg.Module, msg.Version, "govulncheck")
		if msg.OSV != "" {
			f = findings.WithStableID(f, f.Code, msg.Module, msg.Version, "advisory", msg.OSV)
		}
		if msg.Summary != "" {
			f.Description = msg.Summary
		}
		f.References = []string{msg.OSV}
		f.Evidence = []string{"govulncheck advisory: " + msg.OSV}
		if msg.Reachable {
			reachable := true
			f.Reachable = &reachable
			f.Evidence[0] = "govulncheck reported reachable advisory: " + msg.OSV
		}
		if msg.Symbol != "" {
			f.Evidence = append(f.Evidence, "symbol: "+msg.Symbol)
		}
		if msg.FixedVersion != "" {
			f.Evidence = append(f.Evidence, "fixed version: "+msg.FixedVersion)
		}
		for _, trace := range msg.Trace {
			f.Evidence = append(f.Evidence, "trace: "+trace)
		}
		res.Findings = append(res.Findings, f)
		if msg.Module != "" {
			update := res.Modules[msg.Module]
			update.ModulePath = msg.Module
			update.Findings = append(update.Findings, f)
			sec := analyze.SecuritySignals{KnownVulnerabilities: 1}
			if update.Security != nil {
				sec = *update.Security
				sec.KnownVulnerabilities++
			}
			if msg.Reachable {
				sec.ReachableFindings++
			}
			update.Security = &sec
			res.Modules[msg.Module] = update
		}
	}
	return res, nil
}

func hasGovulncheckFindingEnvelope(out []byte) bool {
	return bytes.Contains(out, []byte(`"finding"`))
}
