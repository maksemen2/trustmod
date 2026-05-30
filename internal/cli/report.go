package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/maksemen2/trustmod/internal/analyze"
	"github.com/maksemen2/trustmod/internal/fsutil"
	"github.com/maksemen2/trustmod/internal/report"
)

func renderProject(opts *globalOptions, r *analyze.ProjectReport) error {
	format := opts.format
	if isHumanFormat(format) {
		if opts.outFile != "" {
			format = "json"
		} else if opts.quiet {
			fmt.Fprintf(os.Stdout, "%s\n", r.Verdict)
			return nil
		}
	}
	renderer, ok := report.ProjectRendererFor(format)
	if !ok {
		return usageExitError(fmt.Errorf("unknown format %q", opts.format))
	}
	return renderToOutput(opts.outFile, func(w io.Writer) error {
		return renderer.RenderProject(w, r, report.HumanOptions{NoColor: opts.noColor, Verbose: opts.verbose})
	})
}

func renderCompare(opts *globalOptions, r *analyze.CompareReport) error {
	format := opts.format
	if isHumanFormat(format) {
		if opts.outFile != "" {
			format = "json"
		} else if opts.quiet {
			if r.Recommendation != "" {
				fmt.Fprintln(os.Stdout, r.Recommendation)
			}
			return nil
		}
	}
	renderer, ok := report.CompareRendererFor(format)
	if !ok {
		return usageExitError(fmt.Errorf("format %q is not supported for compare", opts.format))
	}
	return renderToOutput(opts.outFile, func(w io.Writer) error {
		return renderer.RenderCompare(w, r, report.HumanOptions{NoColor: opts.noColor, Verbose: opts.verbose})
	})
}

func writeProjectArtifact(path, format string, r *analyze.ProjectReport) error {
	renderer, ok := report.ProjectRendererFor(format)
	if !ok {
		return usageExitError(fmt.Errorf("unknown format %q", format))
	}
	return renderToOutput(path, func(w io.Writer) error {
		return renderer.RenderProject(w, r, report.HumanOptions{NoColor: true})
	})
}

func renderToOutput(path string, render func(io.Writer) error) error {
	if path == "" {
		w := &newlineTrackingWriter{w: os.Stdout}
		if err := render(w); err != nil {
			return err
		}
		if !w.wrote || w.last != '\n' {
			fmt.Println()
		}
		return nil
	}
	f, err := fsutil.CreatePrivateFile(path)
	if err != nil {
		return userFileExitError(err)
	}
	renderErr := render(f)
	closeErr := f.Close()
	if renderErr != nil {
		return renderErr
	}
	if closeErr != nil {
		return userFileExitError(closeErr)
	}
	return nil
}

type newlineTrackingWriter struct {
	w     io.Writer
	last  byte
	wrote bool
}

func (w *newlineTrackingWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	if n > 0 {
		w.last = p[n-1]
		w.wrote = true
	}
	return n, err
}

func isHumanFormat(format string) bool {
	format = strings.TrimSpace(strings.ToLower(format))
	return format == "" || format == "human"
}

func projectExitError(opts *globalOptions, r *analyze.ProjectReport) error {
	applyCommandExitRecommendation(opts, r)
	if opts.strictData {
		for _, st := range r.Providers {
			if st.Name == "privacy" && st.Status == analyze.ProviderStatusSkippedPrivate && st.Skipped > 0 {
				return exitError{code: ExitPrivacy, err: fmt.Errorf("privacy guard skipped %d private module(s); pass --allow-private-remote only if remote provider disclosure is acceptable", st.Skipped)}
			}
		}
	}
	if opts.strictData && r.Summary.ProviderErrors > 0 {
		return providerExitError(fmt.Errorf("%d provider error(s) in --strict-data mode", r.Summary.ProviderErrors))
	}
	if hasAnalysisFailure(r) {
		return analysisExitError(fmt.Errorf("local Go analysis failed"))
	}
	if r.ExitCodeRecommendation != 0 {
		return policyExitError()
	}
	return nil
}

func applyCommandExitRecommendation(opts *globalOptions, r *analyze.ProjectReport) {
	if r == nil {
		return
	}
	if opts.strictData {
		for _, st := range r.Providers {
			if st.Name == "privacy" && st.Status == analyze.ProviderStatusSkippedPrivate && st.Skipped > 0 {
				r.ExitCodeRecommendation = ExitPrivacy
				return
			}
		}
		if r.Summary.ProviderErrors > 0 {
			r.ExitCodeRecommendation = ExitProvider
			return
		}
	}
	if hasAnalysisFailure(r) {
		r.ExitCodeRecommendation = ExitAnalysis
		return
	}
}

func hasAnalysisFailure(r *analyze.ProjectReport) bool {
	for i := range r.Findings {
		f := r.Findings[i]
		if !f.BaselineAccepted && f.Code == "TM-GO-001" {
			return true
		}
	}
	return false
}
