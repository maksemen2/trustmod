package report

import (
	"fmt"
	"io"
	"strings"

	analyze "github.com/maksemen2/trustmod/internal/model"
)

type ProjectRenderer interface {
	RenderProject(io.Writer, *analyze.ProjectReport, HumanOptions) error
}

type CompareRenderer interface {
	RenderCompare(io.Writer, *analyze.CompareReport, HumanOptions) error
}

func ProjectRendererFor(format string) (ProjectRenderer, bool) {
	switch normalizeFormat(format) {
	case "human":
		return humanRenderer{}, true
	case "json":
		return jsonRenderer{}, true
	case "markdown":
		return markdownRenderer{}, true
	case "sarif":
		return sarifRenderer{}, true
	case "junit":
		return junitRenderer{}, true
	default:
		return nil, false
	}
}

func CompareRendererFor(format string) (CompareRenderer, bool) {
	switch normalizeFormat(format) {
	case "human":
		return humanRenderer{}, true
	case "json":
		return jsonRenderer{}, true
	case "markdown":
		return markdownRenderer{}, true
	default:
		return nil, false
	}
}

func normalizeFormat(format string) string {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "human":
		return "human"
	case "md":
		return "markdown"
	default:
		return strings.ToLower(strings.TrimSpace(format))
	}
}

type humanRenderer struct{}

func (humanRenderer) RenderProject(w io.Writer, r *analyze.ProjectReport, opts HumanOptions) error {
	HumanProject(w, r, opts)
	return nil
}

func (humanRenderer) RenderCompare(w io.Writer, r *analyze.CompareReport, opts HumanOptions) error {
	HumanCompare(w, r, opts)
	return nil
}

type jsonRenderer struct{}

func (jsonRenderer) RenderProject(w io.Writer, r *analyze.ProjectReport, _ HumanOptions) error {
	data, err := JSONProject(r)
	return writeRendered(w, data, err)
}

func (jsonRenderer) RenderCompare(w io.Writer, r *analyze.CompareReport, _ HumanOptions) error {
	data, err := JSONCompare(r)
	return writeRendered(w, data, err)
}

type markdownRenderer struct{}

func (markdownRenderer) RenderProject(w io.Writer, r *analyze.ProjectReport, _ HumanOptions) error {
	_, err := w.Write(MarkdownProject(r))
	return err
}

func (markdownRenderer) RenderCompare(w io.Writer, r *analyze.CompareReport, _ HumanOptions) error {
	_, err := w.Write(MarkdownCompare(r))
	return err
}

type sarifRenderer struct{}

func (sarifRenderer) RenderProject(w io.Writer, r *analyze.ProjectReport, _ HumanOptions) error {
	data, err := SARIFProject(r)
	return writeRendered(w, data, err)
}

type junitRenderer struct{}

func (junitRenderer) RenderProject(w io.Writer, r *analyze.ProjectReport, _ HumanOptions) error {
	data, err := JUnitProject(r)
	return writeRendered(w, data, err)
}

func writeRendered(w io.Writer, data []byte, err error) error {
	if err != nil {
		return err
	}
	n, writeErr := w.Write(data)
	if writeErr != nil {
		return writeErr
	}
	if n != len(data) {
		return fmt.Errorf("short write: wrote %d of %d bytes", n, len(data))
	}
	return nil
}
