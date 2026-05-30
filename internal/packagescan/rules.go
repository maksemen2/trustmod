package packagescan

import (
	"go/ast"
	"go/token"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/maksemen2/trustmod/internal/collect"
	"github.com/maksemen2/trustmod/internal/findings"
	analyze "github.com/maksemen2/trustmod/internal/model"
)

type sourceFacts struct {
	Files []sourceFileFacts
}

type sourceFileFacts struct {
	Path    string
	Imports map[string]string
	Calls   []sourceCall
	Strings []sourceString
}

type sourceCall struct {
	File       string
	Line       int
	ImportPath string
	Name       string
	Selector   string
	Text       string
	Args       []string
}

type sourceString struct {
	File  string
	Line  int
	Value string
}

type SourceRule interface {
	ID() string
	Code() string
	Title() string
	Description() string
	Category() string
	Severity() analyze.Severity
	VerdictImpact() analyze.Verdict
	Confidence() analyze.Confidence
	Remediation() []string
	Source() string
	Match(sourceFacts) []sourceRuleMatch
}

type sourceRuleFunc struct {
	id          string
	code        string
	title       string
	description string
	match       func(sourceFacts) []sourceRuleMatch
}

type sourceRuleMatch struct {
	Evidence []evidence
}

func builtInSourceRules() []SourceRule {
	return []SourceRule{
		sourceRuleFunc{
			id:          "go-exec-base64",
			code:        "TM-MAL-001",
			description: "Base64-decoded data is used near process execution.",
			match:       matchExecBase64,
		},
		sourceRuleFunc{
			id:          "go-download-exec",
			code:        "TM-MAL-002",
			description: "Network download, filesystem write, chmod, and process execution appear in one source file.",
			match:       matchDownloadAndExec,
		},
		sourceRuleFunc{
			id:          "go-exfiltrate-sensitive-data",
			code:        "TM-MAL-003",
			description: "Sensitive local data is read and a network client is used in one source file.",
			match:       matchSensitiveDataExfiltration,
		},
		sourceRuleFunc{
			id:          "go-passwd-access",
			code:        "TM-MAL-004",
			description: "The package reads /etc/passwd.",
			match:       matchPasswdAccess,
		},
		sourceRuleFunc{
			id:          "go-shady-links",
			code:        "TM-MAL-005",
			description: "The package contains URL literals with suspicious top-level domains.",
			match:       matchSuspiciousURLs,
		},
		sourceRuleFunc{
			id:          "go-shell-downloader-pipeline",
			code:        "TM-MAL-006",
			description: "A shell command downloads remote content and pipes or executes it.",
			match:       matchShellDownloaderPipeline,
		},
	}
}

func (r sourceRuleFunc) ID() string {
	return r.id
}

func (r sourceRuleFunc) Code() string {
	return r.code
}

func (r sourceRuleFunc) Title() string {
	return r.title
}

func (r sourceRuleFunc) Description() string {
	return r.description
}

func (r sourceRuleFunc) Category() string {
	return ""
}

func (r sourceRuleFunc) Severity() analyze.Severity {
	return ""
}

func (r sourceRuleFunc) VerdictImpact() analyze.Verdict {
	return ""
}

func (r sourceRuleFunc) Confidence() analyze.Confidence {
	return ""
}

func (r sourceRuleFunc) Remediation() []string {
	return nil
}

func (r sourceRuleFunc) Source() string {
	return "local-source-rule"
}

func (r sourceRuleFunc) Match(facts sourceFacts) []sourceRuleMatch {
	if r.match == nil {
		return nil
	}
	return r.match(facts)
}

func sourceCallFromSelector(path string, fset *token.FileSet, imports map[string]string, sel *ast.SelectorExpr, call *ast.CallExpr, values map[string]string) sourceCall {
	label := selectorLabel(sel)
	root := selectorRoot(sel.X)
	importPath := imports[root]
	selector := label
	if importPath != "" {
		suffix := strings.TrimPrefix(label, root)
		suffix = strings.TrimPrefix(suffix, ".")
		if suffix != "" {
			selector = importPath + "." + suffix
		}
	}
	args := make([]string, len(call.Args))
	for i, arg := range call.Args {
		if value, ok := stringValue(arg, values); ok {
			args[i] = value
		}
	}
	return sourceCall{
		File:       path,
		Line:       fset.Position(sel.Pos()).Line,
		ImportPath: importPath,
		Name:       sel.Sel.Name,
		Selector:   selector,
		Text:       label,
		Args:       args,
	}
}

func selectorRoot(expr ast.Expr) string {
	switch x := expr.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return selectorRoot(x.X)
	default:
		return ""
	}
}

func addSourceString(file *sourceFileFacts, path string, fset *token.FileSet, lit *ast.BasicLit) {
	if file == nil || lit == nil || lit.Kind != token.STRING {
		return
	}
	value, err := strconv.Unquote(lit.Value)
	if err != nil {
		return
	}
	file.Strings = append(file.Strings, sourceString{File: path, Line: fset.Position(lit.Pos()).Line, Value: value})
}

func evaluateSourceRules(modulePath, version, dir string, direct bool, facts sourceFacts, rules []SourceRule) []analyze.Finding {
	byCode := map[string]*analyze.Finding{}
	for _, rule := range rules {
		if rule == nil {
			continue
		}
		code := rule.Code()
		for _, match := range rule.Match(facts) {
			if len(match.Evidence) == 0 {
				continue
			}
			f := byCode[code]
			if f == nil {
				created := findingForSourceRule(rule, modulePath, version)
				created.Direct = direct
				f = &created
				byCode[code] = f
			}
			for _, ev := range match.Evidence {
				file := shortPath(dir, ev.file)
				if f.File == "" {
					f.File = file
					f.Line = ev.line
				}
				f.Evidence = collect.AppendUnique(f.Evidence, file+":"+strconv.Itoa(ev.line)+" "+ev.text)
			}
		}
	}
	out := make([]analyze.Finding, 0, len(byCode))
	for _, f := range byCode {
		out = append(out, *f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	return out
}

func findingForSourceRule(rule SourceRule, modulePath, version string) analyze.Finding {
	source := rule.Source()
	if source == "" {
		source = "local-source-rule"
	}
	f := findings.New(rule.Code(), modulePath, version, source)
	_, cataloged := findings.Lookup(rule.Code())
	if cataloged {
		return f
	}
	if rule.Title() != "" {
		f.Title = rule.Title()
	}
	if rule.Description() != "" {
		f.Description = rule.Description()
	}
	if rule.Category() != "" {
		f.Category = rule.Category()
	}
	if rule.Severity() != "" {
		f.Severity = rule.Severity()
	}
	if rule.VerdictImpact() != "" {
		f.VerdictImpact = rule.VerdictImpact()
	}
	if rule.Confidence() != "" {
		f.Confidence = rule.Confidence()
	}
	if remediation := rule.Remediation(); len(remediation) > 0 {
		f.Remediation = append([]string(nil), remediation...)
	}
	return findings.WithStableID(f, rule.Code(), modulePath, version, source, rule.ID())
}

func allSourceRules(extra []SourceRule) []SourceRule {
	rules := builtInSourceRules()
	if len(extra) == 0 {
		return rules
	}
	out := make([]SourceRule, 0, len(rules)+len(extra))
	out = append(out, rules...)
	out = append(out, extra...)
	return out
}

func matchExecBase64(facts sourceFacts) []sourceRuleMatch {
	var matches []sourceRuleMatch
	for _, file := range facts.Files {
		encoded, okEncoded := firstCall(file.Calls, isBase64DecodeCall)
		execCall, okExec := firstCall(file.Calls, isProcessExecCall)
		if okEncoded && okExec {
			matches = append(matches, sourceRuleMatch{Evidence: []evidence{callEvidence(encoded), callEvidence(execCall)}})
		}
	}
	return matches
}

func matchDownloadAndExec(facts sourceFacts) []sourceRuleMatch {
	var matches []sourceRuleMatch
	for _, file := range facts.Files {
		networkCall, okNetwork := firstNetworkClientCall(file)
		writeCall, okWrite := firstCall(file.Calls, isFilesystemWriteCall)
		chmodCall, okChmod := firstCall(file.Calls, isChmodCall)
		execCall, okExec := firstCall(file.Calls, isProcessExecCall)
		if okNetwork && okWrite && okChmod && okExec {
			matches = append(matches, sourceRuleMatch{Evidence: []evidence{
				callEvidence(networkCall),
				callEvidence(writeCall),
				callEvidence(chmodCall),
				callEvidence(execCall),
			}})
		}
	}
	return matches
}

func matchSensitiveDataExfiltration(facts sourceFacts) []sourceRuleMatch {
	var matches []sourceRuleMatch
	for _, file := range facts.Files {
		readCall, okRead := firstCall(file.Calls, isSensitiveReadCall)
		networkCall, okNetwork := firstNetworkClientCall(file)
		if okRead && okNetwork {
			matches = append(matches, sourceRuleMatch{Evidence: []evidence{callEvidence(readCall), callEvidence(networkCall)}})
		}
	}
	return matches
}

func matchPasswdAccess(facts sourceFacts) []sourceRuleMatch {
	var matches []sourceRuleMatch
	for _, file := range facts.Files {
		if call, ok := firstCall(file.Calls, isPasswdReadCall); ok {
			matches = append(matches, sourceRuleMatch{Evidence: []evidence{callEvidence(call)}})
		}
	}
	return matches
}

func matchSuspiciousURLs(facts sourceFacts) []sourceRuleMatch {
	seen := collect.NewSet[string]()
	var matches []sourceRuleMatch
	for _, file := range facts.Files {
		for _, literal := range file.Strings {
			for _, raw := range urlLiterals(literal.Value) {
				domain := domainFromNetworkTarget(raw)
				if !suspiciousDomain(domain) {
					continue
				}
				key := literal.File + "\x00" + strconv.Itoa(literal.Line) + "\x00" + domain
				if !seen.Add(key) {
					continue
				}
				matches = append(matches, sourceRuleMatch{Evidence: []evidence{{
					file: literal.File,
					line: literal.Line,
					text: "suspicious URL domain: " + domain,
				}}})
			}
		}
	}
	return matches
}

func matchShellDownloaderPipeline(facts sourceFacts) []sourceRuleMatch {
	var matches []sourceRuleMatch
	for _, file := range facts.Files {
		for _, call := range file.Calls {
			if isProcessExecCall(call) && shellDownloaderCommand(call) {
				matches = append(matches, sourceRuleMatch{Evidence: []evidence{callEvidence(call)}})
			}
		}
	}
	return matches
}

func firstCall(calls []sourceCall, pred func(sourceCall) bool) (sourceCall, bool) {
	for _, call := range calls {
		if pred(call) {
			return call, true
		}
	}
	return sourceCall{}, false
}

func firstNetworkClientCall(file sourceFileFacts) (sourceCall, bool) {
	for _, call := range file.Calls {
		if isNetworkClientCall(file, call) {
			return call, true
		}
	}
	return sourceCall{}, false
}

func callEvidence(call sourceCall) evidence {
	return evidence{file: call.File, line: call.Line, text: call.Text}
}

func isProcessExecCall(call sourceCall) bool {
	switch call.Selector {
	case "os/exec.Command", "os/exec.CommandContext":
		return true
	default:
		return false
	}
}

func isBase64DecodeCall(call sourceCall) bool {
	if call.ImportPath != "encoding/base64" {
		return false
	}
	switch call.Name {
	case "DecodeString", "NewDecoder":
		return true
	default:
		return false
	}
}

func isNetworkClientCall(file sourceFileFacts, call sourceCall) bool {
	switch call.Selector {
	case "net.Dial", "net.DialTimeout", "net.DialTCP", "net.DialUDP", "net.DialUnix",
		"net/http.Get", "net/http.Post", "net/http.PostForm", "net/http.Head", "net/http.NewRequest", "net/http.NewRequestWithContext",
		"github.com/valyala/fasthttp.Do", "github.com/valyala/fasthttp.DoTimeout", "github.com/valyala/fasthttp.DoDeadline", "github.com/valyala/fasthttp.DoRedirects",
		"github.com/valyala/fasthttp.Get", "github.com/valyala/fasthttp.GetTimeout", "github.com/valyala/fasthttp.GetDeadline", "github.com/valyala/fasthttp.Post":
		return true
	}
	if call.ImportPath == "net/http" && call.Name == "Do" {
		return true
	}
	if importsPath(file.Imports, "net/http") && isHTTPClientMethodName(call.Name) && strings.Contains(strings.ToLower(call.Text), "client.") {
		return true
	}
	if importsPath(file.Imports, "github.com/valyala/fasthttp") {
		if call.Name == "SetRequestURI" {
			return true
		}
		if isFastHTTPClientMethodName(call.Name) && strings.Contains(strings.ToLower(call.Text), "client.") {
			return true
		}
	}
	return false
}

func isHTTPClientMethodName(name string) bool {
	switch name {
	case "Do", "Get", "Head", "Post", "PostForm":
		return true
	default:
		return false
	}
}

func isFastHTTPClientMethodName(name string) bool {
	switch name {
	case "Do", "DoTimeout", "DoDeadline", "DoRedirects":
		return true
	default:
		return false
	}
}

func isFilesystemWriteCall(call sourceCall) bool {
	switch call.Selector {
	case "os.WriteFile", "os.Create", "os.CreateTemp", "os.OpenFile", "io/ioutil.WriteFile", "io.Copy":
		return true
	default:
		return false
	}
}

func isChmodCall(call sourceCall) bool {
	return call.Selector == "os.Chmod"
}

func isSensitiveReadCall(call sourceCall) bool {
	switch call.Selector {
	case "os.Environ":
		return true
	case "os.Getenv", "os.LookupEnv":
		return len(call.Args) > 0 && sensitiveEnvName(call.Args[0])
	case "os.ReadFile", "os.Open", "os.OpenFile", "io/ioutil.ReadFile":
		return len(call.Args) > 0 && sensitivePath(call.Args[0])
	default:
		return false
	}
}

func isPasswdReadCall(call sourceCall) bool {
	switch call.Selector {
	case "os.ReadFile", "os.Open", "os.OpenFile", "io/ioutil.ReadFile":
		return len(call.Args) > 0 && normalizeSlash(call.Args[0]) == "/etc/passwd"
	default:
		return false
	}
}

func sensitiveEnvName(name string) bool {
	name = strings.ToUpper(strings.TrimSpace(name))
	for _, marker := range []string{"TOKEN", "SECRET", "PASSWORD", "PASSWD", "PRIVATE_KEY", "ACCESS_KEY", "API_KEY", "GITHUB_", "AWS_", "GCP_", "AZURE_"} {
		if strings.Contains(name, marker) {
			return true
		}
	}
	return false
}

func sensitivePath(path string) bool {
	path = normalizeSlash(path)
	for _, marker := range []string{"/etc/passwd", "/.env", ".ssh/", "id_rsa", "id_ed25519", ".netrc", ".npmrc", ".pypirc", ".docker/config.json", ".kube/config", "credentials"} {
		if strings.Contains(path, marker) {
			return true
		}
	}
	return false
}

func normalizeSlash(path string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(path)), "\\", "/")
}

func shellDownloaderCommand(call sourceCall) bool {
	for _, arg := range call.Args {
		cmd := strings.ToLower(arg)
		if !strings.Contains(cmd, "curl ") && !strings.Contains(cmd, "wget ") {
			continue
		}
		if strings.Contains(cmd, "| sh") || strings.Contains(cmd, "| bash") || strings.Contains(cmd, " sh -") || strings.Contains(cmd, " bash -") {
			return true
		}
		if strings.Contains(cmd, "chmod +x") && (strings.Contains(cmd, "./") || strings.Contains(cmd, "/tmp/")) {
			return true
		}
	}
	return false
}

var urlLiteralRE = regexp.MustCompile(`https?://[^\s"'<>]+`)

func urlLiterals(value string) []string {
	matches := urlLiteralRE.FindAllString(value, -1)
	out := matches[:0]
	for _, match := range matches {
		match = strings.TrimRight(match, ".,);]")
		if _, err := url.Parse(match); err == nil {
			out = append(out, match)
		}
	}
	return out
}

func suspiciousDomain(domain string) bool {
	if domain == "" {
		return false
	}
	i := strings.LastIndex(domain, ".")
	if i < 0 || i == len(domain)-1 {
		return false
	}
	_, ok := suspiciousTLDs[domain[i+1:]]
	return ok
}

var suspiciousTLDs = map[string]struct{}{
	"cam":      {},
	"cf":       {},
	"click":    {},
	"country":  {},
	"download": {},
	"ga":       {},
	"gq":       {},
	"icu":      {},
	"ml":       {},
	"monster":  {},
	"mov":      {},
	"rest":     {},
	"stream":   {},
	"support":  {},
	"tk":       {},
	"top":      {},
	"work":     {},
	"xyz":      {},
	"zip":      {},
}
