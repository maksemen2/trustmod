package packagescan

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/maksemen2/trustmod/internal/collect"
	"github.com/maksemen2/trustmod/internal/findings"
	analyze "github.com/maksemen2/trustmod/internal/model"
)

type ScanResult struct {
	Capabilities []analyze.Capability
	Findings     []analyze.Finding
	FilesScanned int
}

type ScanOptions struct {
	AdditionalSourceRules []SourceRule
}

type evidence struct {
	file string
	line int
	text string
}

const maxStoredCapabilityDomains = 8

func ScanModule(ctx context.Context, modulePath, version, dir string, direct bool) (ScanResult, error) {
	return ScanModuleWithOptions(ctx, modulePath, version, dir, direct, ScanOptions{})
}

func ScanModuleWithOptions(ctx context.Context, modulePath, version, dir string, direct bool, opts ScanOptions) (ScanResult, error) {
	if dir == "" {
		return ScanResult{}, nil
	}
	files := make([]string, 0, 128)
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if d.IsDir() {
			name := d.Name()
			if skipAnalysisDir(name) {
				if path != dir {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if len(files) >= 1500 {
			return filepath.SkipAll
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		return ScanResult{}, err
	}
	return ScanFilesWithOptions(ctx, modulePath, version, dir, files, direct, opts)
}

func ScanFiles(ctx context.Context, modulePath, version, dir string, files []string, direct bool) (ScanResult, error) {
	return ScanFilesWithOptions(ctx, modulePath, version, dir, files, direct, ScanOptions{})
}

func ScanFilesWithOptions(ctx context.Context, modulePath, version, dir string, files []string, direct bool, opts ScanOptions) (ScanResult, error) {
	if dir == "" || len(files) == 0 {
		return ScanResult{}, nil
	}
	fset := token.NewFileSet()
	caps := map[string]*analyze.Capability{}
	evidenceByCap := map[string][]evidence{}
	moduleDomainHints := collect.NewSet[string]()
	facts := sourceFacts{}
	seen := collect.NewSet[string]()
	scanned := 0
	for _, path := range files {
		select {
		case <-ctx.Done():
			return ScanResult{}, ctx.Err()
		default:
		}
		if path == "" || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			continue
		}
		if !filepath.IsAbs(path) {
			path = filepath.Join(dir, path)
		}
		clean, err := filepath.Abs(path)
		if err == nil {
			path = clean
		}
		if !seen.Add(path) {
			continue
		}
		if scanned >= 1500 {
			break
		}
		fullFile, err := parser.ParseFile(fset, path, nil, parser.ParseComments|parser.SkipObjectResolution)
		if err != nil {
			continue
		}
		if skipGoFile(dir, path, fullFile) {
			continue
		}
		scanned++
		imports := map[string]string{}
		stringValues := map[string]string{}
		for _, imp := range fullFile.Imports {
			importPath := strings.Trim(imp.Path.Value, `"`)
			name := defaultImportName(importPath)
			if imp.Name != nil {
				name = imp.Name.Name
			}
			if name != "" && name != "_" && name != "." {
				imports[name] = importPath
			}
			for _, capName := range capabilitiesForImport(importPath) {
				addCap(caps, evidenceByCap, capName, path, fset.Position(imp.Pos()).Line, "import "+importPath, direct, analyze.ConfidenceMedium)
			}
		}
		importsHTTP := importsPath(imports, "net/http")
		importsFastHTTP := importsPath(imports, "github.com/valyala/fasthttp")
		fileFacts := sourceFileFacts{Path: path, Imports: imports}
		ast.Inspect(fullFile, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.ValueSpec:
				collectStringValues(x, stringValues)
				collectNetworkDomainHints(x, stringValues, moduleDomainHints)
			case *ast.BasicLit:
				addSourceString(&fileFacts, path, fset, x)
			case *ast.FuncDecl:
				if x.Name != nil && x.Name.Name == "init" {
					addCap(caps, evidenceByCap, "init.side_effect", path, fset.Position(x.Pos()).Line, "init function", direct, analyze.ConfidenceHigh)
				}
			case *ast.CallExpr:
				if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
					fileFacts.Calls = append(fileFacts.Calls, sourceCallFromSelector(path, fset, imports, sel, x, stringValues))
					if id, ok := sel.X.(*ast.Ident); ok {
						importPath := imports[id.Name]
						for _, capName := range capabilitiesForSelector(importPath, sel.Sel.Name) {
							addCap(caps, evidenceByCap, capName, path, fset.Position(sel.Pos()).Line, id.Name+"."+sel.Sel.Name, direct, analyze.ConfidenceHigh)
							if domains := networkDomainsForCall(importPath, sel.Sel.Name, x, stringValues); len(domains) > 0 {
								addCapDomains(caps, capName, domains)
							}
						}
						if importPath == "" {
							addedNetworkClient := false
							if importsHTTP && isHTTPClientMethod(sel) {
								addCap(caps, evidenceByCap, "net.client", path, fset.Position(sel.Pos()).Line, selectorLabel(sel), direct, analyze.ConfidenceMedium)
								if domains := networkDomainsForHTTPClientMethod(sel.Sel.Name, x, stringValues); len(domains) > 0 {
									addCapDomains(caps, "net.client", domains)
								}
								addedNetworkClient = true
							} else if importsHTTP {
								if domains := networkDomainsForHTTPClientMethod(sel.Sel.Name, x, stringValues); len(domains) > 0 {
									addCap(caps, evidenceByCap, "net.client", path, fset.Position(sel.Pos()).Line, selectorLabel(sel), direct, analyze.ConfidenceMedium)
									addCapDomains(caps, "net.client", domains)
									addedNetworkClient = true
								}
							}
							if !addedNetworkClient && importsFastHTTP && isFastHTTPClientMethod(sel) {
								addCap(caps, evidenceByCap, "net.client", path, fset.Position(sel.Pos()).Line, selectorLabel(sel), direct, analyze.ConfidenceMedium)
								if domains := networkDomainsForFastHTTPMethod(sel.Sel.Name, x, stringValues); len(domains) > 0 {
									addCapDomains(caps, "net.client", domains)
								}
							}
						}
					} else {
						addedNetworkClient := false
						if importsHTTP && isHTTPClientMethod(sel) {
							addCap(caps, evidenceByCap, "net.client", path, fset.Position(sel.Pos()).Line, selectorLabel(sel), direct, analyze.ConfidenceMedium)
							if domains := networkDomainsForHTTPClientMethod(sel.Sel.Name, x, stringValues); len(domains) > 0 {
								addCapDomains(caps, "net.client", domains)
							}
							addedNetworkClient = true
						} else if importsHTTP {
							if domains := networkDomainsForHTTPClientMethod(sel.Sel.Name, x, stringValues); len(domains) > 0 {
								addCap(caps, evidenceByCap, "net.client", path, fset.Position(sel.Pos()).Line, selectorLabel(sel), direct, analyze.ConfidenceMedium)
								addCapDomains(caps, "net.client", domains)
								addedNetworkClient = true
							}
						}
						if !addedNetworkClient && importsFastHTTP && isFastHTTPClientMethod(sel) {
							addCap(caps, evidenceByCap, "net.client", path, fset.Position(sel.Pos()).Line, selectorLabel(sel), direct, analyze.ConfidenceMedium)
							if domains := networkDomainsForFastHTTPMethod(sel.Sel.Name, x, stringValues); len(domains) > 0 {
								addCapDomains(caps, "net.client", domains)
							}
						}
					}
				}
			}
			return true
		})
		facts.Files = append(facts.Files, fileFacts)
	}
	if networkCap := caps["net.client"]; networkCap != nil && len(moduleDomainHints) > 0 {
		domains := make([]string, 0, len(moduleDomainHints))
		for domain := range moduleDomainHints {
			domains = append(domains, domain)
		}
		addCapDomains(caps, "net.client", domains)
	}
	out := make([]analyze.Capability, 0, len(caps))
	findingByCode := make(map[string]*analyze.Finding, len(caps))
	for name, cap := range caps {
		evs := evidenceByCap[name]
		sort.Slice(evs, func(i, j int) bool {
			if evs[i].file == evs[j].file {
				return evs[i].line < evs[j].line
			}
			return evs[i].file < evs[j].file
		})
		for i, ev := range evs {
			if i >= 5 {
				break
			}
			file := shortPath(dir, ev.file)
			localPath := ev.file
			if abs, err := filepath.Abs(ev.file); err == nil {
				localPath = abs
			}
			cap.LocalEvidence = append(cap.LocalEvidence, file+":"+strconv.Itoa(ev.line)+" "+ev.text)
			cap.Evidence = append(cap.Evidence, analyze.SourceLocation{
				File:      file,
				Line:      ev.line,
				Text:      ev.text,
				LocalPath: localPath,
			})
		}
		normalizeCapabilityDomains(cap)
		out = append(out, *cap)
		if code := findingCodeForCapability(name); code != "" {
			f := findingByCode[code]
			if f == nil {
				created := findings.New(code, modulePath, version, "local-static-scan")
				created.Direct = direct
				f = &created
				findingByCode[code] = f
			}
			f.Evidence = collect.AppendUnique(f.Evidence, cap.LocalEvidence...)
			if name == "net.client" && len(cap.Domains) > 0 {
				f.Evidence = collect.AppendUnique(f.Evidence, "network domains: "+domainEvidenceSummary(cap.Domains, cap.DomainCount))
			}
		}
	}
	fnds := make([]analyze.Finding, 0, len(findingByCode))
	for _, f := range findingByCode {
		fnds = append(fnds, *f)
	}
	fnds = append(fnds, evaluateSourceRules(modulePath, version, dir, direct, facts, allSourceRules(opts.AdditionalSourceRules))...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	sort.Slice(fnds, func(i, j int) bool { return fnds[i].Code < fnds[j].Code })
	return ScanResult{Capabilities: out, Findings: fnds, FilesScanned: scanned}, nil
}

func skipAnalysisDir(name string) bool {
	switch name {
	case ".git", "vendor", "testdata", "_example", "_examples", "example", "examples", "cmd", "tools", "tool", "scripts", "script", "hack", "upgrade":
		return true
	default:
		return strings.HasPrefix(name, ".")
	}
}

func skipGoFile(root, path string, file *ast.File) bool {
	if file == nil {
		return false
	}
	for _, group := range file.Comments {
		for _, comment := range group.List {
			text := strings.TrimSpace(strings.TrimPrefix(comment.Text, "//"))
			text = strings.TrimSpace(strings.TrimPrefix(text, "/*"))
			if strings.HasPrefix(text, "go:build ") && strings.Contains(text, "ignore") {
				return true
			}
			if strings.HasPrefix(text, "+build ") && strings.Contains(text, "ignore") {
				return true
			}
		}
	}
	if file.Name != nil && file.Name.Name == "main" {
		rel, err := filepath.Rel(root, filepath.Dir(path))
		if err == nil && rel != "." {
			return true
		}
	}
	return false
}

func addCap(caps map[string]*analyze.Capability, ev map[string][]evidence, name, file string, line int, text string, direct bool, confidence analyze.Confidence) {
	c := caps[name]
	if c == nil {
		c = &analyze.Capability{Name: name, FindingCode: findingCodeForCapability(name), Source: "local-static-scan", Confidence: confidence}
		caps[name] = c
	}
	if confidenceRank(confidence) > confidenceRank(c.Confidence) {
		c.Confidence = confidence
	}
	if direct {
		c.DirectCalls++
	} else {
		c.IndirectCalls++
	}
	ev[name] = append(ev[name], evidence{file: file, line: line, text: text})
}

func addCapDomains(caps map[string]*analyze.Capability, name string, domains []string) {
	c := caps[name]
	if c == nil {
		return
	}
	c.Domains = collect.AppendUnique(c.Domains, domains...)
}

func normalizeCapabilityDomains(c *analyze.Capability) {
	if c == nil || len(c.Domains) == 0 {
		return
	}
	sort.Strings(c.Domains)
	c.Domains = collect.UniqueBy(c.Domains, func(v string) string { return v })
	if len(c.Domains) > maxStoredCapabilityDomains {
		c.DomainCount = len(c.Domains)
		c.Domains = append([]string(nil), c.Domains[:maxStoredCapabilityDomains]...)
	}
}

func importsPath(imports map[string]string, path string) bool {
	for _, importPath := range imports {
		if importPath == path {
			return true
		}
	}
	return false
}

func collectStringValues(spec *ast.ValueSpec, values map[string]string) {
	if spec == nil || values == nil {
		return
	}
	for i, name := range spec.Names {
		if name == nil || i >= len(spec.Values) {
			continue
		}
		value, ok := stringValue(spec.Values[i], values)
		if !ok {
			continue
		}
		values[name.Name] = value
	}
}

func collectNetworkDomainHints(spec *ast.ValueSpec, values map[string]string, domains collect.Set[string]) {
	if spec == nil || domains == nil {
		return
	}
	for i, name := range spec.Names {
		if name == nil || i >= len(spec.Values) || !networkDomainHintName(name.Name) {
			continue
		}
		value, ok := stringValue(spec.Values[i], values)
		if !ok {
			continue
		}
		if domain := domainFromNetworkTarget(value); domain != "" {
			domains.Add(domain)
		}
	}
}

func networkDomainHintName(name string) bool {
	name = strings.ToLower(name)
	for _, marker := range []string{"api", "base", "url", "uri", "host", "endpoint", "server"} {
		if strings.Contains(name, marker) {
			return true
		}
	}
	return false
}

func networkDomainsForCall(importPath, name string, call *ast.CallExpr, values map[string]string) []string {
	var candidate string
	switch importPath {
	case "net/http":
		switch name {
		case "Get", "Head", "Post", "PostForm":
			candidate = stringArg(call, values, 0)
		case "NewRequest":
			candidate = stringArg(call, values, 1)
		case "NewRequestWithContext":
			candidate = stringArg(call, values, 2)
		}
	case "net":
		switch name {
		case "Dial", "DialTimeout":
			candidate = stringArg(call, values, 1)
		}
	case "github.com/valyala/fasthttp":
		switch name {
		case "Get", "GetTimeout", "GetDeadline", "Post":
			candidate = stringArg(call, values, 1)
		}
	}
	if candidate == "" {
		return nil
	}
	domain := domainFromNetworkTarget(candidate)
	if domain == "" {
		return nil
	}
	return []string{domain}
}

func networkDomainsForHTTPClientMethod(name string, call *ast.CallExpr, values map[string]string) []string {
	switch name {
	case "Get", "Head", "Post", "PostForm":
		candidate := stringArg(call, values, 0)
		if domain := domainFromNetworkTarget(candidate); domain != "" {
			return []string{domain}
		}
	}
	return nil
}

func isHTTPClientMethod(sel *ast.SelectorExpr) bool {
	if sel == nil || sel.Sel == nil {
		return false
	}
	switch sel.Sel.Name {
	case "Do", "Get", "Head", "Post", "PostForm":
		label := strings.ToLower(selectorLabel(sel))
		return strings.Contains(label, "client.")
	default:
		return false
	}
}

func networkDomainsForFastHTTPMethod(name string, call *ast.CallExpr, values map[string]string) []string {
	if name != "SetRequestURI" {
		return nil
	}
	candidate := stringArg(call, values, 0)
	if domain := domainFromNetworkTarget(candidate); domain != "" {
		return []string{domain}
	}
	return nil
}

func isFastHTTPClientMethod(sel *ast.SelectorExpr) bool {
	if sel == nil || sel.Sel == nil {
		return false
	}
	switch sel.Sel.Name {
	case "SetRequestURI":
		return true
	case "Do", "DoTimeout", "DoDeadline", "DoRedirects":
		label := strings.ToLower(selectorLabel(sel))
		return strings.Contains(label, "client.")
	default:
		return false
	}
}

func stringArg(call *ast.CallExpr, values map[string]string, index int) string {
	if call == nil || index < 0 || index >= len(call.Args) {
		return ""
	}
	value, ok := stringValue(call.Args[index], values)
	if !ok {
		return ""
	}
	return value
}

func stringValue(expr ast.Expr, values map[string]string) (string, bool) {
	switch x := expr.(type) {
	case *ast.BasicLit:
		if x.Kind != token.STRING {
			return "", false
		}
		value, err := strconv.Unquote(x.Value)
		if err != nil {
			return "", false
		}
		return value, true
	case *ast.Ident:
		if values == nil {
			return "", false
		}
		value, ok := values[x.Name]
		return value, ok
	case *ast.BinaryExpr:
		if x.Op != token.ADD {
			return "", false
		}
		left, ok := stringValue(x.X, values)
		if !ok {
			return "", false
		}
		right, ok := stringValue(x.Y, values)
		if !ok {
			return "", false
		}
		return left + right, true
	case *ast.ParenExpr:
		return stringValue(x.X, values)
	default:
		return "", false
	}
}

func domainFromNetworkTarget(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "://") {
		parsed, err := url.Parse(raw)
		if err != nil {
			return ""
		}
		return cleanDomain(parsed.Hostname())
	}
	if strings.ContainsAny(raw, "%{}") {
		return ""
	}
	host, _, err := net.SplitHostPort(raw)
	if err == nil {
		return cleanDomain(host)
	}
	if strings.Contains(raw, "/") || strings.Contains(raw, ":") {
		return ""
	}
	return cleanDomain(raw)
}

func cleanDomain(host string) string {
	host = strings.Trim(strings.ToLower(strings.TrimSpace(host)), ".[]")
	if host == "" || !strings.Contains(host, ".") || strings.ContainsAny(host, "/\\ %{}_") {
		return ""
	}
	if net.ParseIP(host) != nil {
		return ""
	}
	return host
}

func selectorLabel(sel *ast.SelectorExpr) string {
	if sel == nil || sel.Sel == nil {
		return ""
	}
	switch x := sel.X.(type) {
	case *ast.Ident:
		return x.Name + "." + sel.Sel.Name
	case *ast.SelectorExpr:
		return selectorLabel(x) + "." + sel.Sel.Name
	default:
		return sel.Sel.Name
	}
}

func domainEvidenceSummary(domains []string, total int) string {
	if len(domains) == 0 {
		return ""
	}
	limit := len(domains)
	if limit > 5 {
		limit = 5
	}
	parts := append([]string(nil), domains[:limit]...)
	if total <= 0 {
		total = len(domains)
	}
	if more := total - limit; more > 0 {
		parts = append(parts, "+"+strconv.Itoa(more)+" more")
	}
	return strings.Join(parts, ", ")
}

func capabilitiesForImport(importPath string) []string {
	return importCapabilities[importPath]
}

func capabilitiesForSelector(importPath, name string) []string {
	return selectorCapabilities[importPath+"."+name]
}

func findingCodeForCapability(name string) string {
	return capabilityFindingCodes[name]
}

type capabilityRule struct {
	Name        string
	Imports     []string
	Selectors   []string
	FindingCode string
}

var capabilityRules = []capabilityRule{
	{Name: "process.exec", Selectors: []string{"os/exec.Command", "os/exec.CommandContext"}, FindingCode: "TM-CAP-001"},
	{Name: "net.client", Selectors: []string{"net.Dial", "net.DialTimeout", "net.DialTCP", "net.DialUDP", "net.DialUnix", "net/http.Get", "net/http.Post", "net/http.PostForm", "net/http.Head", "net/http.NewRequest", "net/http.NewRequestWithContext", "github.com/valyala/fasthttp.Do", "github.com/valyala/fasthttp.DoTimeout", "github.com/valyala/fasthttp.DoDeadline", "github.com/valyala/fasthttp.DoRedirects", "github.com/valyala/fasthttp.Get", "github.com/valyala/fasthttp.GetTimeout", "github.com/valyala/fasthttp.GetDeadline", "github.com/valyala/fasthttp.Post"}, FindingCode: "TM-CAP-003"},
	{Name: "net.server", Selectors: []string{"net.Listen", "net.ListenTCP", "net.ListenUDP", "net.ListenUnix", "net/http.ListenAndServe", "net/http.ListenAndServeTLS", "net/rpc.Accept", "github.com/valyala/fasthttp.ListenAndServe", "github.com/valyala/fasthttp.ListenAndServeTLS", "github.com/valyala/fasthttp.Serve"}, FindingCode: "TM-CAP-003"},
	{Name: "fs.read", Selectors: []string{"os.ReadFile", "os.Open", "os.OpenFile"}},
	{Name: "fs.write", Selectors: []string{"os.OpenFile", "os.WriteFile", "os.Create", "os.CreateTemp", "os.Mkdir", "os.MkdirAll", "os.Rename", "os.Truncate", "os.Chmod", "os.Chown", "os.Chtimes", "os.Symlink", "os.Link"}, FindingCode: "TM-CAP-002"},
	{Name: "fs.delete", Selectors: []string{"os.Remove", "os.RemoveAll"}, FindingCode: "TM-CAP-002"},
	{Name: "env.read", Selectors: []string{"os.Getenv", "os.LookupEnv", "os.Environ", "os.ExpandEnv"}, FindingCode: "TM-CAP-005"},
	{Name: "env.write", Selectors: []string{"os.Setenv", "os.Unsetenv", "os.Clearenv"}, FindingCode: "TM-CAP-005"},
	{Name: "unsafe", Imports: []string{"unsafe"}, FindingCode: "TM-CAP-004"},
	{Name: "cgo", Imports: []string{"C"}, FindingCode: "TM-CAP-004"},
	{Name: "syscall", Imports: []string{"syscall"}, FindingCode: "TM-CAP-007"},
	{Name: "plugin.load", Imports: []string{"plugin"}, Selectors: []string{"plugin.Open"}, FindingCode: "TM-CAP-007"},
	{Name: "reflection", Imports: []string{"reflect"}},
	{Name: "crypto.weak", Imports: []string{"crypto/md5", "crypto/sha1", "crypto/des", "crypto/rc4"}},
	{Name: "random.insecure", Selectors: []string{"math/rand.Int", "math/rand.Intn", "math/rand.Read", "math/rand.Float64", "math/rand.New", "math/rand.NewSource"}, FindingCode: "TM-CAP-006"},
	{Name: "time.clock", Selectors: []string{"time.Now", "time.Since", "time.Until"}},
	{Name: "database.client", Selectors: []string{"database/sql.Open", "database/sql.OpenDB"}},
	{Name: "init.side_effect", FindingCode: "TM-CAP-008"},
}

var (
	importCapabilities     = map[string][]string{}
	selectorCapabilities   = map[string][]string{}
	capabilityFindingCodes = map[string]string{}
)

func init() {
	for _, rule := range capabilityRules {
		for _, importPath := range rule.Imports {
			importCapabilities[importPath] = append(importCapabilities[importPath], rule.Name)
		}
		for _, selector := range rule.Selectors {
			selectorCapabilities[selector] = append(selectorCapabilities[selector], rule.Name)
		}
		if rule.FindingCode != "" {
			capabilityFindingCodes[rule.Name] = rule.FindingCode
		}
	}
}

func capabilityRegistryNames() []string {
	out := make([]string, 0, len(capabilityRules))
	for _, rule := range capabilityRules {
		out = append(out, rule.Name)
	}
	return out
}

func shortPath(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err == nil && !strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(path)
}

func defaultImportName(importPath string) string {
	if importPath == "" {
		return ""
	}
	if importPath == "C" {
		return "C"
	}
	i := strings.LastIndex(importPath, "/")
	if i >= 0 {
		return importPath[i+1:]
	}
	return importPath
}

func confidenceRank(c analyze.Confidence) int {
	switch c {
	case analyze.ConfidenceHigh:
		return 3
	case analyze.ConfidenceMedium:
		return 2
	case analyze.ConfidenceLow:
		return 1
	default:
		return 0
	}
}
