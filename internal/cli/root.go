package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/maksemen2/trustmod/internal/analyze"
	"github.com/maksemen2/trustmod/internal/buildinfo"
	"github.com/maksemen2/trustmod/internal/config"
	"github.com/maksemen2/trustmod/internal/gomod"
	"github.com/maksemen2/trustmod/internal/model"
	"github.com/maksemen2/trustmod/internal/policy"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type BuildInfo = buildinfo.Info

type globalOptions struct {
	build               BuildInfo
	format              string
	outFile             string
	profile             string
	failOn              []string
	configPath          string
	policyPath          string
	baselinePath        string
	rulesPath           string
	cacheDir            string
	cacheTTL            time.Duration
	noCache             bool
	cwd                 string
	offline             bool
	allowPrivateRemote  bool
	strictData          bool
	includeTests        bool
	includeTools        bool
	tags                string
	runGovulncheck      bool
	govulncheckPath     string
	govulncheckTimeout  time.Duration
	githubToken         string
	disabledProviders   map[string]bool
	disableGovulncheck  bool
	disableScorecard    bool
	disableDepsdev      bool
	disableGithub       bool
	disableOSV          bool
	quiet               bool
	noColor             bool
	verbose             bool
	debug               bool
	timeout             time.Duration
	concurrency         int
	projectRoot         string
	configApplied       bool
	configLoadedPath    string
	rulesPathConfigured bool
}

func NewRootCommand(build BuildInfo) *cobra.Command {
	opts := &globalOptions{build: build, format: "human", profile: "backend-service", timeout: 20 * time.Second, govulncheckTimeout: 2 * time.Minute, cacheTTL: 24 * time.Hour, concurrency: 8, disabledProviders: map[string]bool{}}
	if os.Getenv("TRUSTMOD_OFFLINE") == "1" || os.Getenv("TRUSTMOD_OFFLINE") == "true" {
		opts.offline = true
	}
	if os.Getenv("TRUSTMOD_NO_COLOR") == "1" || os.Getenv("TRUSTMOD_NO_COLOR") == "true" {
		opts.noColor = true
	}
	root := &cobra.Command{
		Use:     "trustmod",
		Short:   "Go-native dependency adoption advisor",
		Long:    "trustmod reviews Go module dependency changes and reports ALLOW, REVIEW, or BLOCK under policy-as-code.",
		Version: build.Version,
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Help()
		},
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.applyConfig(cmd); err != nil {
				return err
			}
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		return usageExitError(err)
	})
	root.PersistentFlags().StringVar(&opts.format, "format", "human", "output format: human, json, markdown, sarif, junit")
	root.PersistentFlags().StringVar(&opts.outFile, "out", "", "write report to file instead of stdout")
	root.PersistentFlags().StringVar(&opts.outFile, "output", "", "write report to file instead of stdout")
	root.PersistentFlags().StringVar(&opts.profile, "profile", "backend-service", "policy profile")
	root.PersistentFlags().StringSliceVar(&opts.failOn, "fail-on", nil, "override policy fail_on verdicts: block, review, allow")
	root.PersistentFlags().StringVar(&opts.configPath, "config", "", "config file path")
	root.PersistentFlags().StringVar(&opts.policyPath, "policy", "", "policy file path")
	root.PersistentFlags().StringVar(&opts.baselinePath, "baseline", "", "baseline file path")
	root.PersistentFlags().StringVar(&opts.rulesPath, "rules", "", "custom source rules YAML path")
	root.PersistentFlags().StringVar(&opts.cacheDir, "cache-dir", "", "cache directory")
	root.PersistentFlags().DurationVar(&opts.cacheTTL, "cache-ttl", 24*time.Hour, "provider response cache TTL")
	root.PersistentFlags().BoolVar(&opts.noCache, "no-cache", false, "disable provider response cache")
	root.PersistentFlags().StringVar(&opts.cwd, "cwd", "", "working directory for local project analysis")
	root.PersistentFlags().BoolVar(&opts.offline, "offline", opts.offline, "use local analysis and cache only")
	root.PersistentFlags().BoolVar(&opts.allowPrivateRemote, "allow-private-remote", false, "allow remote provider requests for private module paths")
	root.PersistentFlags().BoolVar(&opts.strictData, "strict-data", false, "fail when an enabled data provider fails")
	root.PersistentFlags().BoolVar(&opts.includeTests, "include-tests", false, "include test packages in local package analysis")
	root.PersistentFlags().BoolVar(&opts.includeTools, "include-tools", false, "include tool dependencies where supported")
	root.PersistentFlags().StringVar(&opts.tags, "tags", "", "comma-separated build tags for go list")
	root.PersistentFlags().BoolVar(&opts.runGovulncheck, "govulncheck", false, "run local govulncheck when available")
	root.PersistentFlags().StringVar(&opts.govulncheckPath, "govulncheck-path", "", "path to govulncheck executable")
	root.PersistentFlags().DurationVar(&opts.govulncheckTimeout, "govulncheck-timeout", 2*time.Minute, "timeout for local govulncheck runs")
	root.PersistentFlags().StringVar(&opts.githubToken, "github-token", "", "GitHub token for API rate limits; prefer TRUSTMOD_GITHUB_TOKEN in CI")
	root.PersistentFlags().BoolVar(&opts.disableGovulncheck, "disable-govulncheck", false, "disable local govulncheck provider")
	root.PersistentFlags().BoolVar(&opts.disableScorecard, "disable-scorecard", false, "disable OpenSSF Scorecard provider")
	root.PersistentFlags().BoolVar(&opts.disableDepsdev, "disable-depsdev", false, "disable deps.dev provider")
	root.PersistentFlags().BoolVar(&opts.disableGithub, "disable-github", false, "disable GitHub provider")
	root.PersistentFlags().BoolVar(&opts.disableOSV, "disable-osv", false, "disable OSV provider")
	root.PersistentFlags().BoolVar(&opts.quiet, "quiet", false, "print only the final verdict in human output")
	root.PersistentFlags().BoolVar(&opts.noColor, "no-color", opts.noColor, "disable color output")
	root.PersistentFlags().BoolVarP(&opts.verbose, "verbose", "v", false, "print additional privacy and provider details")
	root.PersistentFlags().BoolVar(&opts.debug, "debug", false, "print debug-level details when supported")
	root.PersistentFlags().DurationVar(&opts.timeout, "timeout", 20*time.Second, "per-command/provider timeout")
	root.PersistentFlags().IntVar(&opts.concurrency, "concurrency", 8, "maximum concurrency per analysis phase")
	root.AddCommand(
		newVersionCommand(opts),
		newInitCommand(opts),
		newCheckCommand(opts),
		newAuditCommand(opts),
		newDiffCommand(opts),
		newCompareCommand(opts),
		newAddCommand(opts),
		newExplainCommand(opts),
		newPolicyCommand(opts),
		newBaselineCommand(opts),
		newCacheCommand(opts),
		newDoctorCommand(opts),
		newGraphCommand(opts),
		newReportCommand(opts),
	)
	return root
}

func (o *globalOptions) analyzeOptions() analyze.Options {
	return analyze.Options{
		TrustmodVersion:    o.build.Version,
		WorkingDir:         o.defaultCWD(),
		ConfigPath:         o.configPath,
		PolicyPath:         o.policyPath,
		BaselinePath:       o.baselinePath,
		CustomRulesPath:    o.rulesPath,
		CacheDir:           o.cacheDir,
		CacheTTL:           o.cacheTTL,
		NoCache:            o.noCache,
		Profile:            o.profile,
		PolicyFailOn:       append([]string(nil), o.failOn...),
		Offline:            o.offline,
		AllowPrivateRemote: o.allowPrivateRemote,
		IncludeTests:       o.includeTests,
		IncludeTools:       o.includeTools,
		Tags:               o.tags,
		RunGovulncheck:     o.runGovulncheck,
		GovulncheckPath:    o.govulncheckPath,
		GovulncheckTimeout: o.govulncheckTimeout,
		GitHubToken:        o.githubToken,
		DisabledProviders:  cloneProviderMap(o.disabledProviders),
		StrictData:         o.strictData,
		NoColor:            o.noColor,
		Verbose:            o.verbose,
		Debug:              o.debug,
		Concurrency:        o.concurrency,
		Timeout:            o.timeout,
	}
}

func (o *globalOptions) analyzer() (*analyze.Analyzer, error) {
	a, err := analyze.NewAnalyzer(o.analyzeOptions())
	if err != nil {
		return nil, configExitError(err)
	}
	return a, nil
}

func (o *globalOptions) applyPolicyOverrides(pol policy.Policy) policy.Policy {
	if len(o.failOn) == 0 {
		return pol
	}
	pol.FailOn = pol.FailOn[:0]
	for _, v := range o.failOn {
		v = strings.ToUpper(strings.TrimSpace(v))
		if v != "" {
			pol.FailOn = append(pol.FailOn, v)
		}
	}
	return pol
}

func (o *globalOptions) applyConfig(cmd *cobra.Command) error {
	if o.configApplied {
		return nil
	}
	o.configApplied = true
	root := cmd.Root()
	changed := func(name string) bool {
		f := root.PersistentFlags().Lookup(name)
		return f != nil && f.Changed
	}
	profileConfigured := changed("profile")
	configRoot, err := projectRootFor(preConfigCWD(o, changed))
	if err != nil {
		return configExitError(err)
	}
	cfg, loadedPath, loaded, err := config.LoadFrom(configRoot, o.configPath)
	if err != nil {
		return configExitError(err)
	}
	if loaded {
		o.configLoadedPath = loadedPath
		if cfg.Output != "" && !changed("format") {
			o.format = cfg.Output
		}
		if cfg.DefaultProfile != "" && !changed("profile") {
			o.profile = cfg.DefaultProfile
			profileConfigured = true
		}
		if len(cfg.FailOn) > 0 && !changed("fail-on") {
			o.failOn = append([]string(nil), cfg.FailOn...)
		}
		if cfg.PolicyPath != "" && !changed("policy") {
			o.policyPath = cfg.PolicyPath
		}
		if cfg.BaselinePath != "" && !changed("baseline") {
			o.baselinePath = cfg.BaselinePath
		}
		if cfg.RulesPath != "" && !changed("rules") {
			o.rulesPath = cfg.RulesPath
			o.rulesPathConfigured = true
		}
		if cfg.CacheDir != "" && !changed("cache-dir") {
			o.cacheDir = cfg.CacheDir
		}
		if cfg.NoCache && !changed("no-cache") {
			o.noCache = true
		}
		if cfg.CWD != "" && !changed("cwd") {
			o.cwd = cfg.CWD
		}
		if cfg.CacheTTL != "" && !changed("cache-ttl") {
			ttl, err := time.ParseDuration(cfg.CacheTTL)
			if err != nil {
				return configExitError(fmt.Errorf("invalid config cache_ttl %q: %w", cfg.CacheTTL, err))
			}
			o.cacheTTL = ttl
		}
		if cfg.Concurrency > 0 && !changed("concurrency") {
			o.concurrency = cfg.Concurrency
		}
		if cfg.Timeout != "" && !changed("timeout") {
			timeout, err := time.ParseDuration(cfg.Timeout)
			if err != nil {
				return configExitError(fmt.Errorf("invalid config timeout %q: %w", cfg.Timeout, err))
			}
			o.timeout = timeout
		}
		if cfg.GovulncheckTimeout != "" && !changed("govulncheck-timeout") {
			timeout, err := time.ParseDuration(cfg.GovulncheckTimeout)
			if err != nil {
				return configExitError(fmt.Errorf("invalid config govulncheck_timeout %q: %w", cfg.GovulncheckTimeout, err))
			}
			o.govulncheckTimeout = timeout
		}
		if cfg.Offline && !changed("offline") {
			o.offline = true
		}
		if cfg.AllowPrivateRemote && !changed("allow-private-remote") {
			o.allowPrivateRemote = true
		}
		if cfg.StrictData && !changed("strict-data") {
			o.strictData = true
		}
		if cfg.IncludeTests && !changed("include-tests") {
			o.includeTests = true
		}
		if cfg.IncludeTools && !changed("include-tools") {
			o.includeTools = true
		}
		if cfg.Tags != "" && !changed("tags") {
			o.tags = cfg.Tags
		}
		if cfg.NoColor && !changed("no-color") {
			o.noColor = true
		}
		if cfg.GovulncheckPath != "" && !changed("govulncheck-path") {
			o.govulncheckPath = cfg.GovulncheckPath
		}
		o.applyProviderConfig(cfg.Providers, changed)
	}
	envProfile := os.Getenv("TRUSTMOD_PROFILE")
	o.applyEnv(changed)
	if envProfile != "" && !changed("profile") {
		profileConfigured = true
	}
	if err := o.resolveProjectDefaults(cmd, changed, profileConfigured); err != nil {
		return err
	}
	o.applyDisableFlags(changed)
	if o.disabledProviders["govulncheck"] && !changed("govulncheck") {
		o.runGovulncheck = false
	}
	if o.runGovulncheck && o.disabledProviders["govulncheck"] {
		return usageExitError(fmt.Errorf("--govulncheck and --disable-govulncheck cannot be used together"))
	}
	return nil
}

func (o *globalOptions) applyDisableFlags(changed func(string) bool) {
	for _, item := range []struct {
		provider string
		flag     string
		value    bool
	}{
		{provider: "govulncheck", flag: "disable-govulncheck", value: o.disableGovulncheck},
		{provider: "scorecard", flag: "disable-scorecard", value: o.disableScorecard},
		{provider: "deps.dev", flag: "disable-depsdev", value: o.disableDepsdev},
		{provider: "github", flag: "disable-github", value: o.disableGithub},
		{provider: "osv", flag: "disable-osv", value: o.disableOSV},
	} {
		if changed(item.flag) || item.value {
			o.disabledProviders[item.provider] = item.value
		}
	}
}

func (o *globalOptions) applyProviderConfig(providers map[string]bool, changed func(string) bool) {
	for raw, enabled := range providers {
		name := canonicalProvider(raw)
		if name == "" {
			continue
		}
		disableFlag := disableFlagForProvider(name)
		if name == "govulncheck" {
			if enabled && !changed("govulncheck") && !changed(disableFlag) {
				o.runGovulncheck = true
				o.disabledProviders[name] = false
			}
			if !enabled && !changed(disableFlag) {
				o.disabledProviders[name] = true
			}
			continue
		}
		if !enabled && !changed(disableFlag) {
			o.disabledProviders[name] = true
		}
		if enabled && !changed(disableFlag) {
			o.disabledProviders[name] = false
		}
	}
}

func (o *globalOptions) applyEnv(changed func(string) bool) {
	if v := os.Getenv("TRUSTMOD_FORMAT"); v != "" && !changed("format") {
		o.format = v
	}
	if v := os.Getenv("TRUSTMOD_PROFILE"); v != "" && !changed("profile") {
		o.profile = v
	}
	if v := os.Getenv("TRUSTMOD_FAIL_ON"); v != "" && !changed("fail-on") {
		o.failOn = splitCSV(v)
	}
	if v := os.Getenv("TRUSTMOD_POLICY"); v != "" && !changed("policy") {
		o.policyPath = v
	}
	if v := os.Getenv("TRUSTMOD_BASELINE"); v != "" && !changed("baseline") {
		o.baselinePath = v
	}
	if v := os.Getenv("TRUSTMOD_RULES"); v != "" && !changed("rules") {
		o.rulesPath = v
	}
	if v := os.Getenv("TRUSTMOD_CACHE_DIR"); v != "" && !changed("cache-dir") {
		o.cacheDir = v
	}
	if v := os.Getenv("TRUSTMOD_CWD"); v != "" && !changed("cwd") {
		o.cwd = v
	}
	if v := os.Getenv("TRUSTMOD_CACHE_TTL"); v != "" && !changed("cache-ttl") {
		if ttl, err := time.ParseDuration(v); err == nil {
			o.cacheTTL = ttl
		}
	}
	if v := os.Getenv("TRUSTMOD_TIMEOUT"); v != "" && !changed("timeout") {
		if timeout, err := time.ParseDuration(v); err == nil {
			o.timeout = timeout
		}
	}
	if v := os.Getenv("TRUSTMOD_CONCURRENCY"); v != "" && !changed("concurrency") {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			o.concurrency = n
		}
	}
	if envBool("TRUSTMOD_OFFLINE") && !changed("offline") {
		o.offline = true
	}
	if envBool("TRUSTMOD_NO_COLOR") && !changed("no-color") {
		o.noColor = true
	}
	if envBool("TRUSTMOD_NO_CACHE") && !changed("no-cache") {
		o.noCache = true
	}
	if envBool("TRUSTMOD_ALLOW_PRIVATE_REMOTE") && !changed("allow-private-remote") {
		o.allowPrivateRemote = true
	}
	if envBool("TRUSTMOD_STRICT_DATA") && !changed("strict-data") {
		o.strictData = true
	}
	if envBool("TRUSTMOD_INCLUDE_TESTS") && !changed("include-tests") {
		o.includeTests = true
	}
	if envBool("TRUSTMOD_INCLUDE_TOOLS") && !changed("include-tools") {
		o.includeTools = true
	}
	if v := os.Getenv("TRUSTMOD_TAGS"); v != "" && !changed("tags") {
		o.tags = v
	}
	if envBool("TRUSTMOD_GOVULNCHECK") && !changed("govulncheck") && !changed("disable-govulncheck") {
		o.runGovulncheck = true
		o.disabledProviders["govulncheck"] = false
	}
	if v := os.Getenv("TRUSTMOD_GOVULNCHECK_PATH"); v != "" && !changed("govulncheck-path") {
		o.govulncheckPath = v
	}
	if v := os.Getenv("TRUSTMOD_GOVULNCHECK_TIMEOUT"); v != "" && !changed("govulncheck-timeout") {
		if timeout, err := time.ParseDuration(v); err == nil {
			o.govulncheckTimeout = timeout
		}
	}
	if v := os.Getenv("TRUSTMOD_GITHUB_TOKEN"); v != "" && !changed("github-token") {
		o.githubToken = v
	}
	for _, provider := range []string{"govulncheck", "scorecard", "deps.dev", "github", "osv"} {
		envName := "TRUSTMOD_DISABLE_" + strings.NewReplacer(".", "_").Replace(strings.ToUpper(provider))
		if envBool(envName) && !changed(disableFlagForProvider(provider)) {
			o.disabledProviders[provider] = true
		}
	}
}

func (o *globalOptions) defaultCWD() string {
	if o.cwd != "" {
		return o.cwd
	}
	return "."
}

func (o *globalOptions) defaultPath() string {
	return o.defaultCWD()
}

func preConfigCWD(o *globalOptions, changed func(string) bool) string {
	if changed("cwd") && o.cwd != "" {
		return o.cwd
	}
	if v := os.Getenv("TRUSTMOD_CWD"); v != "" {
		return v
	}
	return "."
}

func (o *globalOptions) resolveProjectDefaults(cmd *cobra.Command, changed func(string) bool, profileConfigured bool) error {
	projectRoot, err := projectRootFor(o.defaultCWD())
	if err != nil {
		return configExitError(err)
	}
	o.projectRoot = projectRoot
	policyExplicit := changed("policy") || os.Getenv("TRUSTMOD_POLICY") != ""
	baselineExplicit := changed("baseline") || os.Getenv("TRUSTMOD_BASELINE") != ""
	rulesExplicit := changed("rules") || os.Getenv("TRUSTMOD_RULES") != "" || o.rulesPathConfigured
	if o.policyPath == "" {
		o.policyPath = filepath.Join(projectRoot, config.DefaultPolicyPath())
	} else if !policyExplicit {
		o.policyPath = rootedProjectPath(projectRoot, o.policyPath)
	}
	if policyExplicit && !regularFileExists(o.policyPath) {
		return configExitError(fmt.Errorf("policy file not found: %s", o.policyPath))
	}
	if o.baselinePath == "" {
		o.baselinePath = filepath.Join(projectRoot, config.DefaultBaselinePath())
	} else if !baselineExplicit {
		o.baselinePath = rootedProjectPath(projectRoot, o.baselinePath)
	}
	if baselineExplicit && commandRequiresExistingBaseline(cmd) && !regularFileExists(o.baselinePath) {
		return configExitError(fmt.Errorf("baseline file not found: %s", o.baselinePath))
	}
	if o.rulesPath == "" {
		defaultRulesPath := filepath.Join(projectRoot, config.DefaultRulesPath())
		if regularFileExists(defaultRulesPath) {
			o.rulesPath = defaultRulesPath
		}
	} else if !rulesExplicit {
		o.rulesPath = rootedProjectPath(projectRoot, o.rulesPath)
	}
	if rulesExplicit && !regularFileExists(o.rulesPath) {
		return configExitError(fmt.Errorf("custom rules file not found: %s", o.rulesPath))
	}
	if !profileConfigured {
		if profile, ok := policyFileProfile(o.policyPath); ok {
			o.profile = profile
		} else {
			o.profile = "backend-service"
		}
	}
	return nil
}

func commandRequiresExistingBaseline(cmd *cobra.Command) bool {
	switch cmd.Name() {
	case "audit", "check", "diff", "add", "compare":
		return true
	case "list", "revoke", "prune":
		return cmd.Parent() != nil && cmd.Parent().Name() == "baseline"
	default:
		return false
	}
}

func projectRootFor(start string) (string, error) {
	project, err := gomod.FindProject(start)
	if err != nil {
		return "", err
	}
	if project.Mode != "detached" {
		return project.Root, nil
	}
	return filepath.Abs(start)
}

func rootedProjectPath(root, path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(root, path)
}

func regularFileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func policyFileProfile(path string) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	var doc struct {
		Profile string `yaml:"profile"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return "", false
	}
	profile := strings.TrimSpace(doc.Profile)
	return profile, profile != ""
}

func envBool(name string) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func canonicalProvider(name string) string {
	canonical, _ := model.CanonicalProviderName(name)
	return canonical
}

func disableFlagForProvider(provider string) string {
	switch provider {
	case "deps.dev":
		return "disable-depsdev"
	default:
		return "disable-" + provider
	}
}

func cloneProviderMap(in map[string]bool) map[string]bool {
	out := map[string]bool{}
	for k, v := range in {
		if canonical := canonicalProvider(k); canonical != "" {
			out[canonical] = v
		}
	}
	return out
}

func commandContext(cmd *cobra.Command) context.Context {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	return ctx
}

func boolString(v bool) string {
	return strconv.FormatBool(v)
}

func splitCSV(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
