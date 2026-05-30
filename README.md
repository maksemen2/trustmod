# trustmod

[![ci](https://github.com/maksemen2/trustmod/actions/workflows/ci.yml/badge.svg)](https://github.com/maksemen2/trustmod/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/maksemen2/trustmod.svg)](https://pkg.go.dev/github.com/maksemen2/trustmod)

`trustmod` is a Go-native dependency review assistant. It looks at the module
graph, local source evidence, vulnerability data, repository metadata, policy
rules, and baselines, then returns one of three verdicts: `ALLOW`, `REVIEW`, or
`BLOCK`.

It does not prove that a package is safe. The goal is more practical: make
dependency changes easier to review, and avoid quietly adding packages with
surprising security, maintenance, malware-like, or footprint signals.

```text
trustmod module review

Module:  github.com/example/lib
Version: v0.8.1
Verdict: REVIEW
Risk:    48/100
Profile: backend-service

Why:
  REVIEW  TM-FP-001   Adds many transitive modules
  ALLOW   TM-VER-005  Module is below v1
  ALLOW   TM-CAP-002  Filesystem write capability detected

Data:
  osv            ok
  deps.dev       ok
  github         ok
  scorecard      skipped_no_provider_data
```

## Install

Requires Go 1.23 or newer.

```sh
go install github.com/maksemen2/trustmod/cmd/trustmod@latest
```

From a checkout:

```sh
go install ./cmd/trustmod
```

## Quick Start

```sh
trustmod init
trustmod audit .
trustmod check github.com/go-chi/chi/v5
trustmod diff --base main
```

Useful report formats:

```sh
trustmod audit --format json --out trustmod.json
trustmod audit --format markdown --out trustmod.md
trustmod audit --format sarif --out trustmod.sarif
trustmod graph --format dot --out deps.dot
```

## Common Workflows

Review a dependency before adding it:

```sh
trustmod check github.com/go-chi/chi/v5
```

Review and add a dependency in one command:

```sh
trustmod add github.com/go-chi/chi/v5
trustmod add github.com/example/review-me --dry-run
trustmod add github.com/example/review-me --allow-review --tidy
```

`add` runs the same review before invoking `go get`. A `REVIEW` result requires
`--allow-review`; a `BLOCK` result requires `--force` or `--allow-block`.
`--require-allow` refuses every non-`ALLOW` result.

Review a pull request:

```sh
trustmod diff --base main
trustmod diff --base main --changed-files-only
trustmod diff --base main --only-new
```

Compare alternatives:

```sh
trustmod compare \
  github.com/go-chi/chi/v5 \
  github.com/gin-gonic/gin \
  github.com/labstack/echo/v4 \
  --use-case http-router
```

## Projects With Multiple `go.mod` Files

`trustmod` starts from `--cwd` or the current directory and uses the nearest
`go.work` or `go.mod`.

If a repository has a `go.work` file, `trustmod audit --cwd repo` analyzes the
workspace modules listed in `go.work use (...)` as one workspace. This is a good
fit for a monorepo with a backend service, cron jobs, and workers that should be
reviewed together.

Without `go.work`, run `trustmod` for each application:

```sh
trustmod audit --cwd ./backend
trustmod audit --cwd ./cron-cleanup
trustmod audit --cwd ./worker
```

If you run from a repository root that has no `go.mod` and no `go.work`,
`trustmod` does not recursively guess which nested modules matter. That avoids
accidentally analyzing fixtures, examples, or test modules as production code.

`trustmod diff` handles nested modules when you run it from the nested project.
For example, `trustmod --cwd ./backend diff --base main` compares
`main:backend/go.mod` with the current backend module.

## Verdicts

- `ALLOW`: no blocking or review-level findings under the active policy.
- `REVIEW`: a human should look at the change before it is accepted.
- `BLOCK`: the policy says this should not pass.

Provider failures are reported as data availability statuses. They do not fail
the process unless `--strict-data` is enabled.

Low-context signals, such as a v0 module, a normal environment read, or weak
maintenance metadata, are still shown and still add risk points. Under the
default profile, they do not automatically force `REVIEW` unless the combined
risk crosses the policy threshold.

## Exit Codes

- `0`: success; no policy failure.
- `1`: policy failure according to `fail_on` or `--fail-on`.
- `2`: usage error, unsupported format, bad flag, or bad user-supplied file.
- `3`: invalid config, policy, or explicitly requested baseline.
- `4`: local Go analysis failed.
- `5`: provider failure while `--strict-data` is enabled.
- `6`: privacy guard prevented a remote provider query.
- `7`: internal error.

## Policy

`trustmod init` writes a starter `.trustmod.yaml`,
`.trustmod/policy.yml`, `.trustmod/baseline.yml`, and
`.trustmod/rules.yml`.

Configuration precedence is:

1. CLI flags
2. Environment variables
3. Config and policy files
4. Built-in defaults

Example `.trustmod.yaml`:

```yaml
default_profile: backend-service
output: human
policy_path: .trustmod/policy.yml
baseline_path: .trustmod/baseline.yml
rules_path: .trustmod/rules.yml
timeout: 20s
concurrency: 8
allow_private_remote: false
offline: false
strict_data: false
no_cache: false
include_tests: false
providers:
  osv: true
  deps.dev: true
  github: true
  scorecard: true
  govulncheck: false
```

Example policy:

```yaml
version: 1
profile: backend-service
fail_on: [BLOCK]

licenses:
  banned: [AGPL-3.0, GPL-3.0]

deny:
  modules:
    - example.com/disallowed/...

allow:
  finding_codes:
    - TM-VER-005

thresholds:
  risk_review: 30
  risk_block: 101
  transitive_review: 20

profiles:
  strict:
    strict: true
    fail_on: [BLOCK, REVIEW]
    providers:
      required: [osv]
```

Useful policy commands:

```sh
trustmod policy validate
trustmod policy print-default
trustmod policy explain
trustmod policy test trustmod.json
```

## Custom Source Rules

Built-in rules cover common Go dependency risks. Teams can add project-specific
source rules in `.trustmod/rules.yml` or pass a file explicitly:

```sh
trustmod audit --rules .trustmod/rules.yml
trustmod check github.com/mymmrac/telego --rules examples/rules/telegram-domain.yml
```

Example rule:

```yaml
version: 1
rules:
  - id: org-telegram-api
    code: TM-CUSTOM-TELEGRAM
    title: Telegram API access
    description: The dependency contains a literal Telegram API endpoint.
    severity: medium
    verdict: REVIEW
    confidence: high
    remediation:
      - Confirm that outbound Telegram API access is expected for this dependency.
    match:
      domains:
        - telegram.org
```

Rule matchers currently support `imports`, `selectors`, string literals through
`strings`, and literal URL/host domains through `domains`. Set
`require_all: true` when every listed condition must match in the same file.
Custom finding codes are stable and can be used in policy allow lists and
baselines.

## Baselines

Baselines accept known findings without hiding them. Accepted findings remain in
JSON with `baselineAccepted: true`, but they no longer drive the final verdict.

```sh
trustmod baseline approve github.com/legacy/package \
  --code TM-MNT-002 \
  --reason "approved legacy dependency" \
  --expires 2026-12-31

trustmod baseline list
trustmod baseline revoke github.com/legacy/package --code TM-MNT-002
trustmod baseline prune
```

Example baseline entry:

```yaml
version: 1
created_at: "2026-05-22T00:00:00Z"
accepted_findings:
  - module: github.com/legacy/package
    version: v1.2.3
    code: TM-MNT-002
    reason: Stable approved legacy dependency
    approved_by: platform-team
    expires: "2026-12-31"
```

## Data Sources

Local evidence comes first:

- `go list -m -json all` for selected modules, replacements, retractions, and
  deprecations where Go reports them.
- `go list -deps -json ./...` for package and test footprint.
- `go mod graph` and `go mod why -m` for graph and path hints.
- `go mod verify` for checksum verification.
- A local AST scan for imports, calls, `unsafe`, cgo, `init` functions, process
  execution, filesystem writes, network APIs, environment access, plugin
  loading, insecure randomness, and literal network request domains where they
  can be determined safely.
- Malware-oriented local source rules for encoded payload execution,
  download-and-execute chains, sensitive data exfiltration patterns,
  `/etc/passwd` access, shell downloader pipelines, and suspicious URL
  infrastructure.
- Optional custom source rules from `.trustmod/rules.yml` or `--rules`.

Optional enrichment:

- OSV for advisory data.
- deps.dev for licenses, advisories, and package metadata.
- GitHub API for repository metadata.
- OpenSSF Scorecard for maintenance signals.
- `govulncheck` for reachable vulnerability evidence when requested.

Run `govulncheck` when it is installed:

```sh
trustmod audit --govulncheck
trustmod audit --govulncheck-path ./bin/govulncheck
```

Providers can be disabled with flags such as `--disable-github`,
`--disable-scorecard`, `--disable-depsdev`, `--disable-osv`, and
`--disable-govulncheck`, or through `.trustmod.yaml`.

Provider statuses are meant to be explicit:

- `ok`: data returned.
- `disabled`: intentionally disabled.
- `not_requested`: available but not requested, such as default `govulncheck`.
- `skipped_private`: private module paths were withheld.
- `skipped_no_public_modules`: there was nothing public to query.
- `skipped_no_eligible_versions`: the provider could not query the selected
  versions.
- `skipped_unsupported_host`: the provider does not support that module host.
- `skipped_no_provider_data`: the provider has no data, such as a Scorecard 404.
- `offline_cache_hit`: offline mode found cached data.
- `offline_cache_miss`, `unavailable`, `rate_limited`, `timeout`, `cancelled`,
  `error`: data was expected but unavailable.

Use `--strict-data` when missing enabled provider data should fail CI.

## Performance

The first run for a large module can be dominated by Go module downloads and
remote providers. Repeated runs are much faster when the Go module cache and
the trustmod provider cache are warm.

Useful knobs:

```sh
# Keep provider caching enabled. Avoid --no-cache unless debugging freshness.
trustmod check google.golang.org/grpc

# Increase parallelism for provider calls and local analysis phases.
trustmod check google.golang.org/grpc --concurrency 16

# Run only local evidence when you need a quick first pass.
trustmod check google.golang.org/grpc \
  --disable-github \
  --disable-scorecard \
  --disable-depsdev \
  --disable-osv

# Use cached provider data only.
trustmod check google.golang.org/grpc --offline
```

For `trustmod check`, the local capability scan is targeted at the requested
module source tree instead of scanning every transitive dependency source tree.
Transitive dependencies are still represented in the module graph and can still
be enriched by enabled providers.

## Privacy

`trustmod` has no telemetry, analytics, hosted backend, or default update check.

Private module paths are not sent to remote providers by default. Private module
detection uses:

- `GOPRIVATE`
- `GONOPROXY`
- `GONOSUMDB`
- local `replace` directives
- main module paths
- workspace module paths

Allow remote enrichment for private paths only when that disclosure is
acceptable:

```sh
trustmod audit --allow-private-remote
```

The cache stores provider responses keyed by request metadata. Tokens are not
stored in the cache.

```sh
trustmod cache path
trustmod cache stats
trustmod cache prune
trustmod cache clear
```

Offline mode keeps local Go analysis and cache reads:

```sh
trustmod audit --offline
```

## GitHub Tokens

GitHub metadata is optional, but unauthenticated API calls are severely
rate-limited. If GitHub returns a primary or secondary rate limit, `trustmod`
reports `rate_limited` and stops querying GitHub for that run.

Set `TRUSTMOD_GITHUB_TOKEN` or `GITHUB_TOKEN` to raise limits. With a token,
`trustmod` uses GitHub GraphQL to fetch repository metadata, including exact
archive timestamps. Without a token, REST fallback can still report archive
status, but not always the archive timestamp.

Create a minimal fine-grained token:

1. Open GitHub **Settings -> Developer settings -> Personal access tokens ->
   Fine-grained tokens**.
2. Generate a new token.
3. Choose public read-only repository access when available, or restrict it to
   the repositories you need.
4. Do not grant write permissions.

Shell:

```sh
export TRUSTMOD_GITHUB_TOKEN="github_pat_..."
trustmod check github.com/gin-gonic/gin
unset TRUSTMOD_GITHUB_TOKEN
```

GitHub Actions:

```yaml
env:
  GITHUB_TOKEN: ${{ github.token }}
```

## GitHub Action

This repository includes a composite action in `action.yml`. It does not need a
separate action repository; consumers can reference this repository directly:

```yaml
name: trustmod
on:
  pull_request:

jobs:
  review:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.23"

      - id: trustmod
        uses: maksemen2/trustmod@v0.1.0
        with:
          command: diff
          base: main
          sarif: trustmod.sarif

      - uses: github/codeql-action/upload-sarif@v3
        if: always() && steps.trustmod.outputs['sarif-path'] != ''
        with:
          sarif_file: ${{ steps.trustmod.outputs['sarif-path'] }}
```

The action supports:

- `command`: `audit`, `diff`, or `check`.
- `args`: extra trustmod arguments.
- `base`: base ref for `diff`.
- `format`: stdout report format.
- `policy`: policy file path.
- `baseline`: baseline file path.
- `rules`: custom source rules YAML path.
- `sarif`: optional SARIF output path.
- `offline`: run without remote provider calls.
- `govulncheck`: run local `govulncheck`.
- `install-govulncheck`: install `govulncheck` first.
- `govulncheck-version`: version used by the optional install step.
- `concurrency`: maximum concurrency per analysis phase.
- `timeout`: per-command/provider timeout.
- `strict-data`: fail when enabled provider data is unavailable.

Outputs:

- `exit-code`
- `sarif-path`

Pin to a release tag such as `maksemen2/trustmod@v0.1.0` for reproducible CI.
Use a moving major tag such as `@v0` only if you want compatible fixes without
editing workflow files.

## Finding Codes

Finding codes are stable and are safe to use in policy and baseline files.

Security:

- `TM-SEC-001`: reachable known vulnerability.
- `TM-SEC-002`: known vulnerability, reachability unknown.
- `TM-SEC-003`: known vulnerability, not reached by current analysis.
- `TM-SEC-004`: vulnerability scanner unavailable.
- `TM-SEC-005`: known malicious package indicator.
- `TM-SEC-006`: checksum verification failed.
- `TM-SEC-007`: `go.sum` missing required entry.
- `TM-SEC-008`: security advisory data unavailable.

Malware-oriented local rules:

- `TM-MAL-001`: encoded payload execution pattern.
- `TM-MAL-002`: download and execute pattern.
- `TM-MAL-003`: sensitive data exfiltration pattern.
- `TM-MAL-004`: suspicious `/etc/passwd` access.
- `TM-MAL-005`: suspicious URL literal.
- `TM-MAL-006`: shell downloader pipeline.

Other families:

- `TM-ID-*`: module identity, repository, canonicalization, and replace signals.
- `TM-VER-*`: versioning signals, including retractions, pre-releases,
  pseudo-versions, v0 modules, and downgrades.
- `TM-MNT-*`: maintenance signals. Archived GitHub repositories include the
  archive timestamp and age when token-backed GraphQL metadata is available.
- `TM-LIC-*`: license signals.
- `TM-FP-*`: dependency footprint signals.
- `TM-CAP-*`: local capability signals.
- `TM-CUSTOM-*`: custom source rules loaded from `.trustmod/rules.yml` or
  `--rules`.
- `TM-POL-*`: policy-generated findings.
- `TM-BAS-001`: baseline exception expired.
- `TM-GO-001`: local Go command failed.
- `TM-GIT-001`: git diff data unavailable.

For local remediation text:

```sh
trustmod explain TM-VER-005
```

## Reports

JSON is the most complete format. Markdown is intended for PR comments. SARIF
can be uploaded to GitHub code scanning. JUnit is useful when CI systems expect
test-like failure output.

Capability evidence includes file, line, matched text, and best-effort source
links. Network client capabilities also include literal request domains when
they are visible in source, with long domain lists truncated in human output.
Public GitHub modules get web links when `trustmod` can derive a version ref.
During local human output, local files may also be shown as `vscode://file/...`
links. Machine-specific local paths are not serialized into JSON or YAML.

`trustmod report` can render an existing project report or compare report:

```sh
trustmod report trustmod.json --format markdown --out trustmod.md
trustmod report compare.json --format markdown --out comparison.md
```

## Evaluation Corpus

The repository includes small synthetic modules under `examples/evaluation`.
They are intentionally boring: each one isolates a behavior so reviewers can see
what is supposed to be `ALLOW`, `REVIEW`, or `BLOCK`.

| Case | Command | Expected signal |
| --- | --- | --- |
| Benign HTTP client | `trustmod audit --cwd examples/evaluation/benign/http-client --offline` | `TM-CAP-003`, no `TM-MAL-*` |
| Suspicious URL literal | `trustmod audit --cwd examples/evaluation/suspicious/rare-domain --offline` | `TM-MAL-005` |
| Custom Telegram rule | `trustmod audit --cwd examples/evaluation/suspicious/telegram-api --rules examples/rules/telegram-domain.yml --offline` | `TM-CUSTOM-TELEGRAM` |
| Download and execute | `trustmod audit --cwd examples/evaluation/malicious/download-exec --offline` | `TM-MAL-002`, `BLOCK` |
| Secret exfiltration pattern | `trustmod audit --cwd examples/evaluation/malicious/exfiltrate-secret --offline` | `TM-MAL-003`, `BLOCK` |

The same corpus is covered by automated tests, so rule changes have to preserve
the expected benign/suspicious/malicious split.

## Limitations

Use `trustmod` as a review assistant, not as a guarantee.

- Capabilities are not vulnerabilities.
- Static scanning is heuristic and does not execute code.
- Provider data may be stale, unavailable, or rate-limited.
- Some providers do not apply to every module host.
- GitHub stars and repository activity are weak signals.
- `govulncheck` reachability depends on build configuration and installed tool
  behavior.
- Private modules are skipped remotely by default, so remote advisory and
  license data may be absent.
- License output is not legal advice.

## Development

```sh
go test ./...
go vet ./...
go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest run
```

Build a local binary:

```sh
go build -o trustmod ./cmd/trustmod
```
