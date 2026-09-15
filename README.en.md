# SubExposure

[Português](README.md) · Go CLI for **authorized** web exposure auditing.

**Run only on systems you own or have explicit authorization to audit.** Default discovery expands the target to its registrable domain and subdomains. Ensure that entire scope is authorized, or use `--no-subdomains` to scan only the supplied host.

## Requirements and build

Go 1.26+ to compile. [Subfinder](https://github.com/projectdiscovery/subfinder) must be installed separately and available on PATH, unless discovery is disabled. Some passive sources require API keys configured in Subfinder. SubExposure binaries do not bundle Subfinder.

```sh
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go build -trimpath -o subexposure ./cmd/subexposure
./subexposure scan example.com --no-subdomains
```

Windows / PowerShell:

```powershell
go build -trimpath -o subexposure.exe ./cmd/subexposure
.\subexposure.exe scan https://app.example.com --no-subdomains
```

The module name is `subexposure`; build from a clone. Publishing on GitHub does not require changing the module name.

## Usage

```sh
subexposure scan example.com --output report.json
subexposure scan https://app.example.com --no-subdomains --format jsonl --output report.jsonl
subexposure scan example.com --workers 4 --rate 2 --timeout 15s --verbose
subexposure scan example.com --subfinder-path /opt/tools/subfinder
subexposure scan --help
```

Place flags after the target or before it; do not mix both positions. Input URL paths, queries and fragments are discarded. Only ASCII/punycode domains and standard ports are supported. Literal IPs, credentials and custom ports are rejected.

| Flag | Default | Bounds / behavior |
| --- | --- | --- |
| `--workers` | 10 | 1–50 concurrent hosts |
| `--rate` | 5 | 0.1–50 global requests/s; burst 1; redirects included |
| `--timeout` | 8s | 1s–60s per HTTP operation, including rate wait, redirects and body read |
| `--output` | stdout | Creates a new file; never overwrites an existing file |
| `--format` | json | JSON array or JSONL, one finding per line |
| `--verbose` | false | Structural progress to stderr |
| `--subfinder-path` | subfinder | Executable path |
| `--no-subdomains` | false | Scan only the supplied host |

`--resume` is future work and is rejected in this version. Ctrl+C cancels discovery and pending work. During scanning it closes the partial report. Exit codes: 0 completed (including findings/individual host errors), 1 operational error, 2 invalid arguments, 130 interrupted scan. Cancellation during discovery returns 1 without a report. Use JSONL for incremental processing; host result order is concurrent.

## Architecture

```text
cmd/subexposure → scope → subfinder → A/AAAA DNS → HTTPS (HTTP fallback)
                                                    ↓
                                    two missing-path baselines → detectors → report
```

- `internal/scope`: registrable domain using `publicsuffix`, domain normalization and boundary checks.
- `internal/subfinder`: shell-free external process, `subfinder -silent -d <domain>`; normalization, deduplication and scope filtering. Limits: 10,000 hosts, 4 MiB stdout, 4 KiB per line, two minutes. Discovery failures abort.
- `internal/dns`: A/AAAA lookup, rejecting the entire host if any address is blocked. Blocks private, loopback, link-local, multicast, unspecified, documentation, benchmark, CGNAT and special ranges. IPv6 is restricted to public `2000::/3` with exclusions.
- `internal/httpcheck`: resolves immediately before new connections and dials only validated numeric IPs. Revalidates DNS after redirects even when a connection could be reused. Ignores environment proxies and verifies TLS certificates. Allows at most five redirects within the root domain, using standard ports; blocks HTTPS→HTTP downgrades. No cookie jar, credentials or JavaScript execution.
- `internal/exposure`: pluggable `Detector` interface: `Name()`, `Paths()`, `Match(path, body)`. Register additions in `Detectors()` and return fixed structural evidence only.
- `internal/models`, `internal/report`: structural findings and streaming serialization.

HTTPS is preferred: any valid HTTP response, including 403/404/500, selects HTTPS. HTTP is tried only if the HTTPS probe fails. This version does not audit HTTP separately when HTTPS responds. Failed HTTPS attempts remain in the report even if HTTP succeeds.

## Indicators and privacy

GET requests only: `/`, two random missing paths, the following six indicators, plus permitted redirects. No DNS brute force, repository cloning, Git object traversal or SQLite queries.

| Path | Structural evidence |
| --- | --- |
| `/.git/HEAD` | Git reference or HEAD hash |
| `/.git/config` | Core section and repositoryformatversion structure |
| `/.env` | Two or more KEY=VALUE assignments; names and values omitted |
| `/.hg/requires` | Two or more known Mercurial requirement identifiers |
| `/.svn/entries` | SVN XML or legacy entries structure |
| `/.svn/wc.db` | SQLite file header only; database never queried |

Bodies are inspected in memory up to 64 KiB, with one extra byte to detect truncation. Truncated responses are inconclusive. No bodies, response headers, query strings, redirect destinations, variable names or secret values are persisted. Env evidence contains only the fixed placeholder `KEY=[REDACTED]`. Reports contain host, scheme, fixed indicator path, detector, HTTP status, classification, confidence and structural explanation. Automatic decompression is disabled. The limit can miss larger files; Go-managed memory buffers are not guaranteed to be zeroed.

## Results

| Classification | Meaning |
| --- | --- |
| EXPOSED | Strong structural signature; does not prove exploitation or complete contents |
| LIKELY_EXPOSED | Suggestive structure, such as env assignments or SQLite |
| PROTECTED | HTTP 401/403; file existence not established |
| NOT_FOUND | HTTP 404/410 |
| SOFT_404 | Matches two consistent missing-path baselines after whitespace / reflected-path normalization |
| REDIRECT | Observed or blocked redirect; final content does not confirm source exposure |
| DNS_UNRESOLVED | Resolution failed |
| CONNECTION_ERROR | Connection, TLS or read failure |
| TIMEOUT | Time budget exceeded |
| INCONCLUSIVE | Blocked network, truncation, unexpected status, absent signature or unstable baseline |

Confidence is HIGH for strong signatures, identical baselines and 404 responses; MEDIUM for suggestive patterns or denied access; LOW for uncertainty. These are not statistical probabilities. Dynamic missing pages can prevent positive classification; HTML is not semantically compared. False positives and negatives remain possible. Validate findings within the authorized environment.

Example only, not a real scan:

```json
{"host":"app.example.com","scheme":"https","path":"/.env","detector":"Env","classification":"LIKELY_EXPOSED","confidence":"MEDIUM","status":200,"evidence":"multiple KEY=[REDACTED] assignments; names and values omitted"}
```

## Testing and distribution

```sh
go test ./...
go vet ./...
make dist
```

Tests use synthetic data and `httptest.Server`, without auditing external domains. Local test servers are accessible only through an injected test transport; the CLI has no private-network bypass. Coverage includes domains, scope, addresses, redirects, redirect DNS validation, body limits, timeout, soft-404, signatures and redaction.

`make dist` builds Windows, Linux and macOS, amd64 and arm64, with CGO disabled. Alternatively run [scripts/build.ps1](scripts/build.ps1) in PowerShell. GitHub Actions tests and builds on all three operating systems on pushes/PRs and uploads cross-platform artifacts; it does not publish public releases. Run `go test -race ./...` where a compatible C compiler is installed.

## Publish on GitHub

Install [GitHub CLI](https://cli.github.com/) and run inside this directory:

```sh
gh auth login
gh repo create subexposure --public --source=. --remote=origin --push
```

Use `--private` instead of `--public` if desired. Keep real audit reports out of the repository. [MIT license](LICENSE).
