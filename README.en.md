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
