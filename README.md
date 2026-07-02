<div align="center">

# dnsenum

**A fast, concurrent DNS enumeration and resolution engine written in Go.**

Bulk-resolve massive subdomain lists across multiple record types, with automatic wildcard detection, custom resolver support, and structured JSON output.

[![Go Version](https://img.shields.io/badge/Go-1.21%2B-00ADD8?logo=go)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

</div>

---

## Overview

`dnsenum` takes a list of hosts (typically subdomains discovered by a passive enumeration tool) and resolves them concurrently across one or more DNS record types. It is built to be dropped into a recon pipeline: pipe hostnames in on `stdin`, get resolved, alive hosts out — with clean JSON if you need to feed the results into other tooling.

It ships with two resolution strategies and built-in wildcard DNS detection, so noisy wildcard domains don't flood your results with false positives.

## Features

- ⚡ **High concurrency** — thousands of hosts resolved in parallel via a configurable worker pool.
- 🎯 **Multiple record types** — `A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`, `PTR`, `SRV`, `SOA` in a single pass.
- 🧠 **Automatic wildcard detection** — probes each registrable domain level with randomized labels and suppresses results that match a wildcard fingerprint, with a threshold-based confirmation pass to avoid false negatives on large batches.
- 🌐 **Custom resolvers** — bring your own resolver list, or fall back to a sane built-in default set (Cloudflare, Google, Quad9, OpenDNS).
- 🔁 **Two strategies**:
  - `fast` — one resolver per host, optimized for speed.
  - `deep` — retries pending record types across multiple resolvers for higher accuracy on flaky or rate-limited resolvers.
- 📄 **Structured JSON output** — every resolved host with its records grouped by type, ready for downstream tooling.
- 🔌 **Pipeline-friendly** — reads from `stdin` or a file, writes results to `stdout`, and supports a machine-readable progress protocol for orchestration by other tools.
- 🧵 Zero external state — no config files, no database, just a binary.

## Installation

### Using `go install`

```bash
go install github.com/Alwardani9090/dnsenum/cmd/dnsenum@latest
```

### Build from source

```bash
git clone https://github.com/Alwardani9090/dnsenum.git
cd dnsenum
go mod tidy
go build -o dnsenum ./cmd/dnsenum
```

Requires **Go 1.21+**.

## Usage

```
Usage: dnsenum [options]

DNS Enumeration Tool

Options:
  -l, --list string          File containing list of targets (subdomains)
  -r, --resolvers string     File containing custom DNS resolvers
  -o, --output string        Output file for JSON results
  -s, --strategy string      Strategy: fast or deep (default "fast")
  -t, --type string          Comma-separated record types: A,AAAA,CNAME,MX,NS,TXT,PTR,SRV,SOA (default "A")
  -c, --concurrency int      Number of concurrent workers (default 500)
      --timeout int          DNS query timeout in seconds (default 3)
      --silent               Silent mode (suppress banner/logs)
```

### Examples

Resolve a list of subdomains and write results to JSON:

```bash
dnsenum -l targets.txt -o results.json
```

Pipe subdomains in from `stdin`, resolving `A` and `AAAA` records with the deep strategy:

```bash
echo "sub.example.com" | dnsenum -t A,AAAA -s deep
```

> If the domain is printed back to you, that means it **resolved successfully** (at least one of the requested record types returned a result). If nothing is printed, the domain did not resolve for any of the requested record types. This bare stdout output only lists resolved hostnames — it does **not** show the actual record values (IPs, etc.); use `-o/--output` for that (see [Output format](#output-format) below).

Chain it after a subdomain discovery tool:

```bash
subfinder -d example.com -silent | dnsenum -t A,CNAME -o alive.json
```

Use custom resolvers with higher concurrency:

```bash
dnsenum -l targets.txt -r resolvers.txt -o output.json -c 1000
```

### Output format

By default (no `-o/--output`), `dnsenum` prints **only the resolved hostnames** to `stdout`, one per line — nothing else. A hostname appears in the output if and only if it successfully resolved for at least one of the requested record types (`-t`). This is intentional: it's designed to be piped straight into other recon tools (`httpx`, `nuclei`, etc.), so the output stays a clean list with no extra noise.

**This stdout list does not include the actual record values** (IPs, CNAME targets, etc.) — just the hostname. If you need the resolved data itself, pass `-o/--output` to write a structured JSON report:
```json
{
  "subdomains": [
    {
      "host": "www.example.com",
      "records": {
        "A": ["93.184.216.34"],
        "CNAME": ["example.com"]
      },
      "resolvers_checked": 1
    }
  ]
}
```

## How wildcard detection works

Many domains configure a catch-all (`*.example.com`) DNS record, which would otherwise cause every random subdomain guess to "resolve" successfully. `dnsenum` handles this by:

1. Generating randomized, non-existent labels at each DNS level above a probed host.
2. Querying those random labels and recording the response as a **baseline fingerprint** per level.
3. Comparing every real result against the relevant baseline(s) — an exact match is flagged as a wildcard and dropped.
4. Running a threshold-based confirmation pass across the whole batch, so a domain that only *looks* like a wildcard from a handful of hosts isn't falsely flagged.

This keeps large-scale enumeration runs clean without manual wildcard filtering.

## Architecture

```
cmd/dnsenum         → CLI entrypoint & flag parsing
internal/runner     → Orchestrates a run: input loading, execution, output
internal/log        → Colored, leveled console logging
internal/progress    → Optional machine-readable progress protocol
pkg/dnsprobe        → Core resolution engine + wildcard detection
pkg/client          → Low-level DNS query client & default resolvers
pkg/utils           → Input helpers (stdin / file reading)
```

## Disclaimer

`dnsenum` is intended for authorized security testing, bug bounty work, and research on infrastructure you own or have explicit permission to test. Running enumeration against domains without authorization may violate the law and/or terms of service. The author assumes no liability for misuse of this tool.

## Contributing

Issues and pull requests are welcome. If you're proposing a larger change, please open an issue first to discuss what you'd like to change.

## License

Licensed under the [MIT License](LICENSE).
