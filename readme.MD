# cam-scanner

A streaming IP-camera fingerprinting, default-credential, and CVE verification tool.

Reads a stream of `host:port` targets (from a file or stdin — typically piped from `masscan`
or `zmap`), fingerprints the device by brand, optionally tests brand-specific default
credentials, and optionally checks for a set of known camera CVEs.

> ## ⚠️ FALSE POSITIVE WARNING
> **This tool is tuned for Hikvision.** The Hikvision detection path is the only one with a
> strong, specific signal (ISAPI fingerprint + `/ISAPI/Security/userCheck` auth check).
>
> **Most results reported for non-Hikvision brands will be false positives.** Detection for
> other vendors relies on generic HTTP `Server` headers (`goahead-webs`, `boa`, `thttpd`,
> `micro_httpd`, …), common body words (`camera`, `login`, `onvif`), and a body-length
> heuristic for credential verification — all of which match a large number of unrelated
> embedded devices, routers, and printers.

---

## What It Does

For each target, cam-scanner:

1. **Probes** `http://host:port/` (or `https://` with `-ssl`, or on port 443).
2. **Fingerprints** the response against a set of brand rules (Server header keys + body
   keys, matched with `any` or `both` semantics). The first matching rule wins, and rules
   are ordered with Hikvision first.
3. **Tests credentials** against the matched brand's built-in default-credential list
   (unless `-probe-only` is set):
   - **Hikvision:** authenticated `GET /ISAPI/Security/userCheck`; success = HTTP 200 with
     `<statusValue>200</statusValue>` in the body.
   - **Everything else:** re-request `/` with Basic auth and treat a `401 → 200` transition,
     or a large body-length delta versus the unauthenticated response, as success. *This is
     heuristic and is the main source of non-Hikvision false positives.*
4. **Optionally checks CVEs** (`-vuln`), gated by detected brand:
   - Hikvision: `CVE-2017-7921` (incl. config download + decryption to recover credentials),
     `CVE-2021-36260`, `CVE-2023-6895`, `CVE-2024-58274`
   - Dahua / Amcrest / Lorex: `CVE-2024-13985`
   - Any fingerprinted device: `CVE-2024-3721`, `CVE-2025-34043`
   - Checks are non-destructive echo/canary probes (`echo cv#####`) or read-only config
     retrieval — but see the disclaimer below.
5. **Writes results** to per-brand files in the output directory (see [Output](#output)).
6. **Optionally records** a per-brand version histogram (`-versions`), sourced from `ETag`
   headers and version strings in the body.

A live status line is printed to **stderr** (`in | tested | cameras | authed | vuln |
excluded | rate | elapsed`). Silence it with `-q`.

## Requirements

- Go **1.19+**
- A target source: `masscan`, `zmap`, or any file of `host:port` lines

## Build

```bash
# single-file build
go build -o cam-scanner cam-scanner.go

# or, if you prefer a module
go mod init cam-scanner
go build -o cam-scanner .

## Usage

cam-scanner reads targets as a stream — either a file (`-i`) or stdin — and writes results to
the output directory (`-o`). Discovery is delegated to `masscan` or `zmap`; this tool does not
scan for hosts or ports itself.

### Input formats

One target per line, from stdin or `-i <file>`:

```
192.0.2.10:80
192.0.2.11:8080
```

Lines in `masscan -oL` format are also accepted directly (lines beginning with `open`):

```
open tcp 80 192.0.2.10 1700000000
```

If a target line does not include a port, supply one for all targets with `-p`/`-port`
(required when piping from `zmap`). Lines that produce no usable port are skipped.

Blank lines are ignored. Targets inside any CIDR listed in the `-e` file are counted as
`excluded` and are not probed.

### Typical pipelines

```bash
# masscan -oL -> cam-scanner (port taken from each line)
sudo masscan --rate=100000 -p80,81,8080,8001 192.0.2.0/24 -oL - \
  | ./cam-scanner -o out

# zmap single-port mode (port supplied via -p)
zmap -p 80 192.0.2.0/24 -q -f saddr \
  | ./cam-scanner -p 80 -o out

# from a file, fingerprint only, skipping excluded ranges
./cam-scanner -i targets.txt -probe-only -e excludes.txt -o out

# with CVE checks and a per-brand version histogram
./cam-scanner -i targets.txt -vuln -versions versions/ -o out

# force HTTPS everywhere, fewer threads, longer timeout
./cam-scanner -i targets.txt -ssl -threads 1024 -timeout 5000 -o out
```

### Options

| Flag | Alias | Default | Description |
|------|-------|---------|-------------|
| `-i` | `-input` | — | Read targets from a file instead of stdin |
| `-o` | `-output-dir` | `cam-output` | Output directory |
| `-t` | `-threads` | `NumCPU*1024`, clamped to 1024–50000 | Concurrent checks |
| `-timeout` | — | `3000` | Per-target timeout in **milliseconds** (allowed 200–30000) |
| `-p` | `-port` | `0` | Port applied to targets that don't specify one (use with `zmap`) |
| `-ssl` | — | `false` | Force HTTPS on all ports (port 443 is always TLS) |
| `-probe-only` | — | `false` | Fingerprint only; do not test credentials |
| `-vuln` | — | `false` | Run the CVE checks listed below |
| `-versions` | — | — | Directory to write per-brand version counts |
| `-e` | `-exclude-file` | — | File of CIDR ranges to skip (one per line, `#` comments allowed) |
| `-q` | `-quiet` | `false` | Suppress the live status line |

### Examples

```bash
# Minimal run — stdin, defaults for everything else
cat targets.txt | ./cam-scanner

# Only fingerprint, never send credentials (safest against production devices)
./cam-scanner -i targets.txt -probe-only -o out

# Full run: fingerprint, test default creds, check CVEs, collect versions
./cam-scanner -i targets.txt -vuln -versions versions/ -o out

# Quiet, high-concurrency run for large input sets
./cam-scanner -i big-list.txt -q -t 20000 -timeout 2000 -o out
```

### Live status

Unless `-q` is set, a single status line is rewritten on **stderr** while the scan runs:

```
[status] 12043 in | 9871 tested | 412 cameras | 7 authed | 3 vuln | 22 excluded | 841/s | 11.7s
```

The `vuln` column only appears when `-vuln` is enabled. Counters mean:

| Field | Meaning |
|-------|---------|
| `in` | Target lines read from input |
| `tested` | Targets actually probed (after exclusions) |
| `cameras` | Targets that matched a brand fingerprint |
| `authed` | Devices where the credential test succeeded |
| `vuln` | Devices where at least one CVE check matched (`-vuln` only) |
| `excluded` | Targets skipped via `-e` |
| `.../s` | Current throughput |
| `...s` | Elapsed wall-clock time |

A final summary line is printed to **stdout** when the run completes:

```
[done] 12043 targets | 9871 tested | 412 cameras | 7 authed | 3 vulnerable | 11.7s
```

### CVE checks (`-vuln`)

Checks are gated by the detected brand, so `-vuln` adds requests only where they apply:

| Brand(s) | Check |
|----------|-------|
| Hikvision | `CVE-2017-7921` (read-only config download + decryption to recover credentials) |
| Hikvision | `CVE-2021-36260`, `CVE-2023-6895`, `CVE-2024-58274` |
| Dahua / Amcrest / Lorex | `CVE-2024-13985` |
| Any fingerprinted device | `CVE-2024-3721`, `CVE-2025-34043` |

Each check is a canary: it sends a marker payload and looks for that marker in the response.
A match means the injection point responded as expected — **not** that exploitation succeeded
end-to-end. See [False Positives & Limitations](#false-positives--limitations).

### Exit behavior

- `0` — run completed (individual target failures do not change the exit code)
- `1` — invalid flags/values, unreadable input file, or unreadable exclude file

Errors are written to stderr with an `[error]` prefix. Invalid `-threads`, `-timeout`, or
`-port` values abort before any scanning begins.

> **Note:** with no `-i` and no piped stdin, the tool reads from stdin and will block on an
> interactive terminal. Always pipe input or use `-i`.
