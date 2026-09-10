# Metho — Automated Recon Pipeline

A Dockerized, fully automated reconnaissance pipeline for bug bounty hunting. Feed it root domains and it maps the entire attack surface: subdomains, live web servers, cloud assets, ASN/network infrastructure, IPs, and open ports.

Inspired by the [Ars0n Framework v2](https://github.com/R-s0n/ars0n-framework-v2) methodology.

## Tools

The pipeline is built on the work of many open-source projects. Every tool
below is wired into one or more phases (see the stage tables in
[The Methodology](#the-methodology) for the per-phase breakdown):

- [Subfaster](https://github.com/melvinsh/subfaster) — Passive subdomain enumeration (Subfinder fork, faster defaults)
- [crt.name](https://crt.name) — Certificate Transparency log lookup
- [GitHub-subdomains](https://github.com/gwen001/github-subdomains) — GitHub code search for subdomain references
- [Waymore](https://github.com/xnl-h4ck3r/waymore) — Historical URL/subdomain discovery from Wayback/CommonCrawl/OTX/URLScan/VirusTotal
- [CeWL](https://github.com/digininja/CeWL) — Custom wordlist generation via web spidering
- [dnsgen](https://github.com/AlephNullSK/dnsgen) — Subdomain permutation generation from discovered patterns
- [Katana](https://github.com/projectdiscovery/katana) — Web crawler and JavaScript discovery
- [Subdomainizer](https://github.com/nsonaniya2010/SubDomainizer) — JavaScript subdomain and secret extraction
- [httpx](https://github.com/projectdiscovery/httpx) — HTTP probing with CDN detection, tech fingerprinting, and metadata
- [dnsx](https://github.com/projectdiscovery/dnsx) — DNS resolution, brute force, wildcard filtering, and permutation resolution (replaces ShuffleDNS + massdns)
- [Cloud_Enum](https://github.com/initstring/cloud_enum) — AWS/Azure/GCP bucket and service brute force
- [naabu](https://github.com/projectdiscovery/naabu) — Fast SYN port scanner for wide port discovery
- [nmap](https://github.com/nmap/nmap) — Port scanning with service/version detection on non-CDN IPs

---

## Quick Start

```bash
# Build the image
docker build -t metho .

# From a comma-separated list of root domains
docker run --rm -it -v $(pwd)/results:/output metho \
  --domains "example.com,test.com" --auto

# From a file of root domains (one per line)
docker run --rm -it \
  -v $(pwd)/results:/output \
  -v $(pwd)/my-domains.txt:/input/domains.txt:ro \
  metho \
  --domains-file /input/domains.txt --auto
```

---

## The Methodology

The pipeline has three phases that run sequentially.

### Phase 1: Root Domains → All Subdomains

For each root domain, discovers subdomains through passive enumeration, historical recon, DNS brute force, and web crawling.

| Stage | What Happens | Tool(s) |
|-------|-------------|---------|
| 1 | Passive subdomain enumeration | Subfaster, crt.name, GitHub-subdomains, AXFR |
| 2 | Historical URL/subdomain discovery | Waymore (root domains only) |
| 3 | Consolidate + DNSx resolution + HTTPx Round 1 | dnsx, httpx |
| 4 | Custom wordlist generation + DNS brute force | CeWL, dnsx |
| 4b | Subdomain permutation + resolution | dnsgen, dnsx |
| 5 | Consolidate + DNSx delta resolution + HTTPx Round 2 | dnsx, httpx |
| 6 | Web crawling + JavaScript analysis | Katana, SubDomainizer |
| 7 | Final consolidation + DNSx delta + HTTPx Round 3 | dnsx, httpx |

Each domain gets its own output subdirectory: `phase1/example.com/`.

### Phase 2: Cloud Asset Discovery

Discovers AWS, Azure, and GCP assets associated with the root domains. This phase does **not** re-resolve the entire hostname corpus — it uses the canonical DNS dataset from Phase 1 and only queries additional record types (CNAME, MX, NS, TXT) specifically for cloud discovery. Katana is not re-run here — cloud assets from Phase 1's Katana crawl are filtered and reused.

| Stage | What Happens | Tool(s) |
|-------|-------------|---------|
| 1 | Cloud DNS record queries (CNAME/MX/NS/TXT) from canonical dataset | dnsx |
| 2 | Brute force cloud storage buckets and services | Cloud_Enum |
| 3 | Extract cloud assets from Phase 1 Katana data | filter_cloud_domains |
| 4 | Consolidate all cloud assets | — |

### Phase 3: IP → Classification → Port Scan

Resolves any still-pending hostnames from the canonical DNS dataset, performs deterministic IP classification, and port scans non-CDN IPs.

| Stage | What Happens | Tool(s) |
|-------|-------------|---------|
| 1 | Extract IPs from canonical DNS dataset (pending hosts resolved first) | dnsx |
| 1b | Reverse DNS (PTR) lookups on resolved IPs → new in-scope hostnames | dnsx |
| 2 | IP → ASN lookup via whois.cymru.com | nc |
| 3 | Deterministic IP classification (CDN/cloud/dedicated/unknown) | Built-in classification engine |
| 4 | Fast port scan (naabu, top 1000 ports) then service detection (nmap -sV on hosts naabu found open, capped to the top `--nmap-top-ports` most-common ports) — skipped with `--no-port-scan` | naabu, nmap |

---

## Canonical DNS Dataset

After Phase 1 discovery, Metho maintains a **canonical hostname/DNS dataset** stored as a TSV file at `canonical_dns.tsv`. This is the single source of truth for hostname-to-IP mappings across all phases.

Columns:

| Column | Description |
|--------|-------------|
| `hostname` | FQDN being tracked |
| `root_domain` | eTLD+1 root domain this hostname belongs to |
| `discovery_sources` | Semicolon-separated list of tools that found this hostname |
| `A` | Semicolon-separated IPv4 addresses |
| `AAAA` | Semicolon-separated IPv6 addresses |
| `CNAME` | Semicolon-separated CNAME targets |
| `resolution_status` | `resolved`, `nxdomain`, `timeout`, `bogon`, or `pending` |

Phases 2 and 3 never re-resolve the entire corpus — only newly discovered hosts are resolved through dnsx, and the results are merged incrementally.

## Deterministic IP Classification

IPs are classified using a strict priority order. Each ASN rule matches on the
ASN number **or** a case-insensitive substring of the ASN organization name:

1. **HTTPX CDN = true** → `cdn`
2. **ASN number or org name matches CDN config** → `cdn`
3. **ASN number or org name matches cloud config** → `cloud`
4. **ASN number or org name matches dedicated hosting config** → `dedicated`
5. **Otherwise** → `unknown`

Each IP receives exactly one classification. CDN IPs are retained in results but excluded from nmap scanning. The classification rules and provider/ASN lists are in `config/asn_providers.sh` — edit this file to add or modify providers.

## Nmap Candidate Selection

By default, nmap scans IPs classified as `dedicated`, `cloud`, or `unknown`. CDN IPs are excluded from scanning but retained in the output. This produces:

- `nmap_candidates.txt` — IPs to scan
- `cdn_ips.txt` — CDN IPs (not scanned)
- `non_cdn_ips.txt` — All non-CDN IPs

## HTTPX Metadata

HTTPX now collects CDN detection, technology fingerprinting, content length, and web server metadata using the flags `-cdn -tech-detect -web-server -content-length`. This metadata is preserved across all HTTPX rounds and merged into a companion file (`httpx_metadata.tsv`) linked to the canonical DNS dataset.

---

## Logging

All stage output is logged to `recon.log` in the output directory with timestamps. Every tool invocation, result count, warning, and error is captured. This is useful for debugging or improving the pipeline later.

```
2026-08-14 14:23:01 [*] Phase 1: Root Domains → Subdomains (3 domains)
2026-08-14 14:23:01 [*] Processing domain: example.com
2026-08-14 14:23:01 [*] Running Subfaster...
2026-08-14 14:23:45 [+] Subfaster subdomains: 142
2026-08-14 14:24:02 [*] Probing 142 targets with httpx...
2026-08-14 14:24:18 [+] Live web servers found: 67
...
```

---

## Usage

### CLI Flags

```
Usage: recon.sh [options]

Required (one of):
  --domains d1,d2,...       Comma-separated root domains
  --domains-file FILE       Line-separated root domains file

Options:
  -h, --help                Show this help and exit
  --subfaster-config FILE   Path to subfaster provider-config.yaml (API keys)
  --proxy URL               Proxy for PASSIVE sources only — crt.name, GitHub, subfaster,
                            waymore. Target DNS/HTTPX/Nmap stay on the direct network.
                            e.g. socks5h://host.docker.internal:12334 or http://host.docker.internal:8080
  --resolvers FILE          DNS resolver list, health-checked at startup so only resolvers
                            reachable from this network are used (default: built-in list)
  --asn-config FILE         Path to ASN provider classification config (default: built-in)
  --waymore-mode MODE       Waymore mode: U (URLs, default) or B (URLs+responses). R
                            (responses only) is not supported — the pipeline consumes URL output
  --auto                    Skip all checkpoint prompts
  --skip-phase {1,2,3}      Skip specific phase(s) — value is validated
  --skip-cloud              Shorthand for --skip-phase 2
  --no-port-scan            Skip the port-scan stage inside Phase 3 (classification still runs)
  --skip-permutation        Disable dnsgen permutation brute force (Stage 4b) for all domains
                            (recommended for large multi-domain sweeps)
  --threads N               Threads for dnsx and Cloud_Enum (default: 50)
  --parallel-hosts N        Hosts crawled in parallel per per-host tool (default: 5)
  --parallel-domains N      Root domains processed in parallel in Phase 1 (default: 3)
  --rate-limit N            httpx requests/second (default: 100)
  --nmap-top-ports N        Cap nmap -sV (Phase 3) to the N most-common open ports (default: 100; 0 = no cap)
  --timeout N               Checkpoint auto-continue timeout in seconds; 0 = wait forever (default: 30)
  --output DIR              Output directory (default: /output)
  --cloud-enum-keywords KW Keywords for cloud_enum brute force (comma-sep, auto-derived from domains)
```

> **Flag scope notes:** `--rate-limit` applies only to httpx (Waymore, Katana, and the DNS tools use their own fixed/internal limits); `--threads` applies only to dnsx and Cloud_Enum.
>
> **`--proxy` scope:** when set, the proxy is applied **only** to the passive OSINT sources (crt.name, GitHub pre-flight + github-subdomains, subfaster, waymore). Target DNS resolution, HTTPX, and the Nmap/naabu port scan deliberately stay **direct** so scanning sees real IPs. `curl` and `waymore` route cleanly over SOCKS or HTTP; statically-linked Go tools (subfaster, github-subdomains) honor `HTTP(S)_PROXY` only for an `http://` proxy, so prefer an HTTP proxy URL for full coverage. Note `localhost` inside the container is the container itself — use `host.docker.internal` for a proxy running on the Docker host.
>
> **`--nmap-top-ports`:** naabu still records every open port (all are kept in the final `ip_port_pairs.txt`); this flag only bounds how many ports nmap `-sV` service-detects, preventing the port union across hundreds of hosts from turning Phase 3 into a ~1000-port × N-host scan.

### Checkpoints

Without `--auto`, the pipeline pauses after each phase with a menu:

```
[CHECKPOINT] Phase 1 complete. ...

  [C]ontinue  [S]kip next phase  [Q]uit  [R]eview results
  >
```

- `C`/Enter continues; `S` skips the next phase; `Q` exits cleanly; `R` lists the phase's output files.
- On a non-TTY run (e.g. `docker run` without `-it`), checkpoints auto-continue — `--auto` and `--timeout` only matter on an interactive terminal.
- With `--timeout N` (default 30s), an unanswered prompt auto-continues after N seconds; `--timeout 0` waits forever.

### Examples

**Basic run with comma-separated domains:**
```bash
docker run --rm -it -v $(pwd)/results:/output metho \
  --domains "example.com,example.org" --auto
```

**From a domains file with all features:**
```bash
docker run --rm -it \
  -v $(pwd)/results:/output \
  -v $(pwd)/targets.txt:/input/domains.txt:ro \
  metho \
  --domains-file /input/domains.txt --auto
```

**With subfaster provider config (API keys for Shodan, Censys, etc.):**
```bash
docker run --rm -it \
  -v $(pwd)/results:/output \
  -v $(pwd)/targets.txt:/input/domains.txt:ro \
  -v $(pwd)/provider-config.yaml:/input/provider-config.yaml:ro \
  metho \
  --domains-file /input/domains.txt \
  --subfaster-config /input/provider-config.yaml \
  --auto
```

**Routing the passive OSINT sources through a proxy (scanning stays direct):**
```bash
docker run --rm -it \
  -v $(pwd)/results:/output \
  -v $(pwd)/targets.txt:/input/domains.txt:ro \
  -v $(pwd)/provider-config.yaml:/input/provider-config.yaml:ro \
  metho \
  --domains-file /input/domains.txt \
  --subfaster-config /input/provider-config.yaml \
  --proxy socks5h://host.docker.internal:12334 \
  --nmap-top-ports 100 \
  --auto
```

**With custom ASN provider config:**
```bash
docker run --rm -it \
  -v $(pwd)/results:/output \
  -v $(pwd)/my-asn-providers.sh:/input/asn-providers.sh:ro \
  metho \
  --domains "example.com" \
  --asn-config /input/asn-providers.sh \
  --auto
```

**Skip cloud discovery and port scanning:**
```bash
docker run --rm -it \
  -v $(pwd)/results:/output \
  -v $(pwd)/targets.txt:/input/domains.txt:ro \
  metho \
  --domains-file /input/domains.txt \
  --skip-cloud --no-port-scan --auto
```

**Waymore URLs-only mode (faster, no response downloading):**
```bash
docker run --rm -it \
  -v $(pwd)/results:/output \
  metho --domains "example.com" --waymore-mode U --auto
```

### Per-tool timeouts

Some tools can stall on misbehaving hosts. Each one has a configurable wall-clock cap:

| Variable | Default | Tool / What it bounds |
|----------|---------|----------------------|
| `BRUTEFORCE_TIMEOUT` | `900` | dnsx brute force (per root domain) |
| `KATANA_TIMEOUT` | `600` | Katana crawl in Phase 1 (per live host) |
| `KATANA_CRAWL_DURATION` | `15m` | Katana per-host wall-clock cap (Phase 1) |
| `SUBDOMAINIZER_TIMEOUT` | `300` | SubDomainizer JS scan (per live host) |
| `DNSX_TIMEOUT` | `600` | DNSx bulk resolution |
| `CLOUD_ENUM_TIMEOUT` | `900` | Cloud_Enum keyword mutation (single call per Phase 2 run) |
| `CEWL_TIMEOUT` | `600` | CeWL word-crawl (per live host) |
| `CEWL_DEPTH` | `2` | CeWL spider depth on first pass (retries at depth 1 on failure) |
| `CEWL_MEM_LIMIT_MB` | `1024` | CeWL per-process address-space cap (MB) |
| `WAYMORE_TIMEOUT` | `600` | Waymore historical recon (per root domain) |
| `GITHUB_SUBDOMAINS_TIMEOUT` | `300` | GitHub-subdomains code search (per root domain) |
| `DNSGEN_TIMEOUT` | `120` | dnsgen permutation generation |
| `DNSGEN_MAX_INPUT` | `500` | Max subdomains fed to dnsgen (resolved hosts prioritized; 0 disables) |
| `DNSGEN_SKIP_THRESHOLD` | `1500` | Domains with more discovered subs than this skip dnsgen entirely (large targets: ~0 yield, hours of DNS; 0 disables) |
| `DNSGEN_MAX_OUTPUT_BYTES` | `26214400` | Hard cap on dnsgen permutation output size (25MB) |
| `NAABU_TIMEOUT` | `600` | Naabu fast port scan |
| `NAABU_TOP_PORTS` | `1000` | Naabu top-N ports to scan |
| `NAABU_RATE` | `1000` | Naabu packets/sec cap (noise/IPS throttle) |
| `NAABU_RETRIES` | `2` | Naabu SYN retransmit count |

```bash
docker run --rm -it \
  -v $(pwd)/results:/output \
  -e KATANA_TIMEOUT=900 \
  -e WAYMORE_TIMEOUT=2700 \
  -e CEWL_MEM_LIMIT_MB=1536 \
  metho --domains "example.com" --parallel-hosts 8 --parallel-domains 5 --auto
```

---

## Output Structure

Mount a local directory as `/output`. After the pipeline completes, it looks like this:

```
results/
├── RECON_SUMMARY.txt              # Final summary with all counts
├── recon.log                      # Timestamped log of all stages
├── canonical_dns.tsv              # Canonical hostname→DNS dataset
├── httpx_metadata.tsv             # HTTPX CDN/tech/webserver metadata per host
├── root_domains.txt               # Normalized, deduplicated input root domains
│
├── phase1/
│   ├── example.com/
│   │   ├── all_subdomains_final.txt      # All subdomains discovered
│   │   ├── live_subdomains_final.txt     # Live web server URLs
│   │   ├── httpx_results_final.json      # Full HTTPx JSON output
│   │   ├── httpx_results_final.httpx.log # HTTPx debug log
│   │   ├── subfaster_results.txt        # Subfaster (passive enum) results
│   │   ├── crtname_results.txt           # crt.name (CT log) subdomains
│   │   ├── crtname_raw.json              # Raw crt.name API response
│   │   ├── waymore_subdomains.txt        # In-scope subdomains from Waymore
│   │   ├── waymore_urls.txt              # All historical URLs from Waymore
│   │   ├── waymore_output/               # Waymore response archive
│   │   ├── katana/
│   │   │   ├── discovered_urls.txt       # URLs discovered by Katana
│   │   │   ├── discovered_hosts.txt      # In-scope hosts from Katana
│   │   │   └── javascript_assets.txt     # JavaScript assets from Katana
│   │   ├── subdomainizer_subdomains.txt  # SubDomainizer subdomains
│   │   └── ...
│   └── ...
│
├── phase2/
│   ├── final_cloud_assets.txt            # All cloud assets consolidated
│   ├── dnsx_cloud_domains.txt
│   ├── cloud_enum_assets.txt
│   ├── katana_cloud_assets.txt
│   └── ...
│
├── phase3/
│   ├── all_resolved_ips.txt              # All unique resolved IPs
│   ├── ip_classification.tsv            # IP → classification (cdn/cloud/dedicated/unknown)
│   ├── cdn_ips.txt                       # CDN-classified IPs
│   ├── non_cdn_ips.txt                   # Non-CDN IPs (cloud + dedicated + unknown)
│   ├── nmap_candidates.txt               # IPs targeted for port scanning
│   ├── asn_list.txt                      # All ASNs
│   ├── asn_summary.txt                   # ASNs sorted by IP count
│   ├── network_ranges.txt                # CIDR blocks
│   ├── domain_ip_map.txt                 # Domain → IP mapping
│   ├── ip_asn_map.txt                    # IP → ASN mapping
│   └── ip_port_pairs.txt                 # IP:port from port scan
│
├── results/                               # Clean per-root-domain final results
│   ├── example.com/
│   │   ├── subdomains.txt                 # In-scope hostnames for this root
│   │   ├── dns_records.tsv                # Canonical DNS info for those hosts
│   │   ├── live_hosts.tsv                 # HTTPX results (url, status, title, tech, …)
│   │   ├── ips.txt                        # Unique IPs associated with this root
│   │   ├── ip_asn.tsv                     # IP, ASN, org, classification
│   │   ├── nmap_results/                  # Nmap output for this root's IPs
│   │   │   ├── ip_port_pairs.txt
│   │   │   └── port_scan_results.txt
│   │   ├── cloud_assets.txt               # Cloud assets attributed to this root
│   │   ├── waymore_urls.txt               # Historical URLs for this root
│   │   └── discovery_sources.tsv          # Hostname → discovery provenance
│   └── example.co.uk/
│       └── ...
│
└── final/
    ├── final_all_domains.txt             # Every subdomain across all root domains
    ├── final_live_web_servers.txt        # Every live URL across all root domains
    ├── final_httpx_metadata.json          # Full httpx JSON output (CDN, tech, etc.)
    ├── httpx_metadata.tsv                 # Per-host HTTPX metadata (companion to canonical_dns.tsv)
    ├── canonical_dns.tsv                  # Canonical hostname→DNS dataset
    ├── final_waymore_urls.txt             # All historical URLs from Waymore
    ├── final_cloud_assets.txt             # Every cloud asset
    ├── final_asn_list.txt                 # All ASNs
    ├── final_asn_summary.txt             # ASNs sorted by occurrence count
    ├── final_network_ranges.txt           # All network ranges
    ├── final_ip_addresses.txt             # All IPs
    ├── final_ip_classification.tsv       # IP classification (cdn/cloud/dedicated/unknown)
    ├── final_ip_port_pairs.txt            # IP:port from non-CDN scan
    ├── final_cdn_ips.txt                  # CDN IPs
    ├── final_non_cdn_ips.txt              # Non-CDN IPs
    ├── final_nmap_candidates.txt          # IPs targeted for port scanning
    └── final_domain_ip_map.txt            # Domain→IP mapping
```

### The `final/` Directory

This is the one you care about. It contains deduplicated, consolidated lists ready for the next stage of your bug bounty workflow.

Key files:
- **`canonical_dns.tsv`** — The single source of truth for hostname→DNS mappings. Every hostname discovered by any tool is tracked here with its resolution status and discovery sources.
- **`final_ip_classification.tsv`** — Deterministic IP classification with CDN/cloud/dedicated/unknown labels, associated hostnames, root domains, ASN, and ASN org.
- **`final_nmap_candidates.txt`** — IPs that were actually port-scanned (excludes CDN IPs).
- **`final_httpx_metadata.json`** — Full HTTPx output with CDN detection, tech fingerprinting, web server, and content length for every live host.
- **`final_waymore_urls.txt`** — All historical URLs discovered by Waymore across all root domains.

### The `results/` Directory — Per-Root-Domain Final Results

After all phases and the global `final/` consolidation complete, Metho carves the
global datasets into **clean, human-consumable per-root-domain result directories**
under `results/<root-domain>/`. This is an additive presentation layer — it does
not re-run any tools, duplicate raw artifacts, or modify the phase directories.

```
results/
├── example.com/
│   ├── subdomains.txt          # All in-scope hostnames for this root
│   ├── dns_records.tsv         # Canonical DNS info (A/AAAA/CNAME/status)
│   ├── live_hosts.tsv          # HTTPX: url, status, title, tech, webserver, content_length, cdn
│   ├── ips.txt                 # Unique IPs associated with this root
│   ├── ip_asn.tsv              # IP, ASN, org, classification
│   ├── nmap_results/           # Nmap output for this root's IPs
│   ├── cloud_assets.txt        # Cloud assets attributed to this root
│   ├── waymore_urls.txt        # Historical URLs for this root
│   └── discovery_sources.tsv   # Hostname → discovery provenance
└── example.co.uk/
    └── …
```

How it works:

- **`phase1/`, `phase2/`, `phase3/`, and the global canonical files** hold the
  detailed raw/intermediate evidence and debugging data.
- **`results/<root-domain>/`** is a compact, final representation of the assets
  discovered for that root — generated by filtering/consolidating the existing
  global datasets, never by re-running reconnaissance.
- **Hostname→root attribution** comes only from the `root_domain` column of
  `canonical_dns.tsv` — root domains are never derived from hostname labels, so
  ccTLDs like `example.co.uk` are attributed correctly (not `co.uk`).
- **Many-to-many IP relationships are preserved.** If an IP is shared by hosts in
  multiple root domains, it appears in every applicable root's `ips.txt`,
  `ip_asn.tsv`, and `nmap_results/`.
- **Discovery provenance is preserved.** `discovery_sources.tsv` lists every tool
  that found each hostname (e.g. `subfaster;crt.name;waymore;dnsx-brute`), and
  root-seeded apexes keep the `root` source.
- All per-root outputs are deduplicated.

### RECON_SUMMARY.txt

A human-readable summary printed at the end of every run:

```
========================================
RECONNAISSANCE PHASE COMPLETE
========================================

Root Domains Provided: 3

ASSETS DISCOVERED:
- All Subdomains:     1,247
- Live Web Servers:   389
- Waymore URLs:       12,456
- Cloud Assets:       23
- ASNs:               15
- Network Ranges:     28
- IP Addresses:       456
- IP:Port Pairs:      1,102

IP CLASSIFICATION:
- CDN IPs:            187
- Cloud IPs:          134
- Dedicated IPs:      89
- Unknown IPs:        46

FILES CREATED IN final/:
...

LOG FILE:
- recon.log                      (timestamped log of all stages)

NEXT STEPS:
Proceed to vulnerability scanning / enumeration on live web servers.

========================================
```

---

## Building the Image

```bash
docker build -t metho .
```

The build uses a multi-stage Dockerfile:
- **Builder stage** (`debian:13-slim`): Compiles the Go binaries (subfaster, httpx, katana, dnsx, naabu, github-subdomains — all pinned to exact release versions), and clones the git-hosted tools (CeWL, SubDomainizer, cloud_enum, dnsgen). Go compiler, git, and build-essential stay in this stage.
- **Runtime stage** (`debian:13-slim`): Copies the compiled binaries and cloned tools, installs runtime interpreters/packages, and installs the Ruby gems CeWL needs (native gems must compile against the runtime's libc, so they are built here — their build deps are purged in the same layer). No compilers, Go SDK, or git in the final image.

---

## How It Works Under the Hood

```
┌──────────────────────────────────────────────────────────┐
│  recon.sh (orchestrator)                                 │
│                                                          │
│  Input: --domains or --domains-file → root_domains.txt   │
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐              │
│  │ Phase 1   │─▶│ Phase 2   │─▶│ Phase 3   │             │
│  │ Subdomain │  │ Cloud     │  │ Classify  │              │
│  │ Discovery │  │ Assets    │  │ & Ports   │              │
│  │ lib/      │  │ lib/      │  │ lib/      │               │
│  │ phase1.sh │  │ phase2.sh │  │ phase3.sh │              │
│  └──────────┘  └──────────┘  └──────────┘              │
│        │             │             │                      │
│        ▼             ▼             ▼                      │
│  ┌──────────────────────────────────────────┐            │
│  │         lib/consolidate.sh               │             │
│  │    Merge → final/ → RECON_SUMMARY.txt    │            │
│  └──────────────────────────────────────────┘            │
│                       │                                   │
│                       ▼                                   │
│  ┌──────────────────────────────────────────┐            │
│  │  lib/results.sh                          │             │
│  │  Per-root results/ (sliced from globals) │            │
│  └──────────────────────────────────────────┘            │
│                                                          │
│  ┌──────────────────────────────────────────┐            │
│  │  lib/canonical_dns.sh                    │             │
│  │  Canonical DNS TSV (source of truth)     │             │
│  └──────────────────────────────────────────┘            │
│                                                          │
│  lib/utils.sh — logging, CLI, httpx, cloud domain filter  │
│  lib/classify.sh — deterministic IP/CDN/ASN classification │
│  config/asn_providers.sh — ASN/provider lists (editable)   │
└──────────────────────────────────────────────────────────┘
```

---

## Tips

- **Rate limiting matters.** If httpx is getting timeouts or empty results, lower `--rate-limit` (e.g., 50 or 25) — note this flag affects httpx only.
- **ASN occurrence matters.** In `final_asn_summary.txt`, ASNs with fewer IPs are more interesting — they may represent niche hosting or forgotten infrastructure.
- **Cloud enum keywords.** By default, the base name of each root domain is used as a keyword. Use `--cloud-enum-keywords` to add extra keywords.
- **Check canonical_dns.tsv.** The canonical DNS dataset tracks every hostname, its resolution status, and which tools discovered it. Useful for debugging and understanding coverage gaps.
- **IP classification is configurable.** Edit `config/asn_providers.sh` to add or remove CDN, cloud, and dedicated hosting providers and ASNs.
- **Waymore modes.** Mode `U` (URLs only, default) is fast and sufficient for subdomain discovery — the pipeline extracts subdomains from the URL output. Mode `B` also downloads archived response bodies (slower, richer data, but the pipeline does not currently parse them). Mode `R` (responses without the URL file) is not supported.
- **GitHub subdomain discovery.** Set the `GITHUB_TOKEN` environment variable (comma-separated for multiple tokens) or include GitHub tokens in the subfaster provider-config. The pipeline searches GitHub code for references to each target domain.
- **Subdomain permutation.** After brute force, dnsgen generates permutations from discovered subdomain patterns (e.g. `dev` → `dev1`, `dev-internal`, `dev-staging`) and resolves them. This finds subdomains that follow the target's naming conventions but appear in no passive source.
- **Reverse DNS.** Phase 3 performs PTR lookups on all resolved IPs, which can reveal hostnames not discovered by any subdomain enumeration tool.
- **Two-phase port scanning.** Naabu fast-scans the top 1000 ports on all non-CDN candidates, then nmap runs service/version detection (`-sV`) on only the hosts naabu found open — the hosts with nothing open skip the expensive -sV pass entirely, and the fallback fixed-port list covers the rare case where naabu is unavailable or finds nothing.
- **Check recon.log.** The timestamped log file captures everything — useful for debugging or tuning the pipeline.
- **Do manual recon first.** Google dorking and reverse WHOIS can find additional root domains. Add them to your input file before running the pipeline.

---

## Testing

Unit tests for the pipeline's pure functions (hostname normalization, ccTLD-safe
root matching, classification priority, canonical-DNS lifecycle, cloud-domain
filtering) live in `tests/run_tests.sh` and run as part of both GitHub build
workflows. To run them locally against a built image:

```bash
docker run --rm --entrypoint bash -v $(pwd)/tests:/opt/scripts/tests:ro \
  metho /opt/scripts/tests/run_tests.sh
```