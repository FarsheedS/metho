# Metho — Automated Recon Pipeline

A Dockerized, fully automated reconnaissance pipeline for bug bounty hunting. Feed it root domains and it maps the entire attack surface: subdomains, live web servers, cloud assets, ASN/network infrastructure, IPs, and open ports.

Inspired by the [Ars0n Framework v2](https://github.com/R-s0n/ars0n-framework-v2) methodology.

## Tools

The pipeline is built on the work of many open-source projects. Every tool
below is wired into one or more phases (see [Installed Tools](#installed-tools)
for the per-phase breakdown):

- [Subfaster](https://github.com/melvinsh/subfaster) — Passive subdomain enumeration (Subfinder fork, faster defaults)
- [crt.name](https://crt.name) — Certificate Transparency log lookup
- [Waymore](https://github.com/xnl-h4ck3r/waymore) — Historical URL/subdomain discovery from Wayback/CommonCrawl/OTX/URLScan/VirusTotal
- [CeWL](https://github.com/digininja/CeWL) — Custom wordlist generation via web spidering
- [ShuffleDNS](https://github.com/projectdiscovery/shuffledns) — DNS brute force with CeWL-derived wordlists
- [massdns](https://github.com/blechschmidt/massdns) — High-performance DNS resolver (required by ShuffleDNS)
- [Katana](https://github.com/projectdiscovery/katana) — Web crawler and JavaScript discovery
- [Subdomainizer](https://github.com/nsonaniya2010/SubDomainizer) — JavaScript subdomain and secret extraction
- [httpx](https://github.com/projectdiscovery/httpx) — HTTP probing with CDN detection, tech fingerprinting, and metadata
- [dnsx](https://github.com/projectdiscovery/dnsx) — Canonical DNS resolution layer
- [Cloud_Enum](https://github.com/initstring/cloud_enum) — AWS/Azure/GCP bucket and service brute force
- [nmap](https://github.com/nmap/nmap) — Port scanning of non-CDN IPs

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
| 1 | Passive subdomain enumeration | Subfaster, crt.name |
| 2 | Historical URL/subdomain discovery | Waymore (root domains only) |
| 3 | Consolidate + DNSx resolution + HTTPx Round 1 | dnsx, httpx |
| 4 | Custom wordlist generation + DNS brute force | CeWL, ShuffleDNS |
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

Resolves all discovered domains to IPs, performs deterministic IP classification, and port scans non-CDN IPs.

| Stage | What Happens | Tool(s) |
|-------|-------------|---------|
| 1 | Extract IPs from canonical DNS dataset | dnsx (already resolved) |
| 2 | IP → ASN lookup via whois.cymru.com | nc |
| 3 | Deterministic IP classification (CDN/cloud/dedicated/unknown) | Built-in classification engine |
| 4 | Port scan on nmap candidates (dedicated + cloud + unknown) | nmap |

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
| `resolution_status` | `resolved`, `nxdomain`, `timeout`, or `pending` |

Phases 2 and 3 never re-resolve the entire corpus — only newly discovered hosts are resolved through dnsx, and the results are merged incrementally.

## Deterministic IP Classification

IPs are classified using a strict priority order:

1. **HTTPX CDN = true** → `cdn`
2. **ASN matches CDN config** → `cdn`
3. **ASN matches cloud config** → `cloud`
4. **ASN matches dedicated hosting config** → `dedicated`
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
  --subfaster-config FILE   Path to subfaster provider-config.yaml (API keys)
  --asn-config FILE         Path to ASN provider classification config (default: built-in)
  --waymore-mode MODE       Waymore mode: U (URLs), R (responses), B (both, default)
  --auto                    Skip all checkpoint prompts
  --skip-phase {1,2,3}      Skip specific phase(s)
  --skip-cloud              Shorthand for --skip-phase 2
  --no-port-scan            Skip port scanning phase
  --threads N               Thread count (default: 50)
  --parallel-hosts N         Hosts crawled in parallel per per-host tool (default: 5)
  --rate-limit N            Requests/second (default: 100)
  --timeout N               Checkpoint auto-continue timeout in seconds (default: 30)
  --output DIR              Output directory (default: /output)
  --cloud-enum-keywords KW Keywords for cloud_enum brute force (comma-sep, auto-derived from domains)
```

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
| `SHUFFLEDNS_TIMEOUT` | `900` | ShuffleDNS brute force (per root domain) |
| `KATANA_TIMEOUT` | `600` | Katana crawl in Phase 1 (per live host) |
| `KATANA_CRAWL_DURATION` | `30m` | Katana per-host wall-clock cap (Phase 1) |
| `SUBDOMAINIZER_TIMEOUT` | `300` | SubDomainizer JS scan (per live host) |
| `DNSX_TIMEOUT` | `600` | DNSx bulk resolution |
| `CLOUD_ENUM_TIMEOUT` | `1800` | Cloud_Enum keyword mutation (single call per Phase 2 run) |
| `CEWL_TIMEOUT` | `600` | CeWL word-crawl (per live host) |
| `CEWL_DEPTH` | `2` | CeWL spider depth on first pass (retries at depth 1 on failure) |
| `CEWL_MEM_LIMIT_MB` | `1024` | CeWL per-process address-space cap (MB) |
| `WAYMORE_TIMEOUT` | `1800` | Waymore historical recon (per root domain) |

```bash
docker run --rm -it \
  -v $(pwd)/results:/output \
  -e KATANA_TIMEOUT=900 \
  -e WAYMORE_TIMEOUT=2700 \
  -e CEWL_MEM_LIMIT_MB=1536 \
  metho --domains "example.com" --parallel-hosts 8 --auto
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
├── root_domains.txt               # Resolved input root domains
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
└── final/
    ├── final_all_domains.txt             # Every subdomain across all root domains
    ├── final_live_web_servers.txt        # Every live URL across all root domains
    ├── final_httpx_metadata.json          # Full httpx JSON output (CDN, tech, etc.)
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
- **Builder stage** (`debian:13-slim`): Compiles Go binaries (subfaster, httpx, katana, dnsx, shuffledns), massdns, and installs Ruby gems for CeWL. All build-only dependencies (Go compiler, git, build-essential, ruby-dev, etc.) stay in this stage.
- **Runtime stage** (`debian:13-slim`): Copies only the compiled binaries and runtime dependencies. No compilers, Go SDK, Python headers, or build tools in the final image.

### Installed Tools

Every tool below is wired into the pipeline (see `lib/phase1.sh`, `lib/phase2.sh`, `lib/phase3.sh`).

#### Subdomain Discovery — Phase 1

| Tool | Role |
|------|------|
| **Subfaster** | Passive subdomain enumeration (fast Subfinder fork) |
| **crt.name** | Certificate Transparency log lookup |
| **Waymore** | Historical URL/subdomain discovery (Wayback, CommonCrawl, etc.) |
| **CeWL** | Spider live hosts → custom wordlist for DNS brute force |
| **ShuffleDNS** | DNS brute force using CeWL-derived wordlist |
| **massdns** | High-performance DNS resolver (required by ShuffleDNS) |
| **Katana** | Web crawler — finds URLs, JS endpoints, and new subdomains |
| **SubDomainizer** | Extract subdomains and secrets from JavaScript files |
| **httpx** | HTTP/HTTPS probing with CDN detection and tech fingerprinting (3 rounds) |
| **dnsx** | Canonical DNS resolution layer |

#### Cloud Asset Discovery — Phase 2

| Tool | Role |
|------|------|
| **dnsx** | Bulk DNS queries for cloud CNAME/A records |
| **Cloud_Enum** | AWS / Azure / GCP bucket and service brute force |

#### IP / Classification / Port Scan — Phase 3

| Tool | Role |
|------|------|
| **dnsx** | DNS resolution (data already in canonical dataset) |
| **nc** (netcat) | whois.cymru.com ASN lookup |
| **nmap** | Port scanning of nmap candidates (dedicated + cloud + unknown IPs) |

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

- **Rate limiting matters.** If you're getting timeouts or empty results, lower `--rate-limit` (e.g., 50 or 25).
- **ASN occurrence matters.** In `final_asn_summary.txt`, ASNs with fewer IPs are more interesting — they may represent niche hosting or forgotten infrastructure.
- **Cloud enum keywords.** By default, the base name of each root domain is used as a keyword. Use `--cloud-enum-keywords` to add extra keywords.
- **Check canonical_dns.tsv.** The canonical DNS dataset tracks every hostname, its resolution status, and which tools discovered it. Useful for debugging and understanding coverage gaps.
- **IP classification is configurable.** Edit `config/asn_providers.sh` to add or remove CDN, cloud, and dedicated hosting providers and ASNs.
- **Waymore modes.** Use `--waymore-mode U` for URLs only (faster) or `--waymore-mode B` for both URLs and archived responses (slower, richer data).
- **Check recon.log.** The timestamped log file captures everything — useful for debugging or tuning the pipeline.
- **Do manual recon first.** Google dorking and reverse WHOIS can find additional root domains. Add them to your input file before running the pipeline.