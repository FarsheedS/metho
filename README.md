# Metho — Automated Recon Pipeline

A Dockerized, fully automated reconnaissance pipeline for bug bounty hunting. Feed it root domains and it maps the entire attack surface: subdomains, live web servers, cloud assets, ASN/network infrastructure, IPs, and open ports.

Inspired by the [Ars0n Framework v2](https://github.com/R-s0n/ars0n-framework-v2) methodology.

## Tools

The pipeline is built on the work of many open-source projects. Every tool
below is wired into one or more phases (see [Installed Tools](#installed-tools)
for the per-phase breakdown):

- [Cero](https://github.com/glebarez/cero)
- [Subfinder](https://github.com/projectdiscovery/subfinder)
- [Assetfinder](https://github.com/tomnomnom/assetfinder)
- [GAU](https://github.com/lc/gau)
- [Sublist3r](https://github.com/aboul3la/Sublist3r)
- [github-subdomains](https://github.com/gwen001/github-subdomains)
- [CeWL](https://github.com/digininja/CeWL)
- [ShuffleDNS](https://github.com/projectdiscovery/shuffledns)
- [massdns](https://github.com/blechschmidt/massdns)
- [GoSpider](https://github.com/jaeles-project/gospider)
- [Subdomainizer](https://github.com/nsonaniya2010/SubDomainizer)
- [httpx](https://github.com/projectdiscovery/httpx)
- [Amass](https://github.com/owasp-amass/amass)
- [dnsx](https://github.com/projectdiscovery/dnsx)
- [Cloud_Enum](https://github.com/initstring/cloud_enum)
- [Katana](https://github.com/projectdiscovery/katana)
- [nmap](https://github.com/nmap/nmap)

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

For each root domain, discovers every subdomain through multiple complementary techniques.

| Stage | What Happens | Tool(s) |
|-------|-------------|---------|
| 1 | Certificate transparency, OSINT scraping | Cero, Subfinder, Assetfinder, GAU, Sublist3r, github-subdomains |
| 2 | Consolidate + HTTPx probe (Round 1) | httpx |
| 3 | Custom wordlist generation + DNS brute force | CeWL, ShuffleDNS |
| 4 | Consolidate + HTTPx probe (Round 2) | httpx |
| 5 | Web crawling + JavaScript analysis | GoSpider, Subdomainizer |
| 6 | Final consolidation + HTTPx probe (Round 3) | httpx |

Each domain gets its own output subdirectory: `phase1/example.com/`.

### Phase 2: Cloud Asset Discovery

Discovers AWS, Azure, and GCP assets associated with the root domains.

| Stage | What Happens | Tool(s) |
|-------|-------------|---------|
| 1 | DNS enumeration for cloud CNAME/A records | Amass Enum |
| 2 | Advanced DNS queries for cloud infrastructure | DNSx |
| 3 | Brute force cloud storage buckets and services | Cloud_Enum |
| 4 | Crawl web apps for cloud URL references | Katana |
| 5 | Consolidate all cloud assets | — |

### Phase 3: IP Extraction → ASN Mapping → Port Scanning

Resolves all discovered domains to IPs, maps them to ASNs, and port scans non-CDN IPs.

| Stage | What Happens | Tool(s) |
|-------|-------------|---------|
| 1 | DNS resolution of all subdomains | dig, dnsx |
| 2 | IP → ASN lookup sorted by occurrence | whois.cymru.com |
| 3 | CDN IP filtering | built-in CDN ASN list |
| 4 | Port scan on non-CDN IPs | nmap |

---

## Logging

All stage output is logged to `recon.log` in the output directory with timestamps. Every tool invocation, result count, warning, and error is captured. This is useful for debugging or improving the pipeline later.

```
2026-05-31 14:23:01 [*] Phase 1: Root Domains → Subdomains (3 domains)
2026-05-31 14:23:01 [*] Processing domain: example.com
2026-05-31 14:23:01 [*] Running Cero (certificate transparency)...
2026-05-31 14:23:45 [+] Subdomains from scraping: 142
2026-05-31 14:24:02 [*] Probing 142 targets with httpx...
2026-05-31 14:24:18 [+] Live web servers found: 67
...
```

---

## Manual Steps

Some reconnaissance steps are best done manually before running the pipeline:

### Pre-Pipeline: Google Dorking & Reverse WHOIS

Before running the pipeline, do manual reconnaissance to find additional root domains:

**Google Dorking:**
```
site:*.example.com
"Example Corp" site:com
inurl:examplecorp
```

**Reverse WHOIS:**
1. Get WHOIS info: `whois example.com | grep -E 'Registrant|Admin'`
2. Search the organization name or email on:
   - https://viewdns.info/reversewhois/
   - https://whoxy.com/
3. Add discovered domains to your input file

### Post-Pipeline: Review

Always review after the pipeline completes:
- `final/final_all_domains.txt` for false positives
- `final/final_asn_summary.txt` for interesting low-count ASNs
- `final/final_httpx_metadata.json` for technology detection results

---

## Usage

### CLI Flags

```
Usage: recon.sh [options]

Required (one of):
  --domains d1,d2,...     Comma-separated root domains
  --domains-file FILE     Line-separated root domains file

Options:
  --subfinder-config FILE Path to subfinder provider-config.yaml (API keys)
  --amass-config FILE     Path to amass config.yaml (API keys -> fewer 403/429)
  --auto                  Skip all checkpoint prompts
  --skip-phase {1,2,3}    Skip specific phase(s)
  --skip-cloud            Shorthand for --skip-phase 2
  --no-port-scan          Skip port scanning phase
  --threads N             Thread count (default: 50)
  --parallel-hosts N      Hosts crawled in parallel per per-host tool (default: 5)
  --rate-limit N          Requests/second (default: 100)
  --timeout N             Checkpoint auto-continue timeout in seconds (default: 30)
  --output DIR            Output directory (default: /output)
  --github-tokens-file FILE  File with GitHub tokens (one per line) for github-subdomains
  --cloud-enum-keywords KW   Keywords for cloud_enum brute force (comma-sep, auto-derived from domains)
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

The domains file is a plain text file with one root domain per line:
```
example.com
example.org
example-cdn.net
```

**With GitHub tokens for github-subdomains:**
```bash
docker run --rm -it \
  -v $(pwd)/results:/output \
  -v $(pwd)/targets.txt:/input/domains.txt:ro \
  -v $(pwd)/github-tokens.txt:/input/github-tokens.txt:ro \
  metho \
  --domains-file /input/domains.txt \
  --github-tokens-file /input/github-tokens.txt \
  --auto
```

GitHub tokens file format (one token per line):
```
ghp_xxxxxxxxxxxxxxxxxxxx
ghp_yyyyyyyyyyyyyyyyyyyy
```

**With subfinder provider config (API keys for Shodan, Censys, etc.):**
```bash
docker run --rm -it \
  -v $(pwd)/results:/output \
  -v $(pwd)/targets.txt:/input/domains.txt:ro \
  -v $(pwd)/provider-config.yaml:/input/provider-config.yaml:ro \
  metho \
  --domains-file /input/domains.txt \
  --subfinder-config /input/provider-config.yaml \
  --auto
```

**With an Amass config (API keys -> fewer 403/429 from passive sources):**
```bash
docker run --rm -it \
  -v $(pwd)/results:/output \
  -v $(pwd)/targets.txt:/input/domains.txt:ro \
  -v $(pwd)/amass-config.yaml:/input/amass-config.yaml:ro \
  metho \
  --domains-file /input/domains.txt \
  --amass-config /input/amass-config.yaml \
  --auto
```
Without a config, Amass runs passively but ~40 premium data sources
(Shodan, Censys, SecurityTrails, URLScan, VirusTotal, ...) skip the auth
check and you see a flood of "check callback failed" / `403` / `429` lines in
`phase2/amass.stderr.log`. A `config.yaml` with those keys makes them answer.
The remaining `403/429` from *free* sources are provider-side rate/geo blocks,
not config issues.

**Skip cloud discovery and port scanning:**
```bash
docker run --rm -it \
  -v $(pwd)/results:/output \
  -v $(pwd)/targets.txt:/input/domains.txt:ro \
  metho \
  --domains-file /input/domains.txt \
  --skip-cloud --no-port-scan --auto
```

**Custom thread count and rate limit:**
```bash
docker run --rm -it -v $(pwd)/results:/output metho \
  --domains "example.com" --threads 100 --rate-limit 200 --auto
```

**With cloud enum keywords (for bucket brute forcing):**
```bash
docker run --rm -it \
  -v $(pwd)/results:/output \
  -v $(pwd)/targets.txt:/input/domains.txt:ro \
  metho \
  --domains-file /input/domains.txt \
  --cloud-enum-keywords "example,examplecorp,example-corp" \
  --auto
```

### Per-tool timeouts

Some tools (gospider, subdomainizer, amass, shuffledns, dnsx, katana,
cloud_enum) can stall on misbehaving hosts. Each one has a configurable
wall-clock cap that prevents a single bad host from blocking the whole
pipeline. Set the env var when you run the container:

| Variable                 | Default | Tool / What it bounds                                            |
|--------------------------|---------|------------------------------------------------------------------|
| `SHUFFLEDNS_TIMEOUT`     | `900`   | ShuffleDNS brute force (per root domain)                         |
| `GOSPIDER_TIMEOUT`       | `600`   | GoSpider crawl (per live host)                                   |
| `SUBDOMAINIZER_TIMEOUT`  | `300`   | SubDomainizer JS scan (per live host)                            |
| `AMASS_TIMEOUT`          | `1800`  | Amass enum (per root domain, Phase 2 cloud)                      |
| `DNSX_TIMEOUT`           | `600`   | DNSx bulk resolution (per Phase 2 / Phase 3 call)                |
| `CLOUD_ENUM_TIMEOUT`     | `1800`  | Cloud_Enum keyword mutation (single call per Phase 2 run)        |
| `KATANA_CRAWL_DURATION`  | `30m`   | Katana per-host wall-clock cap (uses Katana's `-ct` flag, s/m/h) |
| `CEWL_TIMEOUT`           | `600`   | CeWL word-crawl (per live host)                                  |
| `GAU_TIMEOUT`            | `300`   | GAU fetch (per root domain) -- archives can stall on some targets |
| `CEWL_DEPTH`             | `2`     | CeWL spider depth on the first pass (retries at depth 1 on failure) |
| `CEWL_MEM_LIMIT_MB`      | `1024`  | CeWL per-process address-space cap (`ulimit -v`, in MB) — stops CeWL from being OOM-killed on huge sites; on hitting the cap CeWL exits cleanly and the host is retried at depth 1 |

```bash
docker run --rm -it \
  -v $(pwd)/results:/output \
  -e GOSPIDER_TIMEOUT=900 \
  -e AMASS_TIMEOUT=2700 \
  -e KATANA_CRAWL_DURATION=15m \
  -e CEWL_MEM_LIMIT_MB=1536 \
  metho --domains "example.com" --parallel-hosts 8 --auto
```

### Parallel host crawling

The per-host stages (CeWL, GoSpider, SubDomainizer in Phase 1; Amass and
Katana in Phase 2) crawl their host/domain lists **in parallel** instead of
one at a time. These stages are where the pipeline spends the vast majority
of its wall-clock (a serial crawl of ~60 live hosts took ~3h45m of a ~4h run;
parallelizing ~5x drops that to ~45m). Control the pool size:

```
--parallel-hosts N      Hosts crawled concurrently per per-host tool (default: 5)
```

Each host still runs the same tool with the same flags into its **own** temp
file, merged after the pool finishes -- so there is no data loss and no
shared-file contention. The pool is bounded on purpose: N concurrent hosts,
each already using the tool's internal concurrency, multiplies the request
rate, so keep N modest to avoid tripping the target's WAF/rate-limiter.
Lower it (`--parallel-hosts 2`) for aggressive CDN/WAF targets; raise it
(`--parallel-hosts 10`) on a beefy machine against a tolerant target.

> **Memory note:** CeWL holds its crawl in RAM under a per-process `ulimit -v`
> cap (`CEWL_MEM_LIMIT_MB`, default 1024 MB). With `--parallel-hosts 5` that is
> up to ~5 GB of CeWL address space reserved at once -- fine on most machines,
> but lower either knob if memory is tight.

**Why the CeWL knobs exist:** CeWL holds the spider frontier and all
collected words in RAM and has no built-in page/memory limit, so a `-d 2`
crawl of a large docs/library site can be SIGKILLed by the kernel OOM
killer (observed in real runs). The memory cap turns that into a clean,
catchable failure, and the depth-1 retry still collects that host's words
— breadth across all live hosts is preserved without unbounded RAM use.

### Resolvers

The pipeline uses a single resolvers file: `wordlists/resolvers.txt`,
which is the **31-entry `resolvers-trusted.txt` from
[trickest/resolvers](https://github.com/trickest/resolvers/blob/main/resolvers-trusted.txt)**
(it contains vetted public resolvers from Cloudflare, Google, Quad9,
OpenDNS, CleanBrowsing, Comodo, Yandex, SafeDNS, Verisign, Dyn, and
others — the same resolver pool massdns/ShuffleDNS/Amass/dnsx expect).

The file is mounted into the container at
`/opt/scripts/wordlists/resolvers.txt` and is passed to:

- **ShuffleDNS** via `-r resolvers.txt` (the only required consumer
  — massdns needs a resolvers list to do its work at all)
- **Amass** via `-trf resolvers.txt` (trusted-resolver file; passive mode
  doesn't actually query DNS, but `-trf` keeps the resolver set consistent
  if Amass ever falls back to active methods)
- **DNSx** via `-r resolvers.txt` (ProjectDiscovery's dnsx accepts a
  resolvers file or comma-separated list at the same `-r` flag)
- **Cloud_Enum** via `-nsf resolvers.txt` (mirrors Ars0n v2's
  default; without it, Cloud_Enum uses its own bundled resolvers
  which are smaller)

### Checkpoints

When running without `--auto`, the pipeline pauses after each phase and shows:

```
════════════════════════════════════════════════════════════
[CHECKPOINT] Phase 1 complete. Subdomains discovered for 3 domain(s).
════════════════════════════════════════════════════════════

  [C]ontinue  [S]kip next phase  [Q]uit  [R]eview results
  > _
```

- **C** — Continue to the next phase
- **S** — Skip the next phase
- **Q** — Quit the pipeline
- **R** — Review the output files before continuing

If you don't respond within the timeout (default 30 seconds), it auto-continues.

---

## Output Structure

Mount a local directory as `/output`. After the pipeline completes, it looks like this:

```
results/
├── RECON_SUMMARY.txt              # Final summary with all counts
├── recon.log                      # Timestamped log of all stages
├── root_domains.txt               # Resolved input root domains
│
├── phase1/
│   ├── example.com/
│   │   ├── all_subdomains_final.txt      # All subdomains discovered
│   │   ├── live_subdomains_final.txt     # Live web server URLs
│   │   ├── httpx_results_final.json      # Full HTTPx metadata (JSON)
│   │   ├── httpx_results_final.httpx.log # Full HTTPx stderr log (for debugging)
│   │   ├── cero_results.txt              # Cero (cert transparency) results
│   │   ├── subfinder_results.txt         # Subfinder results
│   │   ├── sublist3r_results.txt         # Sublist3r subdomains (captured despite engine errors)
│   │   ├── sublist3r_full_output.txt     # Sublist3r complete raw output
│   │   ├── github_subdomains_results.txt # GitHub subdomains
│   │   └── ...
│   ├── example.org/
│   │   └── ...
│   └── ...
│
├── phase2/
│   ├── final_cloud_assets.txt     # All cloud assets consolidated
│   ├── amass_cloud_domains.txt
│   ├── dnsx_cloud_domains.txt
│   ├── cloud_enum_assets.txt
│   ├── katana_cloud_assets.txt
│   └── ...
│
├── phase3/
│   ├── all_ips.txt                # All resolved IPs
│   ├── asn_list.txt               # All ASNs
│   ├── asn_summary.txt            # ASNs sorted by IP count (descending)
│   ├── network_ranges.txt         # CIDR blocks from ASNs
│   ├── cdn_ips.txt                # CDN-associated IPs
│   ├── non_cdn_ips.txt            # Non-CDN IPs
│   ├── ip_port_pairs.txt          # Open port scan results
│   ├── domain_ip_map.txt          # Domain → IP mapping
│   └── ip_asn_map.txt             # IP → ASN mapping
│
└── final/
    ├── final_all_domains.txt          # Every subdomain across all root domains
    ├── final_live_web_servers.txt     # Every live URL across all root domains
    ├── final_httpx_metadata.json      # Full httpx JSON output (tech, title, status)
    ├── final_cloud_assets.txt         # Every cloud asset
    ├── final_asn_list.txt             # All ASNs
    ├── final_asn_summary.txt          # ASNs sorted by occurrence count
    ├── final_network_ranges.txt       # All network ranges
    ├── final_ip_addresses.txt         # All IPs
    ├── final_ip_port_pairs.txt        # IP:port from non-CDN scan
    ├── final_cdn_ips.txt              # CDN IPs
    ├── final_non_cdn_ips.txt          # Non-CDN IPs
    └── final_domain_ip_map.txt        # Domain→IP mapping
```

### The `final/` Directory

This is the one you care about. It contains deduplicated, consolidated lists ready for the next stage of your bug bounty workflow.

Key files:
- **`final_asn_summary.txt`** — ASNs sorted by how many IPs map to them. ASNs with only 1-2 IPs are more interesting targets (less infrastructure, more likely misconfigured).
- **`final_httpx_metadata.json`** — Full HTTPx output with status codes, titles, tech detection, TLS info for every live web server.
- **`final_ip_port_pairs.txt`** — Open ports on non-CDN IPs, ready for vulnerability scanning.

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
- Cloud Assets:       23
- ASNs:               15
- Network Ranges:     28
- IP Addresses:       456
- IP:Port Pairs:      1,102

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

### Installed Tools

Every tool listed below is wired into the pipeline (see `lib/phase1.sh`,
`lib/phase2.sh`, `lib/phase3.sh`). Optional tools are skipped cleanly when
not configured.

#### Subdomain Discovery — Phase 1

| Tool | Repo | Role |
|------|------|------|
| **Cero** | [glebarez/cero](https://github.com/glebarez/cero) | TLS certificate transparency scraper |
| **Subfinder** | [projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder) | Passive subdomain enumeration across 30+ OSINT sources |
| **Assetfinder** | [tomnomnom/assetfinder](https://github.com/tomnomnom/assetfinder) | Find subdomains via web crawling and OSINT |
| **GAU** | [lc/gau](https://github.com/lc/gau) | Fetch known URLs from Wayback, CommonCrawl, OTX, URLScan |
| **Sublist3r** | [aboul3la/Sublist3r](https://github.com/aboul3la/Sublist3r) | Multi-engine subdomain brute-forcer |
| **github-subdomains** | [gwen001/github-subdomains](https://github.com/gwen001/github-subdomains) | Find subdomains mentioned in GitHub code (requires `--github-tokens-file`) |
| **CeWL** | [digininja/CeWL](https://github.com/digininja/CeWL) | Spider live web servers → custom wordlist for DNS brute force |
| **ShuffleDNS** | [projectdiscovery/shuffledns](https://github.com/projectdiscovery/shuffledns) | Active DNS brute force using the CeWL-derived wordlist |
| **massdns** | [blechschmidt/massdns](https://github.com/blechschmidt/massdns) | High-performance DNS resolver used by ShuffleDNS (compiled from source) |
| **GoSpider** | [jaeles-project/gospider](https://github.com/jaeles-project/gospider) | Web crawler — finds links, JS endpoints, and archived URLs |
| **Subdomainizer** | [nsonaniya2010/SubDomainizer](https://github.com/nsonaniya2010/SubDomainizer) | Extract subdomains and secrets from JavaScript files |
| **httpx** | [projectdiscovery/httpx](https://github.com/projectdiscovery/httpx) | Probe HTTP/HTTPS servers (3 rounds: scrape → brute → crawl) |

#### Cloud Asset Discovery — Phase 2

| Tool | Repo | Role |
|------|------|------|
| **Amass** | [owasp-amass/amass](https://github.com/owasp-amass/amass) | Passive subdomain enumeration focused on cloud infrastructure |
| **dnsx** | [projectdiscovery/dnsx](https://github.com/projectdiscovery/dnsx) | Bulk DNS queries for A/AAAA/CNAME/MX/NS/TXT/PTR/SRV records → cloud chain discovery |
| **Cloud_Enum** | [initstring/cloud_enum](https://github.com/initstring/cloud_enum) | AWS / Azure / GCP bucket and service brute force |
| **Katana** | [projectdiscovery/katana](https://github.com/projectdiscovery/katana) | Modern web crawler for JS-heavy sites — finds cloud-hosted endpoints |

#### IP / ASN / Port Scan — Phase 3

| Tool | Repo | Role |
|------|------|------|
| **nmap** | [nmap/nmap](https://github.com/nmap/nmap) | Port scanning of discovered IPs (skippable via `--no-port-scan`) |

#### HTTP Helpers

| Tool | Repo | Role |
|------|------|------|
| **curl / wget** | — | Used by recon.sh and the various scrapers for direct HTTP fetches |
| **jq** | — | Parses JSONL output from httpx, dnsx, etc. |
| **whois / host / dig** | — | DNS / ASN / ownership lookups |

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
│  │ Subdomain │  │ Cloud     │  │ IP/ASN    │              │
│  │ Discovery │  │ Assets    │  │ Port Scan │              │
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
│  lib/utils.sh — logging (stdout + recon.log), CLI,       │
│                 checkpoints, httpx, CDN ASN detection     │
└──────────────────────────────────────────────────────────┘
```

---

## Tips

- **Rate limiting matters.** If you're getting timeouts or empty results, lower `--rate-limit` (e.g., 50 or 25).
- **ASN occurrence matters.** In `final_asn_summary.txt`, ASNs with fewer IPs are more interesting — they may represent niche hosting or forgotten infrastructure.
- **GitHub tokens increase coverage.** Without `--github-tokens-file`, the github-subdomains stage is skipped.
- **Cloud enum keywords.** By default, the base name of each root domain is used as a keyword. Use `--cloud-enum-keywords` to add extra keywords.
- **Check recon.log.** The timestamped log file captures everything — useful for debugging or tuning the pipeline.
- **Do manual recon first.** Google dorking and reverse WHOIS can find additional root domains. Add them to your input file before running the pipeline.

---
