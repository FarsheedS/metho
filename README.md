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

Resolves any still-pending hostnames from the canonical DNS dataset, performs deterministic IP classification, and port scans non-CDN, non-cloud IPs (see the port-scan notes for why cloud is excluded by default).

| Stage | What Happens | Tool(s) |
|-------|-------------|---------|
| 1 | Extract IPs from canonical DNS dataset (pending hosts resolved first, then unresolved hosts labelled `nxdomain`) | dnsx |
| 1b | Reverse DNS (PTR) lookups on resolved IPs → new in-scope hostnames | dnsx |
| 2 | IP → ASN lookup via whois.cymru.com, falling back to Team Cymru's DNS service. Both failing skips Stage 4 rather than scanning unclassified IPs | nc, dnsx |
| 3 | Deterministic IP classification (CDN/cloud/dedicated/unknown) | Built-in classification engine |
| 4 | Fast port scan (naabu, top `NAABU_TOP_PORTS` ports) then service detection (nmap -sV on hosts naabu found open, capped to the top `--nmap-top-ports` most-common ports) — skipped with `--no-port-scan` | naabu, nmap |
| 5 | HTTP probe of hostnames that resolved after Phase 1 (Phase 2/3 resolution) into `phase3/live_hosts_late.txt` | httpx |

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
| `resolution_status` | `resolved`, `cname_only`, `nxdomain`, `timeout`, `bogon`, or `pending` |

The status vocabulary distinguishes *"this name does not exist"* from *"we could not ask"*, which matters most exactly when a run goes badly:

| Status | Meaning | Retried? |
|--------|---------|----------|
| `resolved` | Answered with **at least one A or AAAA address** | — |
| `cname_only` | Answered with a CNAME but no address | No — settled |
| `nxdomain` | The resolver authoritatively says the name does not exist | No — settled, nothing was lost |
| `timeout` | No answer of the requested types, and not confirmed NXDOMAIN | Yes, while the transport is healthy |
| `bogon` | Resolved, but every address was reserved/private — excluded from port scanning, and from HTTP probing unless `METHO_PROBE_RESERVED=1` | No |
| `pending` | Not yet queried | Always |

**`resolved` means there is an address to connect to.** A CNAME with no address used to be recorded as `resolved`, which put 1,678 hostnames — 13.7% of everything handed to httpx — into the probe set carrying an empty address column. An independent 40-name sample of that set found ~80% NXDOMAIN elsewhere and ~18% pointing at a CNAME target that no longer resolves. Those are two different findings and neither is `resolved`: one is probe time burned on a host that cannot answer, the other is a dangling CNAME, i.e. a subdomain-takeover candidate that belongs in a report rather than a probe list. `cname_only` holds them out of the probe set and keeps them visible — see `phase1/<domain>/canonical_dns.tsv` and the per-run count in the log.

`nxdomain` is confirmed by a pass (`dnsx -rcode nxdomain`) over the hosts still marked `timeout`. Without it a corpus that is 90% unresolved cannot be diagnosed: a run that lost 12,000 live hostnames to a broken transport produces exactly the same output as one whose corpus was genuinely 90% dead.

**That pass runs in Phase 1, immediately after the first resolution round** — before any `include_timeouts` retry. It previously ran only at the top of Phase 3, so Phase 1 Stage 7 and Phase 3 Stage 1 each re-ground the whole timeout pile first. On a measured pile (240-host sample of a real run): 84% NXDOMAIN, 10% SERVFAIL, 5% NODATA. Settling first turns a ~16,000-host retry set into ~1,700 and makes each dead name cost **one** query instead of three or four. It stays conservative — only a positively confirmed NXDOMAIN is promoted, SERVFAIL and every other unconfirmed case keep the `timeout` label — so nothing is written off on a guess.

Re-discovery does **not** re-open a settled row. CT logs are historical, so the same dead names reappear on every run and resetting them would re-grind the entire pile, undoing the saving above. Set `METHO_NXDOMAIN_RECHECK=1` to re-open `nxdomain`, `bogon` and `cname_only` rows anyway, for when a name is genuinely expected to have come back (a decommissioned hostname reused for a new service, or a dangling CNAME whose target has been re-registered — the settled state most likely to change).

When addresses are stripped, the hostname, the address and the matched range are written to `canonical_dns.tsv.bogon` next to the dataset, **appended across every resolution pass and reset once per dataset**. A bogon count with no evidence behind it cannot be audited: the earlier version erased the address *and* left no trace, so determining whether a "bogon" was an RFC1918 leak, a CGNAT name or a fake-IP VPN artefact meant re-resolving the hosts by hand. The log was then truncated on every pass (both by an `rm -f` and by awk's `>` redirect, which truncates on the first write of each invocation), so it only ever held the last pass's strips — on a real run the global file listed 11 hosts against 514 bogon rows, and the same run contradicted itself, reporting "198.18.0.0/15 IS present — fake-IP VPN" in one pass and "No 198.18.0.0/15 present" in the next, because the evidence had been erased in between.

Note the far more common cause is a public DNS record that legitimately points into RFC1918/CGNAT — internal names leaked into Certificate Transparency logs — which no resolver setting will change. `198.18.0.0/15` (RFC 2544) *can* be a fake-IP VPN signature, but its presence alone proves nothing: a VPN can only substitute an answer it is on the path of, so the warning names a VPN only when the range is present **and** the answers came through the system resolver rather than DoH. Verified on a real run — 56 internal-looking names returned `198.18.x` addresses from a public DoH endpoint, i.e. genuine published records for a carrier-internal range, not injection.

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
  --resolvers FILE|URL      DNS resolver list (file path or http(s) URL). The built-in list
                            (~12.7K validated trickest resolvers) is used as-is with no
                            health-check — dnsx retries across the pool, so dead entries in a
                            large list cost little. A custom list IS health-checked at startup;
                            only resolvers answering from this network are kept. Overrides
                            --dns-mode.
  --dns-mode {udp,doh}      doh (default): DNS-over-HTTPS on TCP/443 through a local proxy
                            (lib/doh_proxy.py). The proxy probes Cloudflare 1.1.1.1, Google
                            8.8.8.8 and Quad9 9.9.9.9 at startup and uses only the ones this
                            network can actually reach — a filtered endpoint is demoted
                            instead of swallowing a share of every batch.
                            udp: raw UDP/53 against the ~12.7K static pool.
                            Either way, a batch whose queries stop being answered is retried
                            through the other transport before any result is recorded.
  --asn-config FILE         Path to ASN provider classification config (default: built-in)
  --waymore-mode MODE       Waymore mode: U (URLs, default) or B (URLs+responses). R
                            (responses only) is not supported — the pipeline consumes URL output
  --auto                    Skip all checkpoint prompts
  --skip-phase {1,2,3}      Skip specific phase(s) — value is validated
  --skip-cloud              Shorthand for --skip-phase 2
  --no-port-scan            Skip the port-scan stage inside Phase 3 (classification still runs)
  --skip-permutation        Disable dnsgen permutation brute force (Stage 4b) for all domains
                            (recommended for large multi-domain sweeps)
  --threads N               Cloud_Enum thread count (default: 50). dnsx concurrency is
                            transport-aware — see DNSX_THREADS_DOH / DNSX_THREADS_UDP
  --parallel-hosts N        Hosts crawled in parallel per per-host tool (default: 5)
  --parallel-domains N      Root domains processed in parallel in Phase 1 (default: 3)
  --doh-proxy-threads N     Concurrent DoH requests the local proxy may have in flight
                            (default: 128). Size it to at least
                            parallel-domains × DNSX_THREADS_DOH — see "Scaling to many
                            root domains"
  --rate-limit N            httpx requests/second (default: 100)
  --httpx-threads N         httpx threads per process (default: 150, hard maximum 200).
                            This — not --rate-limit — is what bounds probe throughput.
                            Values above the maximum are clamped and reported, never
                            honoured silently.
  --cewl-max-hosts N        Max live hosts CeWL may crawl for the brute-force wordlist
                            (default: 150; 0 = unlimited)
  --crawl-max-hosts N       Max live hosts Katana/SubDomainizer may crawl
                            (default: 300; 0 = unlimited)
  --probe-reserved          ALSO HTTP-probe hosts whose only addresses are
                            reserved/private (status 'bogon'). Unreachable from the
                            internet, but reachable if your network routes into the
                            target's private/CGNAT space. Never affects naabu/nmap.
  --nmap-top-ports N        Cap nmap -sV (Phase 3) to the N most-common open ports (default: 100; 0 = no cap)
  --timeout N               Checkpoint auto-continue timeout in seconds; 0 = wait forever (default: 30)
  --output DIR              Output directory (default: /output)
  --cloud-enum-keywords KW Keywords for cloud_enum brute force (comma-sep, auto-derived from domains)
```

> **Flag scope notes:** `--rate-limit` is the aggregate request budget against the targets and applies only to httpx (Waymore, Katana and the DNS tools use their own limits); `--threads` applies only to Cloud_Enum — dnsx concurrency is set by `DNSX_THREADS_DOH` / `DNSX_THREADS_UDP`.
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

### DNS transport tuning

| Variable | Default | What it controls |
|----------|---------|------------------|
| `DOH_ENDPOINTS` | `https://8.8.8.8/dns-query,https://8.8.4.4/dns-query,https://94.140.14.14/dns-query,https://94.140.15.15/dns-query,https://208.67.222.222/dns-query,https://208.67.220.220/dns-query,https://1.1.1.1/dns-query,https://9.9.9.9/dns-query` | DoH endpoints to try, all IP literals — resolving a DoH *hostname* would need the very resolver being replaced. The proxy probes them at startup and uses only the reachable ones. With the previous three-endpoint default, one heavily filtered network left exactly one usable endpoint, so the run had no failover at all; per-provider probe results are recorded in `lib/doh_proxy.py` |
| `DOH_PROXY_THREADS` | `128` | Concurrent DoH requests the proxy may have in flight |
| `DOH_PROXY_TIMEOUT` | `4` | Per-request HTTPS timeout in the proxy. This is per **endpoint attempt**, not per query — see `DOH_QUERY_BUDGET` for the bound that actually matters |
| `DOH_QUERY_BUDGET` | `12` | Total wall-clock one query may spend across **all** endpoints. Keep it below `DNSX_QUERY_TIMEOUT_DOH`, or dnsx abandons queries the proxy is still working on and records a `timeout` for a host that was about to be answered. Bounding the query rather than `DOH_PROXY_TIMEOUT` × endpoint count keeps that true however long `DOH_ENDPOINTS` gets |
| `DOH_PROXY_READY_SECS` | `30` | How long to wait for the proxy to bind and probe its endpoints |
| `DOH_PROXY_EXTRA_PORT` | `53` | A second, bare-IP UDP listener the proxy opens alongside its ephemeral port. cloud_enum's dnspython accepts bare IPs only and always dials UDP/53, so without this it leaves the DoH transport for the system resolver and sees a **different DNS view** from every other tool. Best-effort: 53 needs root (the container has it), and if the bind fails the proxy logs it and continues — consumers fall back to the old behaviour |
| `DOH_FAIL_THRESHOLD` | `3` | Consecutive failures before an endpoint is demoted |
| `DOH_COOLDOWN` | `60` | Seconds a demoted endpoint stays out of rotation |
| `DNSX_RETRY` | `2` | dnsx retry count for every resolution pass |
| `DNSX_THREADS` | unset | Pins dnsx concurrency for BOTH transports, overriding the per-transport defaults below |
| `DNSX_THREADS_DOH` | `64` | dnsx concurrency per invocation in `doh` mode |
| `DNSX_THREADS_UDP` | `100` | dnsx concurrency per invocation in `udp` mode |
| `DNSX_QUERY_TIMEOUT` | `5` | dnsx per-query timeout in `udp` mode |
| `DNSX_QUERY_TIMEOUT_DOH` | `15` | dnsx per-query timeout in `doh` mode. Must exceed the proxy's worst case (`DOH_PROXY_TIMEOUT` × number of endpoints), or dnsx abandons queries the proxy is still working on |
| `METHO_NXDOMAIN_LABEL` | `1` | Set to `0` to skip the Phase 3 NXDOMAIN-confirmation pass (saves one query round over the unresolved pile on very large runs, at the cost of leaving every unresolved host as `timeout`) |
| `DNS_MIN_ANSWER_PCT` | `50` | Below this share of *queries answered*, a batch is treated as a transport failure and retried through the fallback |
| `DNS_MIN_HEALTH_BATCH` | `20` | Batches smaller than this never change the DNS-health flag (in either direction) |

### Scaling to many root domains

Phase 1 is the only stage that fans out per root domain; Phases 2 and 3 and the
`results/` slicing all run once over the merged corpus. That keeps the work
linear in the number of roots rather than multiplicative, but it also means
three shared resources need to be sized against each other.

**How the concurrency stacks up**

| Layer | Default | Aggregate effect |
|-------|---------|------------------|
| `--parallel-domains` | `3` | Phase 1 workers, each running a whole per-domain pipeline |
| `--parallel-hosts` | `5` | Hosts crawled in parallel *within* each worker — so up to `3 × 5 = 15` concurrent crawls |
| `--httpx-threads` | `150` (max `200`) | httpx threads **per process**. The real throughput bound: throughput ≈ threads ÷ mean latency, so 50 threads against a corpus full of dead hosts measured 4.34 targets/s while the rate limit sat unused |
| `HTTPX_TIMEOUT_MAX` / `HTTPX_SECONDS_PER_TARGET` | `3600`s / `1` | Wall-clock ceiling for an httpx round, scaled per target. httpx was the last stage with **no cap at all**: Phase 1 bounds it indirectly through the per-domain watchdog, but Phase 3's late probe runs with no watchdog above it, so an unbounded round there could hang the whole run. A killed round keeps what it flushed and is recorded as partial |
| `--rate-limit` | `100`/s | **Aggregate** against the targets. Phase 1 divides it by the number of workers actually started, so 3 workers each use 33/s, not 100/s. Only binds once `--httpx-threads` is high enough to reach it |
| `--cewl-max-hosts` / `--crawl-max-hosts` | `150` / `300` | How many live hosts the wordlist and crawl stages may touch per domain. Uncapped they are linear in the live-host count and outlast the domain budget |
| `CRAWL_STAGE_TIMEOUT` | `1200`s | Wall-clock cap per crawl stage, independent of `--domain-timeout` |
| `NAABU_TIMEOUT_MAX` / `NAABU_TOTAL_TIMEOUT_MAX` | `3600`s / `4×` that | Per-chunk and whole-sweep ceilings. naabu's cost is linear in the candidate count, so Phase 3 sweeps the candidate list **in chunks** sized to fit the per-run cap rather than truncating one big run: 6,501 candidates need ~13,300s at the defaults, against a 3,600s cap |
| `NMAP_TIMEOUT_MAX` / `NMAP_SECONDS_PER_HOST` | `3600`s / `30` | Wall-clock ceiling for the `nmap -sV` pass, which had **no timeout at all**. Matters most on the fallback path (naabu found nothing, so every candidate goes to `-sV`). A killed nmap keeps what it wrote and is recorded as partial |
| `DNSX_THREADS_DOH` | `64` | dnsx threads *per worker*. All workers share one DoH proxy, so in-flight = `parallel-domains × 64` |
| `DOH_PROXY_THREADS` | `128` | Requests the proxy serves at once. Must be ≥ the in-flight figure above, or queries queue past `DNSX_QUERY_TIMEOUT_DOH` and get recorded as `timeout`. Startup now warns when `parallel-domains × DNSX_THREADS_DOH` exceeds it |

Those four numbers are the ones that interact. If you raise
`--parallel-domains`, raise `DOH_PROXY_THREADS` to match
(`parallel-domains × DNSX_THREADS_DOH`, with headroom) or lower
`DNSX_THREADS_DOH`.

**A 70-domain sweep**

```bash
docker run --rm -it \
  -v $(pwd)/results:/output \
  -v $(pwd)/targets.txt:/input/domains.txt:ro \
  metho --domains-file /input/domains.txt \
        --subfaster-config /input/provider-config.yaml \
        --parallel-domains 6 \
        --doh-proxy-threads 384 \
        --auto
```

- `--parallel-domains 6` with `DNSX_THREADS_DOH=64` means 384 DNS queries in
  flight, so `--doh-proxy-threads 384` matches the pool to the load.
- Watch `results/doh_proxy.log`: `dropped=0` and an error count near zero is
  what a correctly sized pool looks like. A growing `dropped` count means
  `DOH_PROXY_THREADS` is too low.
- `--domain-timeout` (default `5400`) caps any single pathological domain so it
  cannot gate the pool; a 70-domain sweep will hit this on the largest targets
  and keep going.
- Port scanning is one global phase. The candidate list is swept in **chunks**
  sized to fit `NAABU_TIMEOUT_MAX`, so a large target is covered rather than
  truncated; the knob that bounds the whole sweep is
  `NAABU_TOTAL_TIMEOUT_MAX` (default `4 × NAABU_TIMEOUT_MAX`), and the log
  reports the chunk count, the projection and any shortfall.
- Raise `--parallel-hosts` only with headroom in CPU/RAM: each host slot can be
  a CeWL, Katana or SubDomainizer process, and CeWL is memory-capped per
  process by `CEWL_MEM_LIMIT_MB` (default 1024MB) — 15 concurrent CeWL crawls
  can legitimately want 15GB.

### Per-tool timeouts

Some tools can stall on misbehaving hosts. Each one has a configurable wall-clock cap:

| Variable | Default | Tool / What it bounds |
|----------|---------|----------------------|
| `BRUTEFORCE_TIMEOUT` | `900` | dnsx brute force (per root domain) |
| `KATANA_TIMEOUT` | `600` | Hard per-host kill for a Katana crawl that ignores its own cap |
| `KATANA_CRAWL_DURATION` | `9m` | Katana's own per-host cap — it stops and flushes at this point. Keep it BELOW `KATANA_TIMEOUT`, or the process is killed mid-crawl and never stops gracefully |
| `SUBDOMAINIZER_TIMEOUT` | `300` | SubDomainizer JS scan (per live host) |
| `DNSX_TIMEOUT` | `600` | DNSx bulk resolution — floor value; the effective cap auto-scales with batch size (max of this and pending-hosts/50, capped at 3600s) so large corpora are never cut off mid-batch |
| `CLOUD_ENUM_TIMEOUT` | `900` | Cloud_Enum keyword mutation (single call per Phase 2 run) |
| `CEWL_TIMEOUT` | `600` | CeWL word-crawl (per live host) |
| `CEWL_DEPTH` | `2` | CeWL spider depth on first pass (retries at depth 1 on failure) |
| `CEWL_MEM_LIMIT_MB` | `1024` | CeWL per-process address-space cap (MB) |
| `WAYMORE_TIMEOUT` | `600` | Waymore historical recon (per root domain) |
| `GITHUB_SUBDOMAINS_TIMEOUT` | `300` | GitHub-subdomains code search (per root domain) |
| `DNSGEN_TIMEOUT` | `120` | dnsgen permutation generation |
| `DNSGEN_MAX_INPUT` | `500` | Max subdomains fed to dnsgen (resolved hosts prioritized; 0 disables) |
| `DNSGEN_SKIP_THRESHOLD` | `100` | Domains with more discovered subs than this skip dnsgen entirely (large targets: ~0 yield, hours of DNS; 0 disables) |
| `DNSGEN_MAX_OUTPUT_BYTES` | `26214400` | Hard cap on dnsgen permutation output size (25MB) |
| `NAABU_TIMEOUT` | `0` (derived) | Naabu fast port scan, per chunk. `0` derives the cap from the chunk's host count (`NAABU_TIMEOUT_BASE + hosts × NAABU_SECONDS_PER_HOST`, max `NAABU_TIMEOUT_MAX`); any positive value pins it |
| `NAABU_TIMEOUT_BASE` | `300` | Fixed part of the derived naabu cap |
| `NAABU_SECONDS_PER_HOST` | `1` | Per-host part of the derived naabu cap. Conservative on purpose — it sets the chunk size, where under-estimating is unsafe. Recalibrate if `NAABU_TOP_PORTS`/`NAABU_RATE` change: the realistic cost is `ports ÷ rate × (1 + retries)` |
| `NAABU_TIMEOUT_MAX` | `1200` | Ceiling on the per-chunk cap, and therefore the chunk size (`(cap − base) ÷ per-host` hosts per chunk). Also the worst case for ONE hung chunk. Being reached is the normal case on a large target, not a truncation — the sweep continues in the next chunk. The knob that bounds the whole sweep is `NAABU_TOTAL_TIMEOUT_MAX` |
| `NAABU_TOP_PORTS` | `100` | Naabu top-N ports to scan. The dominant term in both the sweep's cost and its exposure: at 1,000 ports a 6,501-host sweep is ~6.5M SYNs (~1.8h of continuous SYN from one IP); at 100 it is ~650k (~11 min). Top-100 covers essentially every service that matters for recon |
| `CYMRU_WHOIS_ATTEMPTS` | `3` | Retries of the `whois.cymru.com:43` ASN lookup before falling back to the DNS service |
| `CYMRU_WHOIS_TIMEOUT` | `60` | Wall-clock cap on each `whois.cymru.com:43` bulk attempt |
| `NAABU_RATE` | `1000` | Naabu packets/sec cap (noise/IPS throttle) |
| `NAABU_RETRIES` | `2` | Naabu SYN retransmit count |
| `NMAP_INCLUDE_CLOUD` | `0` | Whether cloud-classified IPs are port-scanned. Off by default: on a real run every host answering on more than 5 ports was a Google Cloud address, and they contributed 226 of the 247 ports found — GCP front-end artefacts that dominated the sweep and filled the `-sV` port union. Dropping cloud halves the candidate list; it does NOT reduce the HTTP surface (httpx results are unchanged). Set to `1` when the target self-hosts on cloud VMs |
| `NMAP_MIN_PORT_HOSTS` | `2` | How many hosts a port must have been seen open on before `-sV` spends time on it. The `-sV` port list is global, so a port seen on one odd host gets probed across the whole estate. Well-known ports (`<1024`) bypass the floor. `1` disables it |
| `NMAP_TIMEOUT_MAX` / `NMAP_SECONDS_PER_HOST` | `3600`s / `30` | Wall-clock ceiling for the `nmap -sV` pass, scaled per host |
| `NMAP_TOP_PORTS` | `100` | Cap on how many ports `-sV` service-detects (see `--nmap-top-ports`) |
| `METHO_PROBE_RESERVED` | `0` | Whether `bogon` hosts (every address reserved/private) are HTTP-probed. Off by default: on a network that does not route into that space each costs an httpx timeout, and the address may reach something unrelated to the target. On a real run 549 hosts were in this bucket and **2 were live** — internal OpenSearch clusters answering 200 from `100.64.x`. HTTP only: `bogon` hosts are never port-scanned either way |

```bash
docker run --rm -it \
  -v $(pwd)/results:/output \
  -e KATANA_TIMEOUT=900 \
  -e KATANA_CRAWL_DURATION=14m \
  -e WAYMORE_TIMEOUT=2700 \
  -e CEWL_MEM_LIMIT_MB=1536 \
  metho --domains "example.com" --parallel-hosts 8 --parallel-domains 5 \
        --doh-proxy-threads 320 --auto
```

`KATANA_CRAWL_DURATION` is raised alongside `KATANA_TIMEOUT` because katana's
own cap must stay below the hard kill. `--doh-proxy-threads` is sized to
`parallel-domains × DNSX_THREADS_DOH` (5 × 64).

---

## Output Structure

Mount a local directory as `/output`. After the pipeline completes, it looks like this:

```
results/
├── RECON_SUMMARY.txt              # Final summary with all counts
├── recon.log                      # Timestamped log of all stages
├── canonical_dns.tsv              # Canonical hostname→DNS dataset
├── httpx_metadata.tsv             # HTTPX CDN/tech/webserver metadata per host
├── httpx_probed.txt               # Every hostname ever handed to httpx (responders AND silent hosts)
├── stage_truncations.txt          # Any stage or domain that did NOT finish — empty means a complete run
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
    ├── final_ip_addresses.txt             # All IPv4 addresses
    ├── final_ip_addresses_v6.txt          # All IPv6 addresses (inventory only — not port-scanned)
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
- **`final_nmap_candidates.txt`** — IPs that were actually port-scanned (excludes CDN IPs, and cloud IPs by default — see `NMAP_INCLUDE_CLOUD`).
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

## Incomplete runs are reported, not hidden

Several things can stop a stage early: the per-domain wall-clock watchdog, a
crawl stage reaching its host cap or its stage budget, or the naabu sweep
running out of its total budget. Each of those leaves a domain **partially
covered**, and every one of them used to be a single `[!]` line lost in the log
while the pipeline went on to print `Recon pipeline complete!`.

Every such event is now appended to `stage_truncations.txt` in the output root,
and the run ends with an error block naming each affected domain and stage:

```
════════════════════════════════════════════════════════════════
  RUN INCOMPLETE — 1 truncation(s) recorded
════════════════════════════════════════════════════════════════
  vodafone.com: domain-watchdog — killed at 5400s
  Results for those domains are LOWER BOUNDS, not coverage.
════════════════════════════════════════════════════════════════
```

`stage_truncations.txt` and `httpx_probed.txt` are cleared at startup, so a
re-run into the same output directory starts clean. Both are per-run state that
either accumulates or is merged into: a leftover truncation record would make a
clean run report itself incomplete, and a leftover probe ledger would make
Phase 3 skip hosts the new run never probed.

**An absent or empty `stage_truncations.txt` is what "complete" means.** If it
is non-empty, every count in `RECON_SUMMARY.txt` for the domains it names is a
floor. The per-host detail is kept next to the stage that stopped: partial
crawl output stays in `phase1/<domain>/katana/` and `subdomainizer/`, and the
naabu sweep records which hosts it completed in
`phase3/naabu_scanned_hosts.txt` — a lower bound, since a chunk killed at its
cap is deliberately not counted as reached.

To get full coverage instead of a truncation, raise the limit rather than
re-running blind: `--domain-timeout` for the watchdog, `--cewl-max-hosts` /
`--crawl-max-hosts` / `CRAWL_STAGE_TIMEOUT` for the crawlers, and
`NAABU_TOTAL_TIMEOUT_MAX` for the port sweep.

## Troubleshooting DNS

**Most of the corpus is `timeout`.** Check `nxdomain` before concluding anything was lost. `nxdomain` means the resolver authoritatively answered that the name does not exist — a Certificate-Transparency corpus is routinely half dead, and that is not a failure. A large `timeout` pile with a *healthy* transport means the same thing, less conclusively. Only a **large `timeout` pile plus a transport that stopped answering** indicates loss, and the run log says which it was:

```
DNS health: transport 'doh' blackholed 1/28901 hosts — below the 50% ceiling, so the transport is answering; timeout retries enabled
  12450/28901 of this batch returned an address or CNAME; the rest are negatives (NXDOMAIN/SERVFAIL), which the label pass below separates
DNS health: transport 'doh' blackholed 28601/28901 hosts — above the 50% ceiling; DNS UNHEALTHY, timeout retries disabled
```

Note the two numbers answer two different questions. The **blackhole** count is
`hosts dnsx reported as failing every attempt` — it detects a dead transport. The
**record** count is how many names actually came back with an address or CNAME.
A transport that answers everything with SERVFAIL scores 100% healthy on the
first number and 0% on the second, which is why both are printed: previously
only the first existed and was labelled "queries answered", so a run whose pile
was a dead *corpus* read like a run whose *transport* was fine without saying
so.

To settle a specific pile by hand, count how many of its hostnames actually exist:

```bash
awk -F'\t' '$7=="timeout"{print $1}' results/canonical_dns.tsv | head -200 > /tmp/sample.txt
docker run --rm -i -v /tmp:/t metho sh -c \
  'dnsx -silent -a -rcode noerror -r 1.1.1.1 -l /t/sample.txt | wc -l'
```

If that returns a large number, the run under-resolved and the data is still recoverable — the hostnames are all in `canonical_dns.tsv`; re-running Phase 3 re-resolves them without repeating discovery.

**Which transport is actually working here?** The DoH proxy prints its endpoint probe at startup, and every proxy query is counted:

```bash
cat results/doh_proxy.log
# [doh-proxy] endpoint probe: 6/8 reachable — https://8.8.8.8/dns-query, https://8.8.4.4/dns-query, ...
# [doh-proxy] queries=12168 answered=12168 dropped=0  errors=ReadTimeout×72
```

`dropped` or a high error count means endpoints are being filtered or throttled. `answered` well below `queries` is the failure signature; add endpoints via `DOH_ENDPOINTS`, or switch to `--dns-mode udp`.

**Everything resolved to a reserved range.** The hostname, the address and the matched range are written to `canonical_dns.tsv.bogon`, and those hosts are marked `bogon` and excluded from probing and scanning rather than poisoning the results. Two causes, and the file tells them apart:

* **`198.18.0.0/15` (RFC 2544 benchmark space)** is the fake-IP signature — a VPN in fake-ip mode (Clash/mihomo/Surge) or a split-DNS resolver answering every name. You are seeing a filtered view of the target: run without the VPN, or disable fake-IP mode for the Docker network.
* **`10.x`, `172.16–31.x`, `192.168.x`, `100.64–127.x` (CGNAT)** are almost always genuine records — a public DNS zone that deliberately points at internal addresses, usually because those names leaked into Certificate Transparency logs. No resolver or Docker setting will change that, and the hosts are not reachable from outside. Keep them as intel, not as scan targets.

The warning only names a VPN when `198.18.0.0/15` is actually present. An earlier version asserted it unconditionally, which sent operators to check their Docker DNS for a problem that was not there.

**Port scanning was skipped.** The log will say `ASN classification unavailable`. Both ASN transports (`whois.cymru.com:43` and Team Cymru's DNS service) failed, which means every IP would classify as `unknown` and the CDN/cloud exclusion would not work. The pipeline refuses to aim a port scan at IPs it cannot scope — DNS, HTTP and cloud results are unaffected.

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

- **DNS resolvers and transport.** Resolution defaults to **DNS-over-HTTPS on TCP/443** (`--dns-mode doh`), which is what works in practice. Raw UDP/53 against a large public resolver pool is the fragile option: the shipped ~12.7K trickest list answered only ~74% of a known-good sample here, and on a real 29K-hostname run the whole transport collapsed after a bulk burst — the run wrote off ~12,000 hostnames that exist and resolve fine, and reported zero live web servers for one target while ~75 of the hosts it *had* resolved were answering HTTP.
  - **Why a local proxy rather than dnsx's built-in DoH.** dnsx v1.3.1 cannot complete a DoH query at all: `doh:https://…` fails with `Post "https://…/dns-query": EOF`, and `dot:`/`tcp:` return zero results, on networks where `curl` and Python POST the identical request to the identical endpoint and get HTTP 200. The resolver string format is correct (retryabledns' `parseResolver()` documents exactly that form) — the client is broken. `lib/doh_proxy.py` therefore speaks DoH itself and hands dnsx a plain `127.0.0.1:PORT` resolver, so wildcard detection, rcode filtering, record-type queries and PTR all keep working unchanged.
  - **Endpoint selection.** The proxy probes all three endpoints at startup and uses only those that answer — on a network that permits 1.1.1.1 but black-holes 8.8.8.8 and 9.9.9.9 on TCP/443, blind round-robin sends a third of every batch into the hole. A failing endpoint is demoted automatically and retried after a cooldown.
  - **Fallback.** If the proxy cannot start, or TCP/443 is filtered so no endpoint answers, the run falls back to the UDP pool automatically. Individual batches are also re-tried through the other transport when their answer rate collapses — the check is on *queries answered*, not *names resolved*, because a Certificate-Transparency corpus is legitimately about half NXDOMAIN and a resolve-rate gate misreads that as failure.
  - For full control, pass your own list via `--resolvers FILE|URL` (custom lists are health-checked first; an all-dead list falls back to the system resolver). `--dns-mode udp` pins the old behaviour.
- **cloud_enum and DoH.** cloud_enum cannot read a `HOST:PORT` resolver, so in DoH mode it previously fell back to the system resolver and resolved bucket names through a different DNS view than the rest of the run. The proxy now also listens on `127.0.0.1:53` (`DOH_PROXY_EXTRA_PORT`), and cloud_enum is handed that, so its checks use the same transport as everything else. If the extra bind is unavailable the log says so and the old fallback applies.

- **Rate limiting matters.** If httpx is getting timeouts or empty results, lower `--rate-limit` (e.g., 50 or 25) — note this flag affects httpx only.
- **ASN occurrence matters.** In `final_asn_summary.txt`, ASNs with fewer IPs are more interesting — they may represent niche hosting or forgotten infrastructure.
- **Cloud enum keywords.** By default, the base name of each root domain is used as a keyword. Use `--cloud-enum-keywords` to add extra keywords.
- **Check canonical_dns.tsv.** The canonical DNS dataset tracks every hostname, its resolution status, and which tools discovered it. Useful for debugging and understanding coverage gaps.
- **IP classification is configurable.** Edit `config/asn_providers.sh` to add or remove CDN, cloud, and dedicated hosting providers and ASNs.
- **Waymore modes.** Mode `U` (URLs only, default) is fast and sufficient for subdomain discovery — the pipeline extracts subdomains from the URL output. Mode `B` also downloads archived response bodies (slower, richer data, but the pipeline does not currently parse them). Mode `R` (responses without the URL file) is not supported.
- **GitHub subdomain discovery.** Set the `GITHUB_TOKEN` environment variable (comma-separated for multiple tokens) or include GitHub tokens in the subfaster provider-config. The pipeline searches GitHub code for references to each target domain.
- **Subdomain permutation.** After brute force, dnsgen generates permutations from discovered subdomain patterns (e.g. `dev` → `dev1`, `dev-internal`, `dev-staging`) and resolves them. This finds subdomains that follow the target's naming conventions but appear in no passive source.
- **Reverse DNS.** Phase 3 performs PTR lookups on all resolved IPs, which can reveal hostnames not discovered by any subdomain enumeration tool.
- **Two-phase port scanning.** Naabu fast-scans the top `NAABU_TOP_PORTS` (100 by default) ports on all non-CDN, non-cloud candidates, then nmap runs service/version detection (`-sV`) on only the hosts naabu found open — the hosts with nothing open skip the expensive -sV pass entirely, and the fallback fixed-port list covers the rare case where naabu is unavailable or finds nothing.
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