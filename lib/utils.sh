#!/usr/bin/env bash
# Shared utility functions for the Metho recon pipeline.

# ── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ── Logging ─────────────────────────────────────────────────────────────────
LOG_FILE=""

init_log() {
    LOG_FILE="${OUTPUT_DIR}/recon.log"
    : > "$LOG_FILE"
    log_info "Log file: $LOG_FILE"
}

_log_ts() { date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo '?'; }

# Unix-seconds timestamp. Used by phase stages to log wall-clock
# duration without spawning `date` repeatedly. Falls back to the
# timestamp helper if epoch isn't available (e.g. some BSD variants).
_now() { date +%s 2>/dev/null || date '+%Y%m%d%H%M%S' | sed 's/^/0/'; }

# Pretty-print a duration in seconds as e.g. "2m 14s" or "47s".
_format_duration() {
    local secs="$1"
    if [[ "$secs" -lt 60 ]]; then
        echo "${secs}s"
    elif [[ "$secs" -lt 3600 ]]; then
        echo "$((secs / 60))m $((secs % 60))s"
    else
        echo "$((secs / 3600))h $(((secs % 3600) / 60))m"
    fi
}

# Turn a URL/host string into a filename-safe token (drop :/, etc.).
_safe_name() {
    printf '%s' "$1" | tr -c '[:alnum:].-' '_'
}

# ── Resolver health-check ────────────────────────────────────────────────────
# Probe every resolver in RESOLVERS_SOURCE and keep only those that actually
# answer from THIS network, writing the survivors to $OUTPUT_DIR/live_resolvers.txt
# and pointing RESOLVERS_FILE at it. A "trusted" public list (e.g. trickest) is
# validated from the author's vantage point, not yours — on a restricted network
# most of its entries are unreachable and every dnsx query that lands on a dead
# resolver just times out (the "resolved=few, timeout=most, nxdomain=0" pattern).
# Pruning to live resolvers up-front makes resolution both accurate and fast, and
# adapts automatically to whatever network Metho runs on. Falls back to the full
# source list if the probe cannot run or nothing responds.
build_live_resolvers() {
    local src="${RESOLVERS_SOURCE:-/opt/scripts/wordlists/resolvers.txt}"
    local out="${OUTPUT_DIR}/live_resolvers.txt"
    RESOLVERS_FILE="$src"

    if ! command -v dnsx &>/dev/null; then
        log_warn "Resolver health-check skipped (dnsx not found); using $src as-is"
        return
    fi
    if [[ ! -s "$src" ]]; then
        log_warn "Resolver source list missing/empty: $src — DNS resolution will likely fail"
        return
    fi

    local total
    total=$(grep -cvE '^[[:space:]]*(#|$)' "$src" 2>/dev/null || echo 0)
    log_info "Health-checking $total DNS resolvers (keeping only those reachable from this network)..."

    # Probe each resolver in parallel: it is "live" if it answers an A query for
    # a stable, always-resolvable probe domain. IP-only input, so passing the
    # resolver as an argument to sh -c is safe.
    grep -vE '^[[:space:]]*(#|$)' "$src" \
        | xargs -P 20 -I RV sh -c '
            if printf "one.one.one.one\ncloudflare.com\n" \
                 | dnsx -silent -a -r "$1" -timeout 3 -retry 1 2>/dev/null | grep -q .; then
                echo "$1"
            fi' _ RV 2>/dev/null \
        | sort -u > "$out" || true

    local live=0
    [[ -s "$out" ]] && live=$(wc -l < "$out")
    if [[ "$live" -gt 0 ]]; then
        RESOLVERS_FILE="$out"
        log_success "Resolver health-check: ${live}/${total} resolvers live — using $out"
    else
        log_warn "Resolver health-check: none of the ${total} resolvers responded — keeping full list ($src). DNS is likely broken on this network (VPN/TUN? blocked UDP/53?)."
        RESOLVERS_FILE="$src"
    fi
}

# ── Normalize a hostname ────────────────────────────────────────────────────
# Strip leading *. wildcard, lowercase, strip trailing dot.
normalize_hostname() {
    echo "$1" | sed 's/^\*\.//; s/\.$//' | tr '[:upper:]' '[:lower:]'
}

# ── crt.name Certificate Transparency query ──────────────────────────────────
# Queries the crt.name API for a root domain and extracts in-scope hostnames.
# Usage: crtname_query <domain> <output_hostnames_file> <raw_json_file>
#
# The crt.name API returns JSON: [{"sub":"hostname.example.com"}, ...]
# We normalize hostnames, filter to in-scope (matching the root domain),
# deduplicate, and preserve the raw API response.
# Registrable apex for a hostname. crt.name's ?apex= param expects a
# REGISTRABLE domain and returns HTTP 400 for a deep subdomain
# (automotive.vodafone.co.uk -> 400, abcom.al -> 200). A full Public Suffix
# List is unnecessary here — this covers the multi-label ccTLD suffixes the
# target scope actually contains (co.uk, com.tr, co.za, co.tz, co.ke, co.mz,
# co.ls, com.eg, ...) plus common extras. Single-label TLDs fall through to
# last-two-labels. Callers still filter results to the exact in-scope host.
_METHO_MULTI_SUFFIXES=" co.uk org.uk gov.uk ac.uk me.uk com.tr net.tr org.tr gov.tr co.za org.za co.tz co.ke co.mz com.mz co.ls com.eg net.eg co.nz com.au net.au org.au co.in co.id com.br com.mx co.jp com.sg com.my "
registrable_apex() {
    local host="${1%.}"
    local IFS='.'
    local -a parts=()
    read -ra parts <<< "$host"
    local n=${#parts[@]}
    if (( n < 2 )); then printf '%s\n' "$host"; return; fi
    local last2="${parts[n-2]}.${parts[n-1]}"
    if (( n >= 3 )) && [[ "$_METHO_MULTI_SUFFIXES" == *" $last2 "* ]]; then
        printf '%s\n' "${parts[n-3]}.$last2"
    else
        printf '%s\n' "$last2"
    fi
}

crtname_query() {
    local domain="$1" output_file="$2" raw_file="$3"

    : > "$output_file"
    : > "$raw_file"

    if ! command -v curl &>/dev/null; then
        log_warn "crt.name: curl not found, skipping certificate transparency query"
        return
    fi

    local apex
    apex=$(registrable_apex "$domain")
    log_info "Querying crt.name for $domain (apex: $apex)..."
    local api_url="https://crt.name/v1/search?apex=${apex}&format=json"
    local http_code
    # --max-time guards against a proxy/endpoint that accepts the connection
    # then stalls (crt.name has no server-side timeout of its own).
    http_code=$(with_passive_proxy curl -s --max-time 30 -w '%{http_code}' -o "$raw_file" "$api_url" 2>/dev/null || echo "000")

    if [[ "$http_code" != "200" ]]; then
        log_warn "crt.name: API returned HTTP $http_code for $domain"
        return
    fi

    if [[ ! -s "$raw_file" ]]; then
        log_warn "crt.name: empty response for $domain"
        return
    fi

    # Extract "sub" fields from JSON, normalize, filter to in-scope, deduplicate.
    # Normalization is a SINGLE streamed pass (strip *. and trailing dot, then
    # lowercase) — the previous per-line shell loop forked sed+tr per hostname
    # and cost minutes on large-CT apexes (~28k names for vodafone.com, far
    # worse under amd64 emulation). Mirrors canonical_dns_add_sources' batch idiom.
    local escaped_domain="${domain//./\\.}"
    jq -r '.[].sub // empty' "$raw_file" 2>/dev/null \
        | sed 's/^\*\.//;s/\.$//' \
        | tr '[:upper:]' '[:lower:]' \
        | grep -E "(^|\.)${escaped_domain}$" \
        | sort -u > "$output_file"

    local count=0
    [[ -s "$output_file" ]] && count=$(wc -l < "$output_file")
    log_success "crt.name subdomains for $domain: $count"
}

# ── Bounded parallel execution ──────────────────────────────────────────────
# Run FUNC once per non-empty line of INPUT with bounded concurrency.
# Each FUNC invocation runs in a backgrounded subshell (which inherits all
# sourced functions/vars, so no export needed). FUNC receives the line as $1
# plus any trailing args. Caller is responsible for giving each worker its
# own output file (see _safe_name) and merging results after this returns.
bounded_parallel() {
    local concurrency="$1" input="$2" func="$3"; shift 3
    local running=0 _prev_errexit
    # Guard: a non-positive PARALLEL_HOSTS would mean no workers spawn.
    [[ "$concurrency" -lt 1 ]] && concurrency=1
    # Detect `wait -n` support (bash >= 4.3). Done once; cheap.
    if [[ -z "${_METHO_HAS_WAIT_N+x}" ]]; then
        # Do NOT probe with `(wait -n)`: with no child jobs it returns non-zero
        # on EVERY bash (unknown-option 2 on <4.3, "no more children" 127 on
        # >=4.3), so the probe ALWAYS failed and silently forced slow
        # whole-batch mode (a stuck domain then gates the entire pool). Gate on
        # the interpreter version directly, which is what actually matters.
        if (( BASH_VERSINFO[0] > 4 || ( BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] >= 3 ) )); then
            _METHO_HAS_WAIT_N=1
        else
            _METHO_HAS_WAIT_N=0
        fi
    fi
    # Temporarily disable errexit AND save/restore it. A worker that returns
    # non-zero must NOT abort the pool (its exit surfaces through `wait`), and
    # we must not leak `set +e` back to the caller.
    case $- in *e*) _prev_errexit=1; set +e;; *) _prev_errexit=0;; esac
    while read -r line; do
        [[ -z "$line" ]] && continue
        # Workers read from /dev/null: a tool that ignores the caller's
        # stdin redirections (katana historically did) must not swallow the
        # remaining input lines this loop is still reading.
        ( "$func" "$line" "$@" || true ) < /dev/null &
        running=$((running + 1))
        if (( running >= concurrency )); then
            if [[ "$_METHO_HAS_WAIT_N" == 1 ]]; then
                wait -n || true
                running=$((running - 1))
            else
                # Older bash: wait for the whole batch, then start the next.
                wait || true
                running=0
            fi
        fi
    done < "$input"
    wait || true
    [[ "$_prev_errexit" == 1 ]] && set -e
}

# NOTE: each logger must return 0 unconditionally. Before init_log runs,
# LOG_FILE is empty and the `[[ -n "$LOG_FILE" ]] && ...` guard would leave
# the function with status 1 — under `set -e` (recon.sh) that silently kills
# the whole pipeline the first time a logger fires pre-init (e.g. the
# --subfaster-config message in validate_args).
log_info()    { local msg="[*] $*"; echo -e "${CYAN}${msg}${NC}"; { [[ -n "$LOG_FILE" ]] && echo "$(_log_ts) ${msg}" >> "$LOG_FILE"; } || true; }
log_success() { local msg="[+] $*"; echo -e "${GREEN}${msg}${NC}"; { [[ -n "$LOG_FILE" ]] && echo "$(_log_ts) ${msg}" >> "$LOG_FILE"; } || true; }
log_warn()    { local msg="[!] $*"; echo -e "${YELLOW}${msg}${NC}"; { [[ -n "$LOG_FILE" ]] && echo "$(_log_ts) ${msg}" >> "$LOG_FILE"; } || true; }
log_error()   { local msg="[-] $*"; echo -e "${RED}${msg}${NC}"; { [[ -n "$LOG_FILE" ]] && echo "$(_log_ts) ${msg}" >> "$LOG_FILE"; } || true; }
log_skip()    { local msg="[SKIP] $*"; echo -e "${YELLOW}${msg}${NC}"; { [[ -n "$LOG_FILE" ]] && echo "$(_log_ts) ${msg}" >> "$LOG_FILE"; } || true; }

# ── Passive-source proxy ─────────────────────────────────────────────────────
# Run a command with proxy env vars set ONLY when --proxy/PASSIVE_PROXY is
# given. Applied exclusively to passive OSINT sources (crt.name, GitHub,
# subfaster, waymore), while target DNS resolution, HTTPX and Nmap keep using
# the direct network (real IPs).
# curl and Python (requests+PySocks) honor these for SOCKS and HTTP proxies;
# statically-linked Go tools honor an http:// proxy via net/http but may ignore
# a socks5:// one — prefer an HTTP proxy URL for full coverage.
with_passive_proxy() {
    if [[ -n "${PASSIVE_PROXY:-}" ]]; then
        HTTP_PROXY="$PASSIVE_PROXY"  HTTPS_PROXY="$PASSIVE_PROXY"  ALL_PROXY="$PASSIVE_PROXY" \
        http_proxy="$PASSIVE_PROXY"  https_proxy="$PASSIVE_PROXY"  all_proxy="$PASSIVE_PROXY" \
        "$@"
    else
        "$@"
    fi
}

# ── CLI Argument Parsing ────────────────────────────────────────────────────
DOMAINS=""
DOMAINS_FILE=""
# Preserve an env-var-supplied config (e.g. -e SUBFASTER_PROVIDER_CONFIG=...).
# Previously this was hardcoded to "" which silently overwrote the env var;
# users had to pass --subfaster-config on the CLI to get it recognized.
SUBFASTER_PROVIDER_CONFIG="${SUBFASTER_PROVIDER_CONFIG:-}"
# Proxy for passive OSINT sources only (see with_passive_proxy). Env-supplied
# value is preserved so `-e PASSIVE_PROXY=...` works like the CLI flag.
PASSIVE_PROXY="${PASSIVE_PROXY:-}"
# DNS resolvers. RESOLVERS_SOURCE is the candidate list; at startup it is
# health-checked and only the resolvers that actually answer from THIS network
# are kept in RESOLVERS_FILE (see build_live_resolvers). Every dnsx call uses
# RESOLVERS_FILE. Override the source list with --resolvers.
RESOLVERS_SOURCE="${RESOLVERS_SOURCE:-/opt/scripts/wordlists/resolvers.txt}"
RESOLVERS_FILE="${RESOLVERS_SOURCE}"
AUTO=false
SKIP_PHASES=()
THREADS=50
RATE_LIMIT=100
CHECKPOINT_TIMEOUT=30
OUTPUT_DIR="/output"
CLOUD_ENUM_KEYWORDS=""
PORT_SCAN=true
# Hard off-switch for dnsgen permutation brute force (Stage 4b). Independent of
# DNSGEN_SKIP_THRESHOLD: when true, permutation is skipped for every domain
# regardless of size. Recommended for large multi-domain sweeps where the
# permutation multiplier would dominate runtime for little yield.
SKIP_PERMUTATION=false
# How many live hosts to crawl in parallel within a per-host tool (CeWL,
# Katana, SubDomainizer). These stages spend the vast majority of wall-clock
# time crawling hosts one-by-one; a small bounded pool cuts that ~Nx with no
# data loss.
PARALLEL_HOSTS=5
# How many root domains to process in parallel during Phase 1. Each domain
# gets its own canonical_dns.tsv and httpx_metadata.tsv; after all complete,
# merge_per_domain_dns combines them into the global TSV. I/O-bound workloads
# (DNS, HTTP) tolerate higher concurrency than CPU-bound ones.
PARALLEL_DOMAINS=3
# Per-domain wall-clock cap (seconds) for Phase 1. A single pathological domain
# (huge permutation set, or DNS grinding through per-query timeouts) must never
# gate the whole parallel pool. A watchdog TERMs then KILLs that domain's worker
# once it outlives the cap; already-written partial results are kept. 0 =
# unlimited. Default 5400s (90m) is generous — it only catches genuine hangs.
DOMAIN_TIMEOUT=5400
# ASN classification config file (shell-sourceable)
ASN_CONFIG_FILE=""
# Waymore mode: U (URLs only, default), B (URLs + response bodies).
# R (responses only) is rejected in validate_args — the pipeline extracts
# subdomains from the -oU URL list, not response bodies. Mode U keeps full
# subdomain-discovery coverage while skipping the slow response-body
# downloads that the pipeline never reads back (the -oR dir is unused).
WAYMORE_MODE="U"
# Per-domain wall-clock cap for waymore. Mode U (URLs only) is much faster
# than mode B (which downloads archived response bodies), so 600s is a sane
# default; override with WAYMORE_TIMEOUT for very large domains.
WAYMORE_TIMEOUT=600
# Cloud_Enum wall-clock cap. The fuzz list checks most common bucket names
# first (dev, staging, test, prod, …), so the highest-value permutations
# happen early. 900s (15 min) covers the vast majority of useful checks;
# the previous 1800s default spent the second 15 min on low-probability
# mutations that rarely yield findings.
CLOUD_ENUM_TIMEOUT=900

# Cap dnsgen input subdomain count. dnsgen v2 default mode yields
# ~800-1100 permutations per input — 500 inputs → up to ~561K candidates.
# 500 inputs keeps resolution ≈ 6-10 min, and beyond ~500 passive subs the
# permutation yield drops to near zero anyway (passive sources saturate
# coverage — reconftw uses the same 500 threshold). Resolved hostnames
# are prioritized. Set to 0 to disable the cap.
DNSGEN_MAX_INPUT=500

# Skip dnsgen entirely when a domain has more than this many discovered
# subdomains. Default is deliberately AGGRESSIVE (100): permutation multiplies
# every input by ~800-1100 candidates, so even a "small" domain explodes (307
# subs → 273K candidates in E2E), and empirical yield on non-tiny corpora is
# ~0 while the DNS cost is huge — a multiplier that is ruinous across a large
# multi-domain sweep. So by default only genuinely tiny domains (≤100 subs)
# permute; everything else relies on passive + brute coverage. Raise it for a
# focused single-domain deep run, use --skip-permutation to disable entirely,
# or set to 0 to never skip (permute every domain — not recommended at scale).
DNSGEN_SKIP_THRESHOLD=100

# Hard cap on dnsgen output size in bytes (default 25MB ≈ ~350K
# candidates). Safety net against permutation explosion before the
# resolution stage.
DNSGEN_MAX_OUTPUT_BYTES=26214400

# Naabu packets-per-second cap for the top-1000 SYN sweep. 1000 pps is
# reconftw's NAABU_RATE default: fast enough that 1000 hosts × 1000 ports
# finish well within the timeout, throttled enough to avoid saturating
# the uplink or tripping IPS on the target edge.
NAABU_RATE=1000
# Naabu SYN retransmit count. 2 matches reconftw's --max-retries default
# (one initial probe + 2 retries): resilient to single-packet loss
# without multiplying noise on filtered ports.
NAABU_RETRIES=2

# Cap on how many ports nmap -sV service-detects in Stage 4b. naabu already
# records EVERY open port (they are merged into the final ip_port_pairs), so
# this only bounds which ports get version detection. Without a cap, the union
# of open ports across hundreds of hosts approaches the full top-1000 set and
# nmap re-scans every host against all of them — the single biggest time sink
# in Phase 3. The cap keeps the N ports open on the MOST hosts (highest signal).
# 0 = no cap (scan the full union). Override with --nmap-top-ports.
NMAP_TOP_PORTS=100

# Numeric-argument guard: rejects non-integer values up-front so a typo like
# `--threads abc` fails immediately with a clear message instead of deep inside
# dnsx/cloud_enum at runtime.
_require_int() {
    local flag="$1" val="$2"
    if ! [[ "$val" =~ ^[0-9]+$ ]]; then
        log_error "$flag requires a positive integer, got: $val"
        exit 1
    fi
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --domains)        DOMAINS="$2"; shift 2 ;;
            --domains-file)   DOMAINS_FILE="$2"; shift 2 ;;
            --subfaster-config) SUBFASTER_PROVIDER_CONFIG="$2"; shift 2 ;;
            --proxy)          PASSIVE_PROXY="$2"; shift 2 ;;
            --resolvers)      RESOLVERS_SOURCE="$2"; RESOLVERS_FILE="$2"; shift 2 ;;
            --asn-config)     ASN_CONFIG_FILE="$2"; shift 2 ;;
            --waymore-mode)   WAYMORE_MODE="$2"; shift 2 ;;
            --auto)           AUTO=true; shift ;;
            --skip-phase)     case "$2" in
                                  1|2|3) SKIP_PHASES+=("$2") ;;
                                  *) log_error "Invalid --skip-phase value: $2 (must be 1, 2, or 3)"; exit 1 ;;
                              esac; shift 2 ;;
            --skip-cloud)     SKIP_PHASES+=("2"); shift ;;
            --no-port-scan)   PORT_SCAN=false; shift ;;
            --skip-permutation) SKIP_PERMUTATION=true; shift ;;
            --threads)        _require_int "$1" "$2"; THREADS="$2"; shift 2 ;;
            --parallel-hosts) _require_int "$1" "$2"; PARALLEL_HOSTS="$2"; shift 2 ;;
            --parallel-domains) _require_int "$1" "$2"; PARALLEL_DOMAINS="$2"; shift 2 ;;
            --domain-timeout) _require_int "$1" "$2"; DOMAIN_TIMEOUT="$2"; shift 2 ;;
            --rate-limit)     _require_int "$1" "$2"; RATE_LIMIT="$2"; shift 2 ;;
            --nmap-top-ports) _require_int "$1" "$2"; NMAP_TOP_PORTS="$2"; shift 2 ;;
            --timeout)        _require_int "$1" "$2"; CHECKPOINT_TIMEOUT="$2"; shift 2 ;;
            --output)         OUTPUT_DIR="$2"; shift 2 ;;
            --cloud-enum-keywords) CLOUD_ENUM_KEYWORDS="$2"; shift 2 ;;
            -h|--help)
                echo "Usage: recon.sh [options]"
                echo ""
                echo "Required (one of):"
                echo "  --domains d1,d2,...       Comma-separated root domains"
                echo "  --domains-file FILE       Line-separated root domains file"
                echo ""
                echo "Options:"
                echo "  --subfaster-config FILE   Path to subfaster provider-config.yaml (API keys)"
                echo "  --proxy URL               Proxy for PASSIVE sources only (crt.name, GitHub,"
                echo "                            subfaster, waymore). Scanning/DNS/Nmap stay direct."
                echo "                            e.g. socks5h://host.docker.internal:12334 or http://host.docker.internal:8080"
                echo "  --resolvers FILE          DNS resolver list to health-check at startup (default: built-in)."
                echo "                            Only resolvers reachable from this network are used."
                echo "  --asn-config FILE         Path to ASN provider classification config (default: built-in)"
                echo "  --waymore-mode MODE       Waymore mode: U (URLs, default) or B (URLs+responses)"
                echo "  --auto                    Skip all checkpoint prompts"
                echo "  --skip-phase {1,2,3}      Skip specific phase(s)"
                echo "  --skip-cloud              Shorthand for --skip-phase 2"
                echo "  --no-port-scan            Skip port scanning phase"
                echo "  --skip-permutation        Disable dnsgen permutation brute force (Stage 4b) for all domains"
                echo "  --threads N               Thread count (default: 50)"
                echo "  --parallel-hosts N         Hosts crawled in parallel per tool (default: 5)"
                echo "  --parallel-domains N       Root domains processed in parallel in Phase 1 (default: 3)"
                echo "  --domain-timeout N        Per-domain wall-clock cap in seconds (default: 5400; 0=off)"
                echo "  --rate-limit N            Requests/second (default: 100)"
                echo "  --nmap-top-ports N        Cap nmap -sV to the N most-common open ports (default: 100; 0=no cap)"
                echo "  --timeout N               Checkpoint auto-continue seconds (default: 30)"
                echo "  --output DIR              Output directory (default: /output)"
                echo "  --cloud-enum-keywords KW  Keywords for cloud_enum brute force (comma-sep)"
                exit 0 ;;
            *) log_error "Unknown argument: $1"; exit 1 ;;
        esac
    done
}

validate_args() {
    if [[ -z "$DOMAINS" && -z "$DOMAINS_FILE" ]]; then
        log_error "One of --domains or --domains-file must be provided."
        exit 1
    fi
    if [[ -n "$DOMAINS_FILE" && ! -f "$DOMAINS_FILE" ]]; then
        log_error "Domains file not found: $DOMAINS_FILE"
        exit 1
    fi
    if [[ -n "$DOMAINS_FILE" && ! -s "$DOMAINS_FILE" ]]; then
        log_error "Domains file is empty: $DOMAINS_FILE"
        exit 1
    fi
    if [[ -n "$SUBFASTER_PROVIDER_CONFIG" && ! -f "$SUBFASTER_PROVIDER_CONFIG" ]]; then
        log_error "Subfaster config file not found: $SUBFASTER_PROVIDER_CONFIG"
        exit 1
    fi
    if [[ -n "$ASN_CONFIG_FILE" && ! -f "$ASN_CONFIG_FILE" ]]; then
        log_error "ASN config file not found: $ASN_CONFIG_FILE"
        exit 1
    fi
    if [[ -n "$SUBFASTER_PROVIDER_CONFIG" ]]; then
        export SUBFASTER_PROVIDER_CONFIG
        log_info "Subfaster provider config: $SUBFASTER_PROVIDER_CONFIG"
    fi
    # Normalize and sanity-check the passive proxy.
    if [[ -n "$PASSIVE_PROXY" ]]; then
        # A bare socks:// is ambiguous to curl; assume SOCKS5 with remote DNS.
        case "$PASSIVE_PROXY" in
            socks://*)
                PASSIVE_PROXY="socks5h://${PASSIVE_PROXY#socks://}"
                log_warn "Proxy scheme 'socks://' is ambiguous; using ${PASSIVE_PROXY} (SOCKS5, remote DNS)" ;;
        esac
        case "$PASSIVE_PROXY" in
            *://localhost:*|*://127.0.0.1:*)
                log_warn "Proxy host is localhost/127.0.0.1 — inside the container that resolves to the container itself, not the Docker host. If the proxy runs on the host, use host.docker.internal instead (e.g. ${PASSIVE_PROXY%%://*}://host.docker.internal:PORT)." ;;
        esac
        export PASSIVE_PROXY
    fi
    # Validate waymore mode
    case "$WAYMORE_MODE" in
        # R (responses only) is deliberately NOT accepted: Phase 1 extracts
        # subdomains from waymore's -oU URL output, which responses-only mode
        # does not produce — a mode-R run would silently discover nothing.
        U|B) ;;
        *) log_error "Invalid --waymore-mode: $WAYMORE_MODE (must be U or B; R is not supported because the pipeline consumes URL output)"; exit 1 ;;
    esac
}

# Resolve domain input (--domains or --domains-file) into a file path.
# Returns the path to a file with one domain per line.
resolve_domain_file() {
    local target="$1"

    if [[ -n "$DOMAINS_FILE" ]]; then
        grep -v '^\s*$' "$DOMAINS_FILE" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sort -u > "$target"
        echo "$target"
        return
    fi

    if [[ -n "$DOMAINS" ]]; then
        IFS=',' read -ra domain_arr <<< "$DOMAINS"
        for d in "${domain_arr[@]}"; do
            echo "$d" | xargs
        done | sort -u > "$target"
        echo "$target"
        return
    fi

    echo ""
}

should_skip_phase() {
    local phase="$1"
    for p in "${SKIP_PHASES[@]}"; do
        [[ "$p" == "$phase" ]] && return 0
    done
    return 1
}

# ── Checkpoint System ────────────────────────────────────────────────────────
checkpoint() {
    local message="$1"
    echo ""
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}[CHECKPOINT]${NC} $message"
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo ""

    if [[ "$AUTO" == true ]]; then
        log_info "Auto mode — continuing..."
        return 0
    fi

    if [[ ! -t 0 ]]; then
        log_info "Non-interactive terminal — continuing..."
        return 0
    fi

    echo "  [C]ontinue  [S]kip next phase  [Q]uit  [R]eview results"
    echo -n "  > "

    if [[ "$CHECKPOINT_TIMEOUT" -gt 0 ]]; then
        read -t "$CHECKPOINT_TIMEOUT" -r choice < /dev/tty || choice="c"
    else
        read -r choice < /dev/tty
    fi

    case "${choice,,}" in
        c|""|"continue")   return 0 ;;
        s|skip)
            # "Skip next phase" records the phase that follows the one that just
            # ran (CURRENT_PHASE is still set to it). Next-phase is consulted by
            # should_skip_phase a moment later, so the skip genuinely takes
            # effect. Establish the user's intent as state rather than a return
            # code, because callers invoke checkpoint with `|| true` (the exit
            # status is otherwise swallowed).
            local next_phase=$((CURRENT_PHASE + 1))
            if [[ "$next_phase" -le 3 ]]; then
                SKIP_PHASES+=("$next_phase")
                log_info "Skip registered for Phase $next_phase."
            else
                log_info "No further phase to skip (all phases already ran)."
            fi
            return 0 ;;
        q|quit)            log_info "Exiting."; exit 0 ;;
        r|review)
            echo ""
            echo "  Phase output files:"
            ls -la "${OUTPUT_DIR}/phase${CURRENT_PHASE:-?}/" 2>/dev/null | tail -20
            echo ""
            echo -n "  Press Enter to continue... "
            read -r < /dev/tty
            return 0 ;;
        *) return 0 ;;
    esac
}

# ── Directory Setup ──────────────────────────────────────────────────────────
# 777 (not u+rwX) is intentional: the container runs as root but the host
# user mounting /output is usually a non-root uid. World-writable lets the
# host user read, modify, and delete results without "permission denied".
setup_dirs() {
    mkdir -p "${OUTPUT_DIR}"/{phase1,phase2,phase3,final,config}
    chmod -R 777 "$OUTPUT_DIR" 2>/dev/null || true
}

# ── Dependency Check ────────────────────────────────────────────────────────
# Only the core plumbing tools are checked up-front. The recon tools
# (dnsx, katana, etc.) are validated lazily, per-stage, with
# `command -v` so any missing tool is skipped cleanly instead of failing
# the whole run.
REQUIRED_TOOLS=(jq curl)

validate_deps() {
    local missing=()
    for tool in "${REQUIRED_TOOLS[@]}"; do
        command -v "$tool" &>/dev/null || missing+=("$tool")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing[*]}"
        exit 1
    fi
}

# ── HTTPx Probe Helper ─────────────────────────────────────────────────────
# Default: httpx probes port 443 (HTTPS) then falls back to 80 (HTTP).
# No -ports flag = much faster, covers the vast majority of web services.
# No -mc flag = show all responses (equivalent to listing every status code).
#
# HTTPX flags for rich metadata:
#   -cdn            detect CDN and include cdn field in JSON output
#   -status-code    include HTTP status code
#   -title          include page title
#   -tech-detect    detect web technologies
#   -web-server     include web server header (alias: -server)
#   -content-length include content length
httpx_probe() {
    local input_file="$1"
    local output_json="$2"

    if [[ ! -s "$input_file" ]]; then
        log_warn "No subdomains to probe in $input_file"
        return
    fi

    local target_count
    target_count=$(wc -l < "$input_file")
    log_info "Probing ${target_count} targets with httpx..."

    # httpx log file for full verbose output (for debugging)
    local httpx_log="${output_json%.json}.httpx.log"

    # Run httpx with CDN detection and full metadata.
    # -cdn: detect CDN (adds "cdn" boolean field to JSON output)
    # -tech-detect: detect web technologies (adds "tech" array)
    # -web-server: detect web server (alias for -server in some versions)
    # -content-length: include content_length field
    # -status-code, -title: include status code and page title
    cat "$input_file" | httpx \
        -silent \
        -json \
        -cdn \
        -status-code \
        -title \
        -tech-detect \
        -web-server \
        -content-length \
        -timeout 10 \
        -retries 2 \
        -rate-limit "$RATE_LIMIT" \
        -o "$output_json" > /dev/null 2>"$httpx_log" || true

    local count=0
    if [[ -s "$output_json" ]]; then
        count=$(wc -l < "$output_json")
        log_success "Live web servers found: $count"
    else
        log_warn "No live web servers found in this round."
    fi

    # Append a summary to the httpx log for context
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] httpx run complete: ${count} results from ${target_count} targets" >> "$httpx_log"

    # Merge httpx metadata into the canonical DNS dataset
    if [[ -s "$output_json" ]]; then
        canonical_dns_merge_httpx "$output_json"
    fi
}

# ── Domain Extraction ───────────────────────────────────────────────────────
extract_domains() {
    local input_file="$1"
    local output_file="$2"
    # `|| true`: grep exits 1 when the input contains zero domain-like
    # tokens. Without it, set -e + pipefail would abort the ENTIRE pipeline
    # run at Stage 5 with no error message (verified in testing).
    #
    # Strip percent-encoded fragments first: URLs like
    # https://x.example.com/redirect?to=%2Fapp.example.com would otherwise
    # yield bogus "2Fapp.example.com" tokens (the %2F path separator
    # merges with the following hostname chars).
    sed -E 's/%[0-9A-Fa-f]{2}/ /g' "$input_file" 2>/dev/null \
        | grep -oE '([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}' \
        | sort -u > "$output_file" || true
}

# ── Cloud Domain Filter ────────────────────────────────────────────────────
# Matches any host pointing at a recognized cloud / PaaS provider.
# The regex is a union of provider-specific suffixes plus root-domain
# tokens; we don't try to enumerate every bucket naming convention.
#
# Coverage rationale:
#   AWS:        amazonaws, cloudfront, elasticbeanstalk, apps that
#               front EC2 with the AWS global accelerator
#   Azure:      azurewebsites, azure, blob.core.windows, cloudapp,
#               azure-api (API Management)
#   GCP:        googleapis, appspot, cloudfunctions, storage.googleapis,
#               web.app (Firebase App Hosting)
#   Cloudflare: cloudflarestorage (R2), workers.dev (Workers)
#   DigitalOcean: digitaloceanspaces (Spaces), digitalocean.app /
#               ondigitalocean.app (App Platform)
#   Heroku:     herokuapp.com / heroku.com
#   Vercel:     vercel.app
#   Netlify:    netlify.app
#   Fly.io:     fly.dev
#   Railway:    railway.app
#   Render:     onrender.com
#   Backblaze:  backblazeb2.com
#   Linode:     linodeobjects.com
#   Oracle:     oraclecloud.com / oraclecloudusercontent.com
#   Supabase:   supabase.co / supabase.in
filter_cloud_domains() {
    local input_file="$1"
    local output_file="$2"
    grep -iE '(amazonaws|cloudfront|elasticbeanstalk|azurewebsites|azure-api|blob\.core\.windows|cloudapp|googleapis|appspot|cloudfunctions|storage\.googleapis|web\.app|cloudflarestorage|workers\.dev|digitaloceanspaces|digitalocean\.app|ondigitalocean\.app|herokuapp|vercel\.app|netlify\.app|fly\.dev|railway\.app|onrender\.com|backblazeb2|linodeobjects|oraclecloud|supabase\.co|supabase\.in)' \
        "$input_file" | sort -u > "$output_file" 2>/dev/null || true
}