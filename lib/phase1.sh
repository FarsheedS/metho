#!/usr/bin/env bash
# Phase 1: Root Domains → All Subdomains
# For each root domain, discovers subdomains via passive enumeration,
# historical recon, DNS brute force, and web crawling.

run_phase1() {
    local pdir="${OUTPUT_DIR}/phase1"
    mkdir -p "$pdir"
    CURRENT_PHASE=1

    local root_domains_file="$1"
    if [[ ! -s "$root_domains_file" ]]; then
        log_error "No root domains file provided for Phase 1"
        return 1
    fi

    local domain_count
    domain_count=$(wc -l < "$root_domains_file")
    log_info "═══ PHASE 1: Root Domains → Subdomains (${domain_count} domains) ═══"

    # Seed every user-supplied root domain itself into the canonical dataset
    # so the apex/root application is not missed simply because no discovery
    # tool returns it. The apex must subsequently go through the normal DNSX
    # and HTTPX processing like any other hostname. Its source is recorded as
    # `root`; match_root_domain resolves each apex to itself (exact match).
    canonical_dns_add_sources "root" "$root_domains_file"

    while read -r DOMAIN; do
        [[ -z "$DOMAIN" ]] && continue
        process_domain "$DOMAIN" "$pdir"
    done < "$root_domains_file"
}

# ── CeWL helpers (Stage 4) ─────────────────────────────────────────────────
# CeWL keeps the spider frontier and every collected word in RAM (it prints
# words only after the crawl finishes). On large doc/library sites a `-d 2`
# crawl can grow past the container's memory and get SIGKILLed by the kernel
# OOM killer — we watched this happen mid-run ("Killed" after ~2.5 min on a
# big docs host, far below the 600s timeout). CeWL itself has NO page-limit
# or memory flag (per the digininja/CeWL README the only crawl-size levers
# are -d, staying on-site, --exclude and --allowed), so we bound it from the
# outside:
#
#   * `ulimit -v` caps the cewl process's address space at CEWL_MEM_LIMIT_MB.
#     When Ruby hits it, cewl exits non-zero (NoMemoryError) instead of the
#     kernel OOM-killing it — and potentially destabilizing the Docker VM.
#   * On ANY failure (memory cap, timeout, crash) we retry the same host at
#     depth 1 — breadth across all live hosts matters more for wordlist
#     diversity than depth on one host, so we degrade gracefully instead of
#     losing the host's words entirely. CeWL only prints its wordlist after
#     the crawl completes, so a killed crawl appends nothing — no partial
#     junk reaches the wordlist.
#   * `< /dev/null` detaches cewl's stdin from the enclosing `while read`
#     loop (defence against the stdin-consumption bug class that
#     katana exhibited).
run_cewl() {
    local url="$1" depth="$2"
    (
        ulimit -v "$(( ${CEWL_MEM_LIMIT_MB:-1024} * 1024 ))" 2>/dev/null || true
        exec timeout "${CEWL_TIMEOUT:-600}" cewl "$url" \
            -d "$depth" -m 5 --with-numbers < /dev/null 2>/dev/null
    )
}

# CeWL output format (per digininja/CeWL cewl.rb): without -c/--count it
# prints one bare word per line. We deliberately do NOT pass -c — the count
# column is noise for ShuffleDNS brute force. `--with-numbers` keeps
# alphanumeric tokens like `iso9001`/`s3` that the source would otherwise
# strip. The awk chain re-filters defensively: CeWL writes connection
# errors to STDOUT (not STDERR) when not in -v mode, and the second awk
# drops anything that isn't a clean 3–20 char token containing at least one
# letter. (The letter floor used to be >= 2, which silently dropped
# valuable labels like mx1, db2, s3x — pure-digit strings are still
# dropped; leading-digit tokens are removed later by the post-filter.)
cewl_filter() {
    awk 'length >= 3 && length <= 20' | \
    awk '{ orig=$0; if (match($0, /^[a-zA-Z0-9_-]{3,20}$/) && gsub(/[a-zA-Z]/, "&") >= 1) print orig }' | \
    tr '[:upper:]' '[:lower:]'
}

process_domain() {
    local domain="$1"
    local pdir="$2"
    local ddir="${pdir}/${domain}"
    mkdir -p "$ddir"

    log_info "────────────────────────────────────────────"
    log_info "Processing domain: $domain"
    log_info "────────────────────────────────────────────"

    cd "$ddir" || return 1

    # ── Stage 1: Passive Subdomain Enumeration ──────────────────────────────
    log_info "Stage 1: Passive subdomain enumeration"

    # Subfaster (replaces Subfinder)
    if command -v subfaster &>/dev/null; then
        log_info "Running Subfaster..."
        local sf_opts=(-d "$domain" -silent -o subfaster_results.txt)
        if [[ -n "$SUBFASTER_PROVIDER_CONFIG" ]]; then
            sf_opts+=(-provider-config "$SUBFASTER_PROVIDER_CONFIG")
        fi
        subfaster "${sf_opts[@]}" 2>/dev/null || true
        local sf_count=0
        [[ -s subfaster_results.txt ]] && sf_count=$(wc -l < subfaster_results.txt)
        log_success "Subfaster subdomains: $sf_count"
    else
        log_warn "Subfaster not found, skipping passive subdomain enumeration"
    fi

    # crt.name — Certificate Transparency
    crtname_query "$domain" crtname_results.txt crtname_raw.json

    # Add all Stage 1 discoveries to the canonical DNS dataset
    [[ -s subfaster_results.txt ]] && canonical_dns_add_sources "subfaster" "subfaster_results.txt" "$domain"
    [[ -s crtname_results.txt ]] && canonical_dns_add_sources "crt.name" "crtname_results.txt" "$domain"

    # ── Stage 2: Historical Recon (Waymore) ─────────────────────────────────
    # Waymore operates on ROOT DOMAINS ONLY — it fetches historical URLs and
    # responses from Wayback, CommonCrawl, OTX, URLScan, VirusTotal, etc.
    log_info "Stage 2: Historical reconnaissance (Waymore)"

    if command -v waymore &>/dev/null; then
        local wm_output_dir="${ddir}/waymore_output"
        mkdir -p "$wm_output_dir"
        local wm_urls="${ddir}/waymore_urls.txt"

        log_info "Running Waymore on root domain $domain (mode ${WAYMORE_MODE:-B})..."
        timeout "${WAYMORE_TIMEOUT:-1800}" waymore \
            -i "$domain" \
            -mode "${WAYMORE_MODE:-B}" \
            -oU "$wm_urls" \
            -oR "$wm_output_dir" \
            -t 30 -p 2 --verbose \
            2>/dev/null || true

        if [[ -s "$wm_urls" ]]; then
            # Extract subdomains from URLs, filter to in-scope, deduplicate
            extract_domains "$wm_urls" waymore_all_domains.txt || true
            local escaped_domain="${domain//./\\.}"
            grep -E "(^|\.)${escaped_domain}$" waymore_all_domains.txt | sort -u > waymore_subdomains.txt || true

            local wm_count=0
            [[ -s waymore_subdomains.txt ]] && wm_count=$(wc -l < waymore_subdomains.txt)
            log_success "Waymore: found $wm_count in-scope subdomains from $(wc -l < "$wm_urls") URLs"

            # Add newly discovered subdomains to canonical DNS dataset
            [[ -s waymore_subdomains.txt ]] && canonical_dns_add_sources "waymore" "waymore_subdomains.txt" "$domain"
        else
            log_info "Waymore: no URLs discovered for $domain"
        fi
    else
        log_warn "Waymore not found, skipping historical reconnaissance"
    fi

    # ── Stage 3: Consolidate + DNSx Canonical Resolution + HTTPx Round 1 ────
    log_info "Stage 3: Consolidating passive results + DNSx resolution + HTTPx Round 1"

    # Merge all discovered subdomains so far
    cat \
        subfaster_results.txt \
        crtname_results.txt \
        waymore_subdomains.txt \
        2>/dev/null | sort -u > all_subdomains_round1.txt || true

    if [[ -s all_subdomains_round1.txt ]]; then
        log_success "Subdomains from passive enumeration: $(wc -l < all_subdomains_round1.txt)"

        # Resolve all pending hostnames through DNSx into the canonical dataset
        canonical_dns_resolve_pending

        # Extract resolved hostnames for HTTPx probing
        canonical_dns_extract_resolved > live_candidates_round1.txt || true

        if [[ -s live_candidates_round1.txt ]]; then
            httpx_probe live_candidates_round1.txt httpx_results_round1.json
            [[ -s httpx_results_round1.json ]] && jq -r '.url' httpx_results_round1.json | sort -u > live_subdomains_round1.txt || true
        else
            log_warn "No resolved subdomains to probe with HTTPx"
            : > live_subdomains_round1.txt
        fi
    else
        log_warn "No subdomains found from passive enumeration for $domain"
        cd "$pdir" || return 1
        return 0
    fi

    # ── Stage 4: Brute Force with Custom Wordlist ──────────────────────────
    log_info "Stage 4: Brute force subdomain discovery"

    # Step 4a: Generate custom wordlist with CeWL
    mkdir -p wordlists
    : > wordlists/custom_wordlist.txt

    if [[ -s live_subdomains_round1.txt ]] && command -v cewl &>/dev/null; then
        # Per-host worker: crawl one URL for words into its own temp file so
        # concurrent CeWL processes never contend on a shared file.
        local _cewl_tmpdir="wordlists/.perhost"
        mkdir -p "$_cewl_tmpdir"; rm -f "$_cewl_tmpdir"/*

        _cewl_one_host() {
            local url="$1" depth="${CEWL_DEPTH:-2}"
            local out="${_cewl_tmpdir}/$(_safe_name "$url").txt"
            if ! run_cewl "$url" "$depth" | cewl_filter > "$out"; then
                log_warn "CeWL failed on $url at depth $depth -- retrying at depth 1"
                run_cewl "$url" 1 | cewl_filter > "$out" || rm -f "$out"
            fi
        }

        log_info "CeWL: crawling $(wc -l < live_subdomains_round1.txt) hosts (depth ${CEWL_DEPTH:-2}, mem cap ${CEWL_MEM_LIMIT_MB:-1024}MB, ${PARALLEL_HOSTS:-5} in parallel)..."
        bounded_parallel "${PARALLEL_HOSTS:-5}" live_subdomains_round1.txt _cewl_one_host

        cat "$_cewl_tmpdir"/*.txt 2>/dev/null > wordlists/custom_wordlist.txt || :
        rm -rf "$_cewl_tmpdir"
        sort -u wordlists/custom_wordlist.txt -o wordlists/custom_wordlist.txt

        # Final label-sanity filter. Digits are ALLOWED (token must merely
        # start with a letter): --with-numbers deliberately keeps tokens
        # like s3, mx1, iso9001, php7 — real subdomain labels — and a
        # previous version of this filter stripped every digit-containing
        # token, silently nullifying --with-numbers. Leading-digit tokens
        # are still dropped.
        awk 'length >= 3 && length <= 20' wordlists/custom_wordlist.txt | \
            grep -E '^([a-z][a-z0-9_-]*[a-z0-9]|[a-z])$' | \
            sort -u -o wordlists/custom_wordlist.txt || true
    fi

    # Fallback: use a minimal default wordlist if CeWL didn't produce anything
    if [[ ! -s wordlists/custom_wordlist.txt ]]; then
        log_warn "CeWL produced no results, using default wordlist"
        cat > wordlists/custom_wordlist.txt <<'WORDBASE'
www
mail
api
dev
staging
test
admin
portal
app
blog
shop
store
cdn
docs
git
ci
jenkins
vpn
remote
dashboard
intranet
internal
stg
uat
prod
preview
sandbox
demo
beta
alpha
old
new
backup
db
mysql
postgres
redis
elastic
grafana
kibana
monitor
status
health
metrics
log
logs
s3
assets
static
media
images
img
cdn
content
cms
wp
wordpress
drupal
joomla
api-gw
gateway
auth
login
sso
oauth
id
identity
account
accounts
user
users
profile
manage
manager
panel
control
cpanel
webmail
mx
smtp
imap
pop
ftp
ns1
ns2
dns
WORDBASE
    fi

    log_info "Wordlist size: $(wc -l < wordlists/custom_wordlist.txt) unique words (CeWL-filtered)"

    # Step 4b: ShuffleDNS brute force
    if command -v shuffledns &>/dev/null; then
        if ! command -v massdns &>/dev/null; then
            log_warn "massdns not found on PATH — ShuffleDNS brute force will produce 0 results. Re-build the Docker image to include massdns."
        fi

        if [[ ! -s /opt/scripts/wordlists/resolvers.txt ]]; then
            log_warn "resolvers file missing or empty: /opt/scripts/wordlists/resolvers.txt — ShuffleDNS will fail"
        fi

        log_info "Running ShuffleDNS brute force on $(wc -l < wordlists/custom_wordlist.txt) words against $domain..."

        local shuffledns_log="shuffledns.debug.log"
        : > "$shuffledns_log"
        local shuffledns_exit=0
        timeout "${SHUFFLEDNS_TIMEOUT:-900}" shuffledns -d "$domain" \
            -w wordlists/custom_wordlist.txt \
            -r /opt/scripts/wordlists/resolvers.txt \
            -mode bruteforce \
            -sw \
            -duc \
            -t "$THREADS" \
            -wt 100 \
            -o shuffledns_results.txt \
            >> "$shuffledns_log" 2>&1 || shuffledns_exit=$?

        if [[ "$shuffledns_exit" -ne 0 ]]; then
            log_warn "ShuffleDNS exited with code ${shuffledns_exit} — see ${shuffledns_log}"
            tail -5 "$shuffledns_log" 2>/dev/null | sed 's/^/    /'
        fi

        if [[ -s shuffledns_results.txt ]]; then
            local bf_count
            bf_count=$(wc -l < shuffledns_results.txt)
            log_success "Subdomains from brute force: ${bf_count} (see ${shuffledns_log})"
        elif [[ -s "$shuffledns_log" ]]; then
            log_info "ShuffleDNS: no output file produced. Last log lines:"
            tail -3 "$shuffledns_log" 2>/dev/null | sed 's/^/    /'
        else
            log_info "ShuffleDNS: no new subdomains found (no log entries captured)"
        fi
    else
        log_warn "ShuffleDNS not found, skipping brute force"
    fi

    # comm (Stage 5 below) requires BOTH inputs sorted, but shuffledns -o
    # output is in massdns discovery order — NOT sorted. Sorting it in place
    # here fixes the "comm: file 2 is not in sorted order" error.
    if [[ -s shuffledns_results.txt ]]; then
        sort -u shuffledns_results.txt -o shuffledns_results.txt || true
    fi

    # Add ShuffleDNS results to canonical DNS dataset
    [[ -s shuffledns_results.txt ]] && canonical_dns_add_sources "shuffledns" "shuffledns_results.txt" "$domain"

    # ── Stage 5: Consolidate + DNSx Delta Resolution + HTTPx Round 2 ───────
    log_info "Stage 5: Consolidate + DNSx delta resolution + HTTPx Round 2"

    # Build the full set so far (round-1 passive + brute force).
    cat all_subdomains_round1.txt shuffledns_results.txt 2>/dev/null | \
        sort -u > all_subdomains_round2.txt || true

    # Compute ONLY the newly discovered subdomains from brute force so we don't
    # re-probe the entire round-1 set with HTTPx again.
    local new_only_subs=0
    : > new_subdomains_round2.txt
    if [[ -s all_subdomains_round1.txt && -s shuffledns_results.txt ]]; then
        comm -13 all_subdomains_round1.txt shuffledns_results.txt \
            > new_subdomains_round2.txt || true
    elif [[ -s shuffledns_results.txt ]]; then
        cp shuffledns_results.txt new_subdomains_round2.txt
    fi
    [[ -s new_subdomains_round2.txt ]] && new_only_subs=$(wc -l < new_subdomains_round2.txt)
    log_success "New subdomains from brute force: $new_only_subs"

    # Resolve newly discovered hostnames through DNSx
    if [[ "$new_only_subs" -gt 0 ]]; then
        canonical_dns_resolve_pending

        # Extract resolved hostnames for HTTPx probing
        canonical_dns_extract_resolved > live_candidates_round2.txt || true

        # Probe ONLY the newly discovered subdomains that resolved
        if [[ -s new_subdomains_round2.txt ]]; then
            httpx_probe new_subdomains_round2.txt httpx_results_round2.json
        fi

        if [[ -s httpx_results_round2.json ]]; then
            jq -r '.url' httpx_results_round2.json | sort -u > new_live_subdomains_round2.txt || true
        else
            : > new_live_subdomains_round2.txt
        fi

        cat live_subdomains_round1.txt new_live_subdomains_round2.txt 2>/dev/null | \
            sort -u > live_subdomains_round2.txt || true

        # Merge JSON for downstream consumers/debugging.
        cat httpx_results_round1.json httpx_results_round2.json 2>/dev/null \
            > httpx_results_round2.json.tmp || true
        mv -f httpx_results_round2.json.tmp httpx_results_round2.json
    else
        log_info "No new subdomains from brute force — skipping HTTPx Round 2 (reusing Round 1 results)"
        cp live_subdomains_round1.txt live_subdomains_round2.txt 2>/dev/null || : > live_subdomains_round2.txt
        cp httpx_results_round1.json httpx_results_round2.json 2>/dev/null || : > httpx_results_round2.json
    fi

    # ── Stage 6: Web Crawling + JavaScript Analysis ────────────────────────
    log_info "Stage 6: Web Crawling & JavaScript Analysis"

    # Katana (replaces GoSpider)
    # Per https://github.com/projectdiscovery/katana README:
    #   -u URL       seed URL to crawl
    #   -d N         max depth (we use 3)
    #   -jc          parse endpoints from JS files (default off)
    #   -j           emit JSON Lines
    #   -timeout N   per-HTTP-request timeout (default 10s)
    #   -c N         concurrent fetchers per target
    #   -p N         concurrent input targets (1 — we iterate per-URL)
    #   -retry N     retries per failed request
    #   -rd N        per-request delay (politeness)
    #   -rl N        global rate-limit (req/s)
    #   -ct DURATION wall-clock cap for the whole crawl (s/m/h suffix)
    #   -ob -or      omit response body and raw request/response from JSONL
    #   -silent      suppress banner and progress
    if command -v katana &>/dev/null && [[ -s live_subdomains_round2.txt ]]; then
        mkdir -p katana
        : > katana/raw_output.jsonl
        local ka_tmp="katana/.perhost"
        mkdir -p "$ka_tmp"; rm -f "$ka_tmp"/*

        _katana_one_host() {
            local url="$1" tag
            tag="$(_safe_name "$url")"
            timeout "${KATANA_TIMEOUT:-600}" katana -u "$url" -d 3 -jc -j \
                -ob -or \
                -timeout 30 -c 20 -p 1 \
                -retry 2 -rd 1 -rl 10 \
                -ct "${KATANA_CRAWL_DURATION:-30m}" \
                -silent \
                < /dev/null > "${ka_tmp}/${tag}.jsonl" 2>/dev/null || true
        }

        log_info "Katana: crawling $(wc -l < live_subdomains_round2.txt) hosts (per-host cap ${KATANA_CRAWL_DURATION:-30m}, ${PARALLEL_HOSTS:-5} in parallel)..."
        bounded_parallel "${PARALLEL_HOSTS:-5}" live_subdomains_round2.txt _katana_one_host

        cat "$ka_tmp"/*.jsonl 2>/dev/null > katana/raw_output.jsonl || : > katana/raw_output.jsonl
        rm -f "$ka_tmp"/*.jsonl

        if [[ -s katana/raw_output.jsonl ]]; then
            local ka_lines ka_hosts_count
            ka_lines=$(wc -l < katana/raw_output.jsonl | tr -d ' ')
            ka_hosts_count=$(wc -l < live_subdomains_round2.txt | tr -d ' ')

            # Discovered URLs (preserve separately from hostnames)
            grep -oE 'https?://[^"'"'"' ]+' katana/raw_output.jsonl 2>/dev/null | \
                sort -u > katana/discovered_urls.txt || true

            # Discovered hosts (domain-level)
            extract_domains katana/raw_output.jsonl katana/all_domains.txt || true
            local escaped_domain="${domain//./\\.}"
            grep -E "(^|\.)${escaped_domain}$" katana/all_domains.txt | sort -u > katana/discovered_hosts.txt || true

            # JavaScript assets (from -jc flag)
            jq -r 'select(.javascript != null) | .javascript[]? | select(. != null)' katana/raw_output.jsonl 2>/dev/null | \
                sort -u > katana/javascript_assets.txt || true

            local ka_sub_count=0
            [[ -s katana/discovered_hosts.txt ]] && ka_sub_count=$(wc -l < katana/discovered_hosts.txt)
            log_success "Katana: ${ka_lines} JSON lines, ${ka_sub_count} in-scope subdomains, $(wc -l < katana/discovered_urls.txt 2>/dev/null || echo 0) URLs, $(wc -l < katana/javascript_assets.txt 2>/dev/null || echo 0) JS assets across ${ka_hosts_count} hosts"

            # Add newly discovered hosts to canonical DNS dataset
            [[ -s katana/discovered_hosts.txt ]] && canonical_dns_add_sources "katana" "katana/discovered_hosts.txt" "$domain"
        else
            local ka_hosts_count
            ka_hosts_count=$(wc -l < live_subdomains_round2.txt | tr -d ' ')
            log_info "Katana: scanned ${ka_hosts_count} seeds, no output captured"
        fi
        rm -rf "$ka_tmp"
    else
        if ! command -v katana &>/dev/null; then
            log_warn "Katana not found, skipping web crawling"
        else
            log_skip "Katana skipped (no live hosts to crawl)"
        fi
    fi

    # Subdomainizer
    # Per https://github.com/nsonaniya2010/SubDomainizer:
    #   -u URL         target URL to scan for JS-loaded subdomains
    #   -o FILE        write results to FILE
    #   -k             --nossl — disable SSL verification
    # Each per-host scan is wrapped in `timeout` so a single slow/unreachable
    # URL can't stall the whole stage for hours.
    if [[ -f /opt/tools/SubDomainizer/SubDomainizer.py ]] && [[ -s live_subdomains_round2.txt ]]; then
        mkdir -p subdomainizer
        : > subdomainizer/raw_output.txt
        : > subdomainizer/stdout.log

        _subdomainizer_one_host() {
            local url="$1"
            local out="subdomainizer/$(_safe_name "$url").txt"
            timeout "${SUBDOMAINIZER_TIMEOUT:-300}" python3 \
                /opt/tools/SubDomainizer/SubDomainizer.py \
                -u "$url" -k -o "$out" < /dev/null >> subdomainizer/stdout.log 2>&1 || true
            [[ -s "$out" ]] || rm -f "$out"
        }

        log_info "Subdomainizer: scanning $(wc -l < live_subdomains_round2.txt) hosts (${PARALLEL_HOSTS:-5} in parallel)..."
        bounded_parallel "${PARALLEL_HOSTS:-5}" live_subdomains_round2.txt _subdomainizer_one_host

        cat subdomainizer/*.txt 2>/dev/null > subdomainizer/raw_output.txt || : > subdomainizer/raw_output.txt

        if [[ -s subdomainizer/raw_output.txt ]] || [[ -s subdomainizer/stdout.log ]]; then
            local sd_hosts
            sd_hosts=$(wc -l < live_subdomains_round2.txt | tr -d ' ')
            {
                cat subdomainizer/raw_output.txt
                cat subdomainizer/stdout.log 2>/dev/null
            } > /tmp/sd_combined.txt
            extract_domains /tmp/sd_combined.txt subdomainizer/all_domains.txt
            local escaped_domain="${domain//./\\.}"
            grep -E "(^|\.)${escaped_domain}$" subdomainizer/all_domains.txt | sort -u > subdomainizer_subdomains.txt || true
            rm -f /tmp/sd_combined.txt

            # Preserve JavaScript assets separately
            if [[ -s subdomainizer/stdout.log ]]; then
                grep -oE 'https?://[^"'"'"' \)]+\.js[^"'"'"' \)]*' subdomainizer/stdout.log 2>/dev/null | \
                    sort -u > subdomainizer/javascript_assets.txt || true
            fi

            local sd_count=0
            [[ -s subdomainizer_subdomains.txt ]] && sd_count=$(wc -l < subdomainizer_subdomains.txt)
            log_success "Subdomainizer subdomains (${sd_hosts} hosts scanned): $sd_count"

            # Add newly discovered hosts to canonical DNS dataset
            [[ -s subdomainizer_subdomains.txt ]] && canonical_dns_add_sources "subdomainizer" "subdomainizer_subdomains.txt" "$domain"
        else
            local sd_hosts
            sd_hosts=$(wc -l < live_subdomains_round2.txt | tr -d ' ')
            log_info "Subdomainizer: ran on ${sd_hosts} hosts, nothing found"
        fi
    else
        log_skip "Subdomainizer skipped (tool missing or no live hosts)"
    fi

    # ── Stage 7: Final Consolidation + DNSx Delta + HTTPx Round 3 ──────────
    log_info "Stage 7: Final consolidation + DNSx delta resolution + HTTPx Round 3"

    cat \
        all_subdomains_round2.txt \
        katana/discovered_hosts.txt \
        subdomainizer_subdomains.txt \
        2>/dev/null | sort -u > all_subdomains_final.txt || true

    local total_subs=0
    [[ -s all_subdomains_final.txt ]] && total_subs=$(wc -l < all_subdomains_final.txt)
    log_success "Total unique subdomains for $domain: $total_subs"

    # Add any newly discovered subdomains from crawling to the canonical dataset
    [[ -s all_subdomains_final.txt ]] && canonical_dns_add_sources "final" "all_subdomains_final.txt" "$domain"

    # Resolve any remaining pending hostnames
    canonical_dns_resolve_pending

    # Probe ONLY the subdomains discovered since Round 2 (crawling
    # candidates that aren't already probed). Merge their live URLs with
    # the Round 2 live set.
    : > new_subdomains_final.txt
    if [[ -s all_subdomains_round2.txt ]]; then
        comm -13 all_subdomains_round2.txt all_subdomains_final.txt \
            > new_subdomains_final.txt || true
    fi
    local crawl_new=0
    [[ -s new_subdomains_final.txt ]] && crawl_new=$(wc -l < new_subdomains_final.txt)
    log_info "New subdomains since Round 2 (from crawling): $crawl_new"

    if [[ "$crawl_new" -gt 0 ]]; then
        httpx_probe new_subdomains_final.txt httpx_results_final.json
        if [[ -s httpx_results_final.json ]]; then
            jq -r '.url' httpx_results_final.json | sort -u > new_live_subdomains_final.txt || true
        else
            : > new_live_subdomains_final.txt
        fi
        cat live_subdomains_round2.txt new_live_subdomains_final.txt 2>/dev/null | \
            sort -u > live_subdomains_final.txt || true
        # Merge JSON for downstream/debug consumers.
        cat httpx_results_round2.json httpx_results_final.json 2>/dev/null \
            > httpx_results_final.json.tmp || true
        mv -f httpx_results_final.json.tmp httpx_results_final.json
    else
        log_info "No new subdomains from crawling — reusing Round 2 live results"
        cp live_subdomains_round2.txt live_subdomains_final.txt 2>/dev/null || : > live_subdomains_final.txt
        cp httpx_results_round2.json httpx_results_final.json 2>/dev/null || : > httpx_results_final.json
    fi

    local final_live=0
    [[ -s live_subdomains_final.txt ]] && final_live=$(wc -l < live_subdomains_final.txt)
    log_success "FINAL live web servers for $domain: $final_live"

    cd "$pdir" || return 1
}