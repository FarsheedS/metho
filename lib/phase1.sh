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

    # Process domains in parallel. Each domain gets its own canonical_dns.tsv
    # and httpx_metadata.tsv (set in process_domain via CANONICAL_DNS_TSV /
    # HTTPX_META_TSV exports scoped to the subshell). After all domains
    # complete, merge_per_domain_dns combines them into the global TSV that
    # Phase 2 and Phase 3 consume.
    _process_domain_wrapper() {
        process_domain "$1" "$pdir"
    }

    log_info "Processing ${domain_count} domains with ${PARALLEL_DOMAINS:-3} parallel workers..."
    bounded_parallel "${PARALLEL_DOMAINS:-3}" "$root_domains_file" _process_domain_wrapper

    # Merge all per-domain canonical DNS TSVs into the global dataset
    merge_per_domain_dns
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

    # Per-domain canonical DNS dataset. Each parallel domain gets its own
    # canonical_dns.tsv and httpx_metadata.tsv in its per-domain directory.
    # After all domains complete, merge_per_domain_dns combines them into
    # the global TSV. These exports are scoped to this subshell (via
    # bounded_parallel), so the parent shell retains the global defaults
    # for Phase 2/3.
    export CANONICAL_DNS_TSV="${ddir}/canonical_dns.tsv"
    export HTTPX_META_TSV="${ddir}/httpx_metadata.tsv"
    init_canonical_dns

    # Seed this domain's root into the per-domain canonical dataset so the
    # apex is not missed (previously done globally in run_phase1 for all
    # roots at once; now per-domain since each has its own TSV).
    printf '%s\n' "$domain" > .root_seed.txt
    canonical_dns_add_sources "root" .root_seed.txt "$domain"

    # ── Stage 1: Passive Subdomain Enumeration ──────────────────────────────
    log_info "Stage 1: Passive subdomain enumeration"

    # Subfaster (replaces Subfinder)
    if command -v subfaster &>/dev/null; then
        log_info "Running Subfaster..."
        local sf_opts=(-d "$domain" -silent -o subfaster_results.txt)
        if [[ -n "$SUBFASTER_PROVIDER_CONFIG" ]]; then
            # -all enables every source, including the API-keyed ones in the
            # provider config (binaryedge, chaos, github, virustotal, …).
            # Without -all, subfaster defaults to -fast (8 keyless sources)
            # and the configured API keys are silently unused.
            sf_opts+=(-all -provider-config "$SUBFASTER_PROVIDER_CONFIG")
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

    # GitHub-subdomains — search GitHub code for subdomain references.
    # Unique source: developers commit config files, internal URLs, and
    # hostname references that no DNS/CT/archive source indexes.
    if command -v github-subdomains &>/dev/null; then
        local gh_token="${GITHUB_TOKEN:-}"
        # If no env var, try extracting tokens from the subfaster provider-config.
        # The config may use either bare YAML list items (github: [- ghp_xxx]) or
        # the subfinder key format (github: [{token: ghp_xxx}]). grep -oE extracts
        # just the token regardless of surrounding YAML structure. The || true
        # is critical: under set -e + pipefail, a grep with no matches exits 1
        # and would kill the pipeline before the empty-check below.
        if [[ -z "$gh_token" && -n "$SUBFASTER_PROVIDER_CONFIG" && -f "$SUBFASTER_PROVIDER_CONFIG" ]]; then
            gh_token=$(grep -oE '(ghp_|github_pat_)[A-Za-z0-9_]+' "$SUBFASTER_PROVIDER_CONFIG" 2>/dev/null \
                | sort -u | paste -sd, -) || true
        fi
        if [[ -n "$gh_token" ]]; then
            log_info "Running GitHub-subdomains..."
            timeout "${GITHUB_SUBDOMAINS_TIMEOUT:-300}" github-subdomains \
                -d "$domain" -t "$gh_token" -o github_subdomains.txt \
                < /dev/null 2>/dev/null || true
            local gh_count=0
            [[ -s github_subdomains.txt ]] && gh_count=$(wc -l < github_subdomains.txt)
            log_success "GitHub-subdomains: $gh_count subdomains"
        else
            log_skip "GitHub-subdomains skipped (set GITHUB_TOKEN env var or add github tokens to provider-config)"
        fi
    else
        log_warn "github-subdomains not found, skipping GitHub subdomain discovery"
    fi

    # DNS zone transfer (AXFR) — rarely permitted on modern targets, but
    # near-zero cost to attempt and a complete zone dump when it works.
    log_info "Attempting DNS zone transfer (AXFR)..."
    : > axfr_results.txt
    printf '%s\n' "$domain" > axfr_input.txt
    timeout 30 dnsx -silent -axfr -resp-only \
        -l axfr_input.txt \
        -r /opt/scripts/wordlists/resolvers.txt \
        < /dev/null > axfr_results.txt 2>/dev/null || true
    if [[ -s axfr_results.txt ]]; then
        extract_domains axfr_results.txt axfr_all_domains.txt || true
        local escaped_domain="${domain//./\\.}"
        grep -E "(^|\.)${escaped_domain}$" axfr_all_domains.txt | sort -u > axfr_subdomains.txt || true
        local axfr_count=0
        [[ -s axfr_subdomains.txt ]] && axfr_count=$(wc -l < axfr_subdomains.txt)
        log_success "AXFR: $axfr_count in-scope subdomains from zone transfer"
    else
        log_info "AXFR: zone transfer not permitted (expected for most targets)"
    fi

    # Add all Stage 1 discoveries to the canonical DNS dataset
    [[ -s subfaster_results.txt ]] && canonical_dns_add_sources "subfaster" "subfaster_results.txt" "$domain"
    [[ -s crtname_results.txt ]] && canonical_dns_add_sources "crt.name" "crtname_results.txt" "$domain"
    [[ -s github_subdomains.txt ]] && canonical_dns_add_sources "github" "github_subdomains.txt" "$domain"
    [[ -s axfr_subdomains.txt ]] && canonical_dns_add_sources "axfr" "axfr_subdomains.txt" "$domain"

    # ── Stage 2: Historical Recon (Waymore) ─────────────────────────────────
    # Waymore operates on ROOT DOMAINS ONLY — it fetches historical URLs and
    # responses from Wayback, CommonCrawl, OTX, URLScan, VirusTotal, etc.
    log_info "Stage 2: Historical reconnaissance (Waymore)"

    if command -v waymore &>/dev/null; then
        local wm_output_dir="${ddir}/waymore_output"
        mkdir -p "$wm_output_dir"
        local wm_urls="${ddir}/waymore_urls.txt"

        log_info "Running Waymore on root domain $domain (mode ${WAYMORE_MODE:-U})..."
        # < /dev/null detaches waymore's stdin from the enclosing `while read`
        # loop (phase1.sh:28). Without it, waymore drains the loop's input
        # file and only the FIRST root domain is ever processed — the rest are
        # silently consumed as waymore's stdin. This is the same bug class that
        # katana/cewl exhibited; they already carry < /dev/null guards.
        timeout "${WAYMORE_TIMEOUT:-600}" waymore \
            -i "$domain" \
            -mode "${WAYMORE_MODE:-U}" \
            -oU "$wm_urls" \
            -oR "$wm_output_dir" \
            -t 30 -p 2 --verbose \
            < /dev/null 2>/dev/null || true

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

        # Extract resolved hostnames for HTTPx probing. Scope to THIS domain
        # (the canonical dataset holds every domain processed so far) so a host
        # resolved under an earlier domain is not re-probed here — before this
        # filter, Round 1 re-probed all prior domains' hosts each iteration
        # (O(N²) overall). Only resolved hosts are probed, never the raw
        # candidate list.
        canonical_dns_extract_resolved \
            | grep -E "(^|\.)${domain//./\\.}$" > live_candidates_round1.txt || true

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

    # Step 4b: dnsx brute force (replaces shuffledns — same wildcard detection,
    # faster, no massdns dependency). dnsx -auto-wildcard filters wildcard
    # subdomains (equivalent to shuffledns -sw). -t 500 for high throughput.
    if command -v dnsx &>/dev/null; then
        if [[ ! -s /opt/scripts/wordlists/resolvers.txt ]]; then
            log_warn "resolvers file missing or empty: /opt/scripts/wordlists/resolvers.txt — dnsx bruteforce will fail"
        fi

        log_info "Running dnsx brute force on $(wc -l < wordlists/custom_wordlist.txt) words against $domain..."

        local bruteforce_log="bruteforce.debug.log"
        : > "$bruteforce_log"
        local bruteforce_exit=0
        timeout "${BRUTEFORCE_TIMEOUT:-900}" dnsx \
            -d "$domain" \
            -w wordlists/custom_wordlist.txt \
            -r /opt/scripts/wordlists/resolvers.txt \
            -auto-wildcard \
            -duc -silent \
            -t 500 \
            -o shuffledns_results.txt \
            >> "$bruteforce_log" 2>&1 || bruteforce_exit=$?

        if [[ "$bruteforce_exit" -ne 0 ]]; then
            log_warn "dnsx bruteforce exited with code ${bruteforce_exit} — see ${bruteforce_log}"
            tail -5 "$bruteforce_log" 2>/dev/null | sed 's/^/    /'
        fi

        if [[ -s shuffledns_results.txt ]]; then
            local bf_count
            bf_count=$(wc -l < shuffledns_results.txt)
            log_success "Subdomains from brute force: ${bf_count} (see ${bruteforce_log})"
        elif [[ -s "$bruteforce_log" ]]; then
            log_info "dnsx bruteforce: no output file produced. Last log lines:"
            tail -3 "$bruteforce_log" 2>/dev/null | sed 's/^/    /'
        else
            log_info "dnsx bruteforce: no new subdomains found (no log entries captured)"
        fi
    else
        log_warn "dnsx not found, skipping brute force"
    fi

    # comm (Stage 5 below) requires BOTH inputs sorted. dnsx -o output is
    # NOT guaranteed sorted. Sorting it in place here fixes the
    # "comm: file 2 is not in sorted order" error.
    if [[ -s shuffledns_results.txt ]]; then
        sort -u shuffledns_results.txt -o shuffledns_results.txt || true
    fi

    # Add ShuffleDNS results to canonical DNS dataset
    [[ -s shuffledns_results.txt ]] && canonical_dns_add_sources "dnsx-brute" "shuffledns_results.txt" "$domain"

    # ── Stage 4b: Subdomain Permutation (dnsgen) ──────────────────────────
    # dnsgen takes discovered subdomains and generates permutations by
    # combining labels with common prefixes/suffixes and extracting words
    # from the existing subdomain names. E.g. dev.example.com → dev1,
    # dev-internal, dev-staging, qa-dev, prod-dev .example.com. The
    # permutations are then resolved with dnsx. This
    # finds subdomains that follow the target's naming patterns but appear
    # in no passive source, CT log, or archive.
    log_info "Stage 4b: Subdomain permutation (dnsgen)"

    if command -v dnsgen &>/dev/null; then
        # Build input from all subdomains discovered so far (passive + brute).
        # Keep only valid hostname characters — passive sources (esp. waymore
        # URL parsing) leak debris like "2Fapp.example.com" (URL-encoding
        # fragments) that dnsgen would treat as real labels.
        cat all_subdomains_round1.txt shuffledns_results.txt 2>/dev/null \
            | grep -E '^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$' \
            | sort -u > dnsgen_input.txt || true

        # Cap dnsgen input for large domains. dnsgen (default mode) yields
        # ~150-200 permutations per input — 5K inputs → ~885K candidates,
        # which takes hours to resolve and starves the rest of the pipeline
        # (reconftw skips permutations entirely above 500 subs for the same
        # reason). For large corpora, prefer resolved hostnames (they reveal
        # active naming patterns) and cap the rest.
        local _dnsgen_max="${DNSGEN_MAX_INPUT:-500}"
        if [[ -s dnsgen_input.txt ]]; then
            local _dnsgen_in_count
            _dnsgen_in_count=$(wc -l < dnsgen_input.txt)
            if [[ "$_dnsgen_in_count" -gt "$_dnsgen_max" ]]; then
                log_warn "  dnsgen input capped: $_dnsgen_in_count → $_dnsgen_max (resolved hosts prioritized)"
                local _tsv="${CANONICAL_DNS_TSV:-${OUTPUT_DIR}/canonical_dns.tsv}"
                # Extract resolved hostnames from canonical DNS, fall back to head
                if [[ -s "$_tsv" ]]; then
                    awk -F'\t' 'NR>1 && $7=="resolved" {print $1}' "$_tsv" 2>/dev/null \
                        | sort -u > dnsgen_input.resolved.txt
                fi
                if [[ -s dnsgen_input.resolved.txt ]]; then
                    head -n "$_dnsgen_max" dnsgen_input.resolved.txt > dnsgen_input.txt
                    rm -f dnsgen_input.resolved.txt
                else
                    head -n "$_dnsgen_max" dnsgen_input.txt > dnsgen_input.tmp
                    mv dnsgen_input.tmp dnsgen_input.txt
                fi
            fi
        fi

        if [[ -s dnsgen_input.txt ]]; then
            log_info "  Generating permutations from $(wc -l < dnsgen_input.txt) subdomains..."

            # Default mode (no -f): includes the word-insertion permutator,
            # which is where permutation value is (dev→dev-staging,
            # api→api-internal neighbors). v2's -f "fast mode" only does
            # number mutations and port suffixes — a near-no-op for domains
            # without digits/ports in their subdomains (verified on
            # mydigipay.com: fast mode → 0 permutations).
            # Volume is controlled by DNSGEN_MAX_INPUT (500) upstream and
            # this byte cap downstream (head -c cuts mid-generation, so a
            # runaway generator can't outlast DNSGEN_TIMEOUT either).
            timeout "${DNSGEN_TIMEOUT:-120}" dnsgen dnsgen_input.txt \
                < /dev/null 2>/dev/null \
                | head -c "${DNSGEN_MAX_OUTPUT_BYTES:-26214400}" \
                > dnsgen_permutations.txt || true

            # Drop a possibly-truncated last line (head -c cuts mid-line)
            [[ -s dnsgen_permutations.txt ]] && sed -i '$ d' dnsgen_permutations.txt 2>/dev/null || true

            if [[ -s dnsgen_permutations.txt ]]; then
                local perm_count
                perm_count=$(wc -l < dnsgen_permutations.txt)
                log_info "  Generated $perm_count permutation candidates, resolving..."

                # Resolve permutations using dnsx with wildcard detection.
                # dnsx -wd performs inline wildcard filtering (replaces
                # shuffledns -sw). -wt 1 = strict per-host wildcard check.
                # -t 500 = high thread count (dnsx defaults to 100; we need
                # massdns-level throughput for bulk permutation resolution).
                # Dynamic timeout: scale with permutation count so large
                # sets aren't killed prematurely.
                local _resolve_timeout
                _resolve_timeout=$(( perm_count / 100 ))
                (( _resolve_timeout < 300 )) && _resolve_timeout=300
                (( _resolve_timeout > 3600 )) && _resolve_timeout=3600

                timeout "$_resolve_timeout" dnsx \
                    -l dnsgen_permutations.txt \
                    -silent -wd "$domain" -wt 1 \
                    -r /opt/scripts/wordlists/resolvers.txt \
                    -t 500 -timeout 5 -json \
                    < /dev/null 2>/dev/null > dnsgen_results.json || true

                if [[ -s dnsgen_results.json ]]; then
                    jq -r '.host // empty' dnsgen_results.json 2>/dev/null \
                        | sort -u > dnsgen_results.txt || true
                    rm -f dnsgen_results.json
                else
                    : > dnsgen_results.txt
                    rm -f dnsgen_results.json
                fi

                if [[ -s dnsgen_results.txt ]]; then
                    local dnsgen_count
                    dnsgen_count=$(wc -l < dnsgen_results.txt)
                    log_success "dnsgen: $dnsgen_count subdomains resolved from permutations"
                else
                    log_info "dnsgen: no permutations resolved"
                    : > dnsgen_results.txt
                fi
            else
                log_info "dnsgen: no permutations generated"
                : > dnsgen_results.txt
            fi
        else
            log_info "dnsgen: no subdomains to permute"
            : > dnsgen_results.txt
        fi
    else
        log_warn "dnsgen not found, skipping subdomain permutation"
        : > dnsgen_results.txt
    fi

    # Add dnsgen results to canonical DNS dataset
    [[ -s dnsgen_results.txt ]] && canonical_dns_add_sources "dnsgen" "dnsgen_results.txt" "$domain"

    # ── Stage 5: Consolidate + DNSx Delta Resolution + HTTPx Round 2 ───────
    log_info "Stage 5: Consolidate + DNSx delta resolution + HTTPx Round 2"

    # Build the full set so far (round-1 passive + brute force + permutations).
    cat all_subdomains_round1.txt shuffledns_results.txt dnsgen_results.txt 2>/dev/null | \
        sort -u > all_subdomains_round2.txt || true

    # Compute ONLY the newly discovered subdomains from brute force + permutation
    # so we don't re-probe the entire round-1 set with HTTPx again.
    local new_only_subs=0
    : > new_subdomains_round2.txt
    if [[ -s all_subdomains_round1.txt ]]; then
        comm -13 all_subdomains_round1.txt all_subdomains_round2.txt \
            > new_subdomains_round2.txt || true
    elif [[ -s all_subdomains_round2.txt ]]; then
        cp all_subdomains_round2.txt new_subdomains_round2.txt
    fi
    [[ -s new_subdomains_round2.txt ]] && new_only_subs=$(wc -l < new_subdomains_round2.txt)
    log_success "New subdomains from brute force: $new_only_subs"

    # Resolve newly discovered hostnames through DNSx
    if [[ "$new_only_subs" -gt 0 ]]; then
        canonical_dns_resolve_pending

        # HTTPX Round 2 probes ONLY the brute-force additions that actually
        # resolved and belong to this domain. We intersect the resolved set
        # (which, globally, includes earlier domains' hosts) with this domain's
        # brute-force additions so no other-domain or unresolved label is probed.
        comm -12 \
            <(canonical_dns_extract_resolved | grep -E "(^|\.)${domain//./\\.}$" | sort -u) \
            <(sort -u new_subdomains_round2.txt) \
            > new_resolved_round2.txt || true

        if [[ -s new_resolved_round2.txt ]]; then
            httpx_probe new_resolved_round2.txt httpx_results_round2.json
        else
            log_info "Round 2: no brute-force subdomains resolved — nothing new to probe"
            : > httpx_results_round2.json
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
    # Katana and Subdomainizer crawl the same hosts but write to separate
    # directories (katana/ vs subdomainizer/) with no data dependency between
    # them. Running them in parallel saves the full Subdomainizer time (~5 min
    # per domain). canonical_dns_add_sources calls are deferred to after both
    # complete to avoid concurrent TSV writes.
    log_info "Stage 6: Web Crawling & JavaScript Analysis (Katana + Subdomainizer in parallel)"

    # ── Katana (background subshell) ──────────────────────────────────────
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
    (
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
                -ct "${KATANA_CRAWL_DURATION:-15m}" \
                -silent \
                < /dev/null > "${ka_tmp}/${tag}.jsonl" 2>/dev/null || true
        }

        log_info "Katana: crawling $(wc -l < live_subdomains_round2.txt) hosts (per-host cap ${KATANA_CRAWL_DURATION:-15m}, ${PARALLEL_HOSTS:-5} in parallel)..."
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
    ) &
    local _katana_pid=$!

    # ── Subdomainizer (background subshell) ───────────────────────────────
    # Per https://github.com/nsonaniya2010/SubDomainizer:
    #   -u URL         target URL to scan for JS-loaded subdomains
    #   -o FILE        write results to FILE
    #   -k             --nossl — disable SSL verification
    # Each per-host scan is wrapped in `timeout` so a single slow/unreachable
    # URL can't stall the whole stage for hours.
    (
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
            } > subdomainizer/.sd_combined.txt
            extract_domains subdomainizer/.sd_combined.txt subdomainizer/all_domains.txt
            local escaped_domain="${domain//./\\.}"
            grep -E "(^|\.)${escaped_domain}$" subdomainizer/all_domains.txt | sort -u > subdomainizer_subdomains.txt || true
            rm -f subdomainizer/.sd_combined.txt

            # Preserve JavaScript assets separately
            if [[ -s subdomainizer/stdout.log ]]; then
                grep -oE 'https?://[^"'"'"' \)]+\.js[^"'"'"' \)]*' subdomainizer/stdout.log 2>/dev/null | \
                    sort -u > subdomainizer/javascript_assets.txt || true
            fi

            local sd_count=0
            [[ -s subdomainizer_subdomains.txt ]] && sd_count=$(wc -l < subdomainizer_subdomains.txt)
            log_success "Subdomainizer subdomains (${sd_hosts} hosts scanned): $sd_count"
        else
            local sd_hosts
            sd_hosts=$(wc -l < live_subdomains_round2.txt | tr -d ' ')
            log_info "Subdomainizer: ran on ${sd_hosts} hosts, nothing found"
        fi
    else
        log_skip "Subdomainizer skipped (tool missing or no live hosts)"
    fi
    ) &
    local _sd_pid=$!

    # Wait for both Katana and Subdomainizer to complete
    wait "$_katana_pid" 2>/dev/null || true
    wait "$_sd_pid" 2>/dev/null || true

    # Merge results into canonical DNS (sequential — no concurrent TSV writes)
    [[ -s katana/discovered_hosts.txt ]] && canonical_dns_add_sources "katana" "katana/discovered_hosts.txt" "$domain"
    [[ -s subdomainizer_subdomains.txt ]] && canonical_dns_add_sources "subdomainizer" "subdomainizer_subdomains.txt" "$domain"

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
        # HTTPX Round 3 probes ONLY the crawler-discovered subdomains that
        # actually resolved and belong to this domain (same reasoning as Round 2:
        # the resolved set includes earlier domains' hosts; keep only this
        # domain's resolved crawl additions).
        comm -12 \
            <(canonical_dns_extract_resolved | grep -E "(^|\.)${domain//./\\.}$" | sort -u) \
            <(sort -u new_subdomains_final.txt) \
            > new_resolved_final.txt || true

        if [[ -s new_resolved_final.txt ]]; then
            httpx_probe new_resolved_final.txt httpx_results_final.json
        else
            log_info "Round 3: no crawler subdomains resolved — nothing new to probe"
            : > httpx_results_final.json
        fi
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