#!/usr/bin/env bash
# Phase 3: IP Extraction, Deterministic Classification, and Port Scanning
#
# Uses the canonical DNS dataset (populated in Phases 1-2) as the source of
# truth for hostnames and IPs. No re-resolution of the entire corpus — only
# newly discovered hosts get resolved incrementally.
#
# Classification is deterministic:
#   1. HTTPX CDN = true        → "cdn"
#   2. ASN/provider matches CDN → "cdn"
#   3. ASN/provider matches cloud → "cloud"
#   4. ASN/provider matches dedicated → "dedicated"
#   5. Otherwise               → "unknown"
#
# Nmap candidates = dedicated + cloud + unknown (CDN excluded from scanning).

# ── Naabu sweep sizing ───────────────────────────────────────────────────────
# naabu's cost is linear in the candidate count: -rate caps packets/sec and each
# host costs about NAABU_SECONDS_PER_HOST seconds of sending. A single capped
# run therefore scans only the hosts that fit inside the cap and drops the rest,
# which is why the candidate list is swept in chunks instead. These two helpers
# are the arithmetic that decides whether a large target is covered or silently
# halved, so they live on their own and are unit-tested.

# Largest chunk of hosts whose sweep still fits the per-run cap.
_naabu_chunk_hosts() { # <cap> <base_overhead> <seconds_per_host>
    local cap="${1:-3600}" base="${2:-300}" per="${3:-2}"
    (( per < 1 )) && per=1
    local n=$(( (cap - base) / per ))
    (( n < 1 )) && n=1
    echo "$n"
}

# Build the nmap -sV port union from naabu's results. Echoes a comma-separated
# port list (empty when there is nothing corroborated enough to probe).
#
# The union is GLOBAL — one port list applied to every target — so a port that
# only ever appeared on a single odd host gets probed against the whole estate.
# On a live run 226 of 247 discovered ports appeared on exactly 2 hosts, all of
# them GCP front-end artefacts, and they filled the union end to end. Hence the
# support floor: a port must have been seen open on at least <min_hosts> hosts,
# unless it is well-known (<1024), where an open port is almost always real and
# there are few enough of them to keep unconditionally.
_nmap_port_union() { # <naabu ip:port file> [top_n] [min_hosts]
    local f="$1" n="${2:-100}" min="${3:-2}"
    [[ -s "$f" ]] || { echo ""; return 0; }
    if (( n > 0 )); then
        cut -d: -f2 "$f" | sort | uniq -c | sort -rn \
            | awk -v n="$n" -v min="$min" '($1 >= min || $2 < 1024) && c < n { print $2; c++ }' \
            | sort -un | paste -sd, -
    else
        cut -d: -f2 "$f" | sort | uniq -c | sort -rn \
            | awk -v min="$min" '($1 >= min || $2 < 1024) { print $2 }' \
            | sort -un | paste -sd, -
    fi
}

# Split nmap's greppable output into ports where a service was identified and
# ports that came back `tcpwrapped`.
#
#   _nmap_split_ports <port_scan_results.txt> <identified_out> <wrapped_out>
#
# The verdict is decided PER PORT, not per line. nmap puts every open port for a
# host on a single `Ports:` line, and 47 lines on a real run carried a genuine
# service next to wrapped ones — judging the line would have thrown the real
# service out with the wrappers (an `80 http//Amazon CloudFront httpd` sat on
# exactly such a line).
#
# `tcpwrapped` means the TCP handshake completed and then nothing answered any
# probe: a middlebox or accept-then-close, not a service. It carries no product,
# no version and no banner. On that run it was 1,836 of nmap's 1,925 findings
# (95%) and 1,765 of those existed ONLY here, so it is recorded in its own file
# rather than dropped — but it is not ranked beside a real identification.
_nmap_split_ports() {
    local src="$1" ident_out="$2" wrapped_out="$3" tmp
    tmp="$(mktemp)"
    : > "$tmp"
    # The verdict goes FIRST and the port has its whitespace stripped, because
    # the port field arrives as " 53" (the chunk before "/open/tcp" carries the
    # separator space). Printing "ip: 53" would shift every field for the
    # downstream filter, match nothing, and empty nmap_ip_ports.txt outright —
    # silently deleting every nmap finding from the port inventory.
    awk '
        /^Host:/ && /Ports:/ {
            ip = $2
            split($0, halves, "Ports:")
            n = split(halves[2], chunks, ",")
            for (i = 1; i <= n; i++) {
                split(chunks[i], f, "/")
                if (f[2] != "open") continue
                gsub(/^[ \t]+|[ \t]+$/, "", f[1])
                verdict = (f[5] == "tcpwrapped") ? "wrapped" : "identified"
                print verdict, ip ":" f[1]
            }
        }
    ' "$src" > "$tmp" 2>/dev/null || true
    awk '$1 == "identified" { print $2 }' "$tmp" | sort -u > "$ident_out"
    awk '$1 == "wrapped"    { print $2 }' "$tmp" | sort -u > "$wrapped_out"
    rm -f "$tmp"
}

# Realistic upper bound on the sweep's wall clock: hosts × ports ÷ rate, with one
# full retry round.
#
# Deliberately a DIFFERENT model from NAABU_SECONDS_PER_HOST, which is a
# conservative integer used for chunk SIZING — a smaller chunk and a tighter
# per-chunk timeout are safe, a chunk sized from an optimistic constant is not.
# Using the sizing constant for the projection inflated it ~3× and warned about
# a budget the sweep was never going to exceed: 6,501 hosts at top-100/1000 pps
# is ~650s of pure sending, or ~1,950s with every port retried.
_naabu_projected_seconds() { # <hosts> <top_ports> <rate> <retries>
    awk -v n="${1:-0}" -v p="${2:-100}" -v r="${3:-1000}" -v k="${4:-2}" '
        BEGIN { if (r < 1) r = 1; printf "%d", n * p / r * (1 + k) }'
}

# ── Build the domain→IP maps from the canonical DNS dataset ──────────────────
# Writes, under $pdir:
#   domain_ip_map.txt     hostname→IPv4  (feeds ASN lookup, classification,
#                                        naabu and nmap)
#   all_ips.txt           unique IPv4
#   domain_ip_map_v6.txt  hostname→IPv6  (inventory only — see below)
#   all_ips_v6.txt        unique IPv6
#
# IPv6 is inventoried but deliberately NOT fed to the scanners. naabu has no
# IPv6 support and nmap needs -6 with a different target syntax, so folding the
# AAAA column into all_ips.txt would break the port scan rather than extend it.
#
# Keeping the two families separate is the whole point: before this, column
# AAAA was written by the DNS layer and then read by nothing at all. An
# IPv6-only host could be `resolved`, be probed by httpx, and still be absent
# from the IP inventory, the ASN lookup and the classification that every
# downstream decision depends on — silently, because no stage complained.
#
# Built in one place because it used to be copy-pasted twice (initial build,
# and the rebuild after PTR enrichment). Two copies of an extraction rule is
# how the AAAA omission survived: a fix applied to one would leave the other.
# Echoes the IPv4 count.
_build_ip_maps() {
    local dns_tsv="$1" pdir="$2"

    awk -F'\t' '$1 == "hostname" && $2 == "root_domain" { next } {
        if ($7 != "resolved" || $4 == "") next
        n = split($4, ips, ";")
        for (i = 1; i <= n; i++) {
            gsub(/^[ \t]+|[ \t]+$/, "", ips[i])
            if (ips[i] != "") printf "%s %s\n", $1, ips[i]
        }
    }' "$dns_tsv" > "${pdir}/domain_ip_map.txt"

    awk -F'\t' '$1 == "hostname" && $2 == "root_domain" { next } {
        if ($7 != "resolved" || $5 == "") next
        n = split($5, ips, ";")
        for (i = 1; i <= n; i++) {
            gsub(/^[ \t]+|[ \t]+$/, "", ips[i])
            if (ips[i] != "") printf "%s %s\n", $1, ips[i]
        }
    }' "$dns_tsv" > "${pdir}/domain_ip_map_v6.txt"

    cut -d' ' -f2 "${pdir}/domain_ip_map.txt"    | sort -u -V > "${pdir}/all_ips.txt"
    cut -d' ' -f2 "${pdir}/domain_ip_map_v6.txt" | sort -u     > "${pdir}/all_ips_v6.txt"

    wc -l < "${pdir}/all_ips.txt" 2>/dev/null | tr -d '[:space:]'
}

run_phase3() {
    local pdir="${OUTPUT_DIR}/phase3"
    mkdir -p "$pdir"
    CURRENT_PHASE=3

    log_info "═══ PHASE 3: IP → Classification → Port Scanning ═══"

    # ── Stage 1: Extract IPs from Canonical DNS Dataset ─────────────────────
    log_info "Stage 1: Extracting IPs from canonical DNS dataset"

    # Settle the remaining "timeout" rows into "does not exist" vs "we could
    # not ask" BEFORE the retry pass. Without this the dataset cannot say
    # whether a 90%-unresolved corpus is a dead corpus or a dead transport,
    # which is the first question anyone asks after a run like that — and the
    # retry below would spend itself re-asking names that are already settled.
    #
    # Ordering matters and was previously the other way round: retry-then-
    # settle means every confirmed-dead name is queried twice (once by the
    # retry, once by the rcode pass) where once would do. Phase 1 now settles
    # before its retries too, so by this point the pile is normally small.
    canonical_dns_label_nxdomain

    # Final resolution pass — resolve any hostnames still pending, and retry
    # ones lost to transient timeouts earlier in the run (the include_timeouts
    # mode only fires if the transport has actually been answering, so a dead
    # network never triggers a pointless re-grind). Everything the rcode pass
    # confirmed is excluded, so this only touches genuinely ambiguous names —
    # SERVFAIL and the like.
    canonical_dns_resolve_pending include_timeouts

    # Extract the domain→IP mapping from the canonical DNS dataset
    local dns_tsv="${CANONICAL_DNS_TSV:-${OUTPUT_DIR}/canonical_dns.tsv}"
    if [[ ! -s "$dns_tsv" ]]; then
        log_error "Canonical DNS dataset not found — cannot proceed with IP classification"
        return 1
    fi

    # Build the domain→IP maps from the canonical DNS dataset. The input file
    # MUST be passed explicitly: an awk with no file argument reads stdin, so
    # dropping it once silently produced an empty map, zero IPs, and a run that
    # skipped classification and port scanning entirely.
    local ip_count=0
    ip_count=$(_build_ip_maps "$dns_tsv" "$pdir")
    [[ "$ip_count" =~ ^[0-9]+$ ]] || ip_count=0

    local ip_count_v6=0
    [[ -s "${pdir}/all_ips_v6.txt" ]] && ip_count_v6=$(wc -l < "${pdir}/all_ips_v6.txt" | tr -d '[:space:]')
    log_success "Unique IP addresses from canonical DNS: $ip_count (IPv4) / ${ip_count_v6:-0} (IPv6, inventory only)"
    [[ "${ip_count_v6:-0}" -gt 0 ]] && \
        log_info "  IPv6 addresses are recorded in phase3/all_ips_v6.txt and final_ip_addresses_v6.txt. They are not port-scanned: naabu has no IPv6 support and nmap would need -6."

    # Consistency check. "Zero IPs" out of a dataset that clearly holds
    # resolved hosts means the extraction is broken, not that the corpus is
    # empty — and the failure is otherwise silent, because the phase simply
    # reports success and skips classification and scanning. (It happened: an
    # awk lost its input-file argument and read stdin instead.)
    if [[ "$ip_count" -eq 0 ]]; then
        local _resolved_with_a
        _resolved_with_a=$(awk -F'\t' \
            '$1 == "hostname" && $2 == "root_domain" { next }
             $7 == "resolved" && $4 != "" { c++ } END { print c+0 }' "$dns_tsv")
        if [[ "${_resolved_with_a:-0}" -gt 0 ]]; then
            log_error "Canonical DNS holds ${_resolved_with_a} resolved host(s) with A records, but the IP extraction produced none."
            log_error "  This is an extraction bug, not an empty corpus. Skipping classification and port scanning."
            # Deliberately NOT a non-zero return: recon.sh runs this phase
            # directly, so under `set -e` that would abort the run and the user
            # would lose final consolidation too — including the DNS and live
            # host results that are perfectly good.
            return 0
        fi
        log_warn "No IPs resolved, skipping classification and port scanning"
        return 0
    fi

    # ── Stage 1b: Reverse DNS (PTR) Lookups ───────────────────────────────
    # PTR lookups on resolved IPs can reveal hostnames not in any subdomain
    # source — internal naming, infrastructure hosts, CDN backend names.
    # dnsx -ptr -resp-only prints just the resolved PTR hostnames.
    if command -v dnsx &>/dev/null; then
        log_info "Stage 1b: Reverse DNS (PTR) lookups on ${ip_count} IPs"

        # Stage 1b is a real source — it recovered 1,025 in-scope hostnames on a
        # live run — so a cap kill here must not pass as a thin reverse-DNS
        # result. Redirect first, sort after, so timeout(1)'s status survives.
        local _ptr_rc=0
        cat "${pdir}/all_ips.txt" | timeout "${DNSX_TIMEOUT}" dnsx \
            -silent -ptr -resp-only \
            -r "${RESOLVERS_FILE:-/opt/scripts/wordlists/resolvers.txt}" \
            -timeout "$(_dnsx_query_timeout)" \
            -t "$(_dnsx_threads)" \
            > "${pdir}/.ptr_raw.txt" 2>/dev/null || _ptr_rc=$?
        sort -u "${pdir}/.ptr_raw.txt" > "${pdir}/ptr_hostnames.txt" 2>/dev/null \
            || : > "${pdir}/ptr_hostnames.txt"
        rm -f "${pdir}/.ptr_raw.txt"
        if _was_capped "$_ptr_rc"; then
            _record_truncation "all" "dnsx-ptr" "hit its ${DNSX_TIMEOUT}s cap — reverse-DNS coverage is partial"
            log_warn "PTR lookups were KILLED at their ${DNSX_TIMEOUT}s cap — reverse-DNS coverage is PARTIAL"
        fi

        if [[ -s "${pdir}/ptr_hostnames.txt" ]]; then
            local ptr_total ptr_in_scope_count=0
            ptr_total=$(wc -l < "${pdir}/ptr_hostnames.txt")

            # Filter to in-scope hostnames using the root-domain list.
            # canonical_dns_add_sources already does root-domain matching,
            # but we pre-filter to avoid adding thousands of unrelated PTR
            # names (e.g. google.com, cloudflare.com) to the dataset.
            local ptr_in_scope="${pdir}/ptr_in_scope.txt"
            filter_in_scope_hostnames "${pdir}/ptr_hostnames.txt" "$ptr_in_scope"

            [[ -s "$ptr_in_scope" ]] && ptr_in_scope_count=$(wc -l < "$ptr_in_scope")
            log_success "PTR: $ptr_total hostnames from reverse DNS, $ptr_in_scope_count in-scope"

            if [[ "$ptr_in_scope_count" -gt 0 ]]; then
                canonical_dns_add_sources "ptr-reverse" "$ptr_in_scope"
                canonical_dns_resolve_pending
            fi
        else
            log_info "PTR: no hostnames discovered from reverse DNS"
        fi
    fi

    # ── Stage 1c: Rebuild IP datasets after PTR enrichment ────────────────
    # Stage 1b may have added and resolved NEW hostnames (ptr-reverse). They
    # were not in the canonical TSV when domain_ip_map.txt / all_ips.txt were
    # built at the top of this phase, so their IPs would silently miss ASN
    # lookup, classification, and port scanning. Rebuild both files from the
    # now-updated TSV so no resolved host is lost.
    if [[ -s "${pdir}/ptr_in_scope.txt" ]]; then
        # Same builder as the initial pass — see _build_ip_maps. These two call
        # sites were identical copy-pasted awk programs before, which is how the
        # AAAA omission survived: fixing one would have left the other.
        local _ip_count_before_ptr="$ip_count"
        ip_count=$(_build_ip_maps "$dns_tsv" "$pdir")
        [[ "$ip_count" =~ ^[0-9]+$ ]] || ip_count=0
        ip_count_v6=0
        [[ -s "${pdir}/all_ips_v6.txt" ]] && ip_count_v6=$(wc -l < "${pdir}/all_ips_v6.txt" | tr -d '[:space:]')
        log_info "IP dataset rebuilt after PTR enrichment: ${ip_count} unique IPs (was ${_ip_count_before_ptr})"
        if [[ "$ip_count" -eq 0 ]]; then
            log_warn "No IPs resolved, skipping classification and port scanning"
            return 0
        fi
    fi

    # ── Stage 2: IP → ASN Lookup ───────────────────────────────────────────
    # Two independent transports, because this lookup decides which IPs are
    # safe to port-scan. When it fails, every IP classifies as "unknown" and
    # the CDN/cloud exclusion stops working — in the observed run that put
    # Akamai, Imperva and Amazon S3 addresses in front of naabu and nmap.
    log_info "Stage 2: Looking up ASNs (whois.cymru.com:43, DNS fallback)"

    local _cymru_cache="${pdir}/.cymru_raw.txt"
    local _cymru_ok=0
    if _cymru_whois_lookup "${pdir}/all_ips.txt" "$_cymru_cache"; then
        _cymru_ok=1
    else
        log_warn "whois.cymru.com:43 did not answer — falling back to Team Cymru's DNS service"
        if _cymru_dns_lookup "${pdir}/all_ips.txt" "$_cymru_cache"; then
            _cymru_ok=1
            log_success "ASN data recovered over DNS ($(wc -l < "$_cymru_cache") rows)"
        fi
    fi

    # Neither transport worked. Do NOT let the pipeline walk into a port scan
    # it cannot scope: with no ASN data there is no way to tell a target's own
    # server from a shared CDN edge, so the scan is skipped instead of being
    # aimed at third-party infrastructure.
    ASN_LOOKUP_FAILED=0
    if (( _cymru_ok == 0 )); then
        ASN_LOOKUP_FAILED=1
        log_error "ASN lookup failed on BOTH transports (whois.cymru.com:43 and origin.asn.cymru.com)."
        log_error "  Every IP would classify as 'unknown', which disables the CDN/cloud exclusion."
        log_error "  Port scanning will be SKIPPED for this run rather than aimed at unscoped infrastructure."
        log_error "  All DNS, HTTP and cloud results are unaffected. Re-run Phase 3 once egress to"
        log_error "  whois.cymru.com:43 or UDP/53 resolution is available."
    fi

    # Cymru "verbose" output format (pipe-separated, with leading/trailing spaces):
    #   AS | IP | BGP-Prefix | CC | Registry | Allocated | AS Name ...
    # The AS Name field ($7..$NF) contains spaces, so we must join $7 through
    # the last field, NOT just take $7 (which would truncate to the first word).
    # Field map: $1=AS, $2=IP, $3=Prefix, $4=CC, $5=Registry, $6=Allocated, $7..=AS Name

    # View 1: per-(asn,prefix) IP count → asn_raw.txt as "ASN|Name|Prefix|count"
    awk -F'|' '
    NR>1 {
        gsub(/^[ \t]+|[ \t]+$/, "", $1);  # AS
        gsub(/^[ \t]+|[ \t]+$/, "", $3);  # BGP prefix
        # AS Name = $7 through $NF joined (it contains spaces)
        name = ""
        for (i = 7; i <= NF; i++) {
            t = $i
            gsub(/^[ \t]+|[ \t]+$/, "", t)
            name = (name == "") ? t : name " " t
        }
        asn = "AS" $1
        key = asn "|" name "|" $3
        count[key]++
    }
    END {
        for (k in count) {
            split(k, parts, "|")
            printf "%s|%s|%s|%d\n", parts[1], parts[2], parts[3], count[k]
        }
    }' "$_cymru_cache" > "${pdir}/asn_raw.txt" || true

    # View 2: per-IP mapping → ip_asn_map.txt as "IP|ASN|OrgName|Prefix"
    # OrgName is the full AS Name ($7..$NF), NOT $3 (which is the prefix).
    awk -F'|' '
    NR>1 {
        gsub(/^[ \t]+|[ \t]+$/, "", $1);  # AS
        gsub(/^[ \t]+|[ \t]+$/, "", $2);  # IP
        gsub(/^[ \t]+|[ \t]+$/, "", $3);  # BGP prefix
        # AS Name = $7 through $NF joined
        name = ""
        for (i = 7; i <= NF; i++) {
            t = $i
            gsub(/^[ \t]+|[ \t]+$/, "", t)
            name = (name == "") ? t : name " " t
        }
        asn = "AS" $1
        print $2 "|" asn "|" name "|" $3
    }' "$_cymru_cache" > "${pdir}/ip_asn_map.txt" || true

    rm -f "$_cymru_cache"

    # Build ASN summary sorted by occurrence count (descending)
    : > "${pdir}/asn_summary.txt"
    awk -F'|' '{asn=$1; name=$2; prefix=$3; count=$4} {key=asn"|"name; totals[key]+=count; prefixes[key]=prefix} END {for (k in totals) {split(k,p,"|"); printf "%s|%s|%s|%d\n", p[1], p[2], prefixes[k], totals[k]}}' \
        "${pdir}/asn_raw.txt" 2>/dev/null | \
        sort -t'|' -k4 -rn > "${pdir}/asn_summary.txt" || true

    if [[ -s "${pdir}/asn_summary.txt" ]]; then
        log_success "ASN summary:"
        head -20 "${pdir}/asn_summary.txt" | while IFS='|' read -r asn name prefix count; do
            log_info "  ${asn} | ${name} | ${prefix} | ${count} IPs"
        done
        log_info "  ... (total $(wc -l < "${pdir}/asn_summary.txt") ASNs)"
    fi

    cut -d'|' -f1 "${pdir}/asn_summary.txt" 2>/dev/null | sort -u > "${pdir}/asn_list.txt" || true
    cut -d'|' -f3 "${pdir}/asn_summary.txt" 2>/dev/null | sort -u > "${pdir}/network_ranges.txt" || true

    # ── Stage 3: Deterministic IP Classification ────────────────────────────
    log_info "Stage 3: Deterministic IP classification"

    # Load the ASN provider config (CDN/cloud/dedicated lists)
    load_asn_config || {
        log_error "Failed to load ASN provider configuration — cannot classify IPs"
        return 1
    }

    # Build the classification datasets using write_ip_datasets from lib/classify.sh
    write_ip_datasets "${pdir}/domain_ip_map.txt" "${pdir}/ip_asn_map.txt" "${pdir}"

    # ── Stage 4: Port Scan on Nmap Candidates ───────────────────────────────
    # Two-phase scanning: naabu (fast SYN scan, top 1000 ports) discovers
    # open ports quickly, then nmap -sV does service/version detection on
    # just those ports. This is wider than the old fixed 37-port nmap list
    # and faster than nmap scanning 1000 ports directly.
    if [[ "$PORT_SCAN" != true ]]; then
        log_skip "Port scanning disabled (--no-port-scan)"
    elif [[ "${ASN_LOOKUP_FAILED:-0}" == "1" ]]; then
        log_skip "Port scanning SKIPPED: ASN classification unavailable (see Stage 2) — refusing to scan IPs that may be shared CDN/cloud infrastructure"
        log_skip "  Everything else (DNS records, live hosts, cloud assets, IP inventory) is complete."
    elif [[ ! -s "${pdir}/nmap_candidates.txt" ]]; then
        log_warn "No nmap candidates to port scan"
    else
        local nmap_count=0
        nmap_count=$(wc -l < "${pdir}/nmap_candidates.txt")
        log_info "Stage 4: Port scanning ${nmap_count} nmap candidates (non-CDN IPs)"

        : > "${pdir}/ip_port_pairs.txt"

        # ── Stage 4a: Naabu fast port scan (top 1000 ports) ──────────────
        # -rate caps packets/sec (reconftw default NAABU_RATE=1000): fast
        # enough for top-1000 sweeps, throttled enough to avoid tripping
        # IPS/IDS and saturating the uplink on large candidate lists.
        local naabu_found=0
        if command -v naabu &>/dev/null; then
            # ── Chunked sweep ────────────────────────────────────────────────
            # naabu's cost is LINEAR in the candidate count: -rate caps
            # packets/sec, and each host costs about NAABU_SECONDS_PER_HOST
            # seconds of sending (top-N ports plus retries). A single capped run
            # therefore scans only the hosts that fit inside the cap and drops
            # the rest, with no record of which. Measured on a real 6,501-host
            # run: 13,302s needed against a 3,600s cap, so roughly three
            # quarters of the candidate set was never scanned — and the run
            # still finished "complete".
            #
            # Splitting the candidate list into chunks sized to fit the cap and
            # running them one after another covers the whole set inside a
            # bounded total. Chunks are SEQUENTIAL on purpose: -rate is per
            # process, so concurrent chunks would multiply the packet rate,
            # which is the one thing the rate limit exists to prevent.
            local _naabu_rate="${NAABU_RATE:-1000}"
            local _naabu_ports="${NAABU_TOP_PORTS:-100}"
            local _per_host="${NAABU_SECONDS_PER_HOST:-2}"
            local _base="${NAABU_TIMEOUT_BASE:-300}"
            local _cap="${NAABU_TIMEOUT_MAX:-3600}"

            # Largest chunk that still fits the per-run cap.
            local _chunk_hosts
            _chunk_hosts=$(_naabu_chunk_hosts "$_cap" "$_base" "$_per_host")

            local _chunks=$(( (nmap_count + _chunk_hosts - 1) / _chunk_hosts ))
            local _projected
            _projected=$(_naabu_projected_seconds "$nmap_count" "$_naabu_ports" "$_naabu_rate" "${NAABU_RETRIES:-2}")
            # Whole-sweep budget. Defaults to 4× the per-run cap, which covers
            # this size of target outright; past it the sweep stops and says so
            # rather than running unbounded. 0 disables the ceiling.
            local _total_budget="${NAABU_TOTAL_TIMEOUT_MAX:-0}"
            (( _total_budget <= 0 )) && _total_budget=$(( _cap * 4 ))

            log_info "  Stage 4a: Naabu fast scan (top ${_naabu_ports} ports, rate ${_naabu_rate} pps)"
            log_info "    ${nmap_count} hosts → ${_chunks} chunk(s) of ≤${_chunk_hosts}, projected ~${_projected}s, sweep budget ${_total_budget}s"
            (( _projected > _total_budget )) && \
                log_warn "    projected ${_projected}s exceeds the ${_total_budget}s sweep budget — raise NAABU_TOTAL_TIMEOUT_MAX, raise NAABU_RATE, or lower NAABU_TOP_PORTS to cover everything"

            : > "${pdir}/naabu_results.json"
            : > "${pdir}/naabu_scanned_hosts.txt"
            local _chunkdir="${pdir}/.naabu_chunks"
            rm -rf "$_chunkdir"; mkdir -p "$_chunkdir"
            # Guarded, and `-a 6`. Unguarded, a split failure aborts Phase 3 —
            # and under `set -euo pipefail` the whole run — with no truncation
            # recorded, i.e. precisely the silent partial-coverage outcome this
            # block exists to prevent. `-a 4` runs out of suffixes at 10,000
            # chunks, which is reachable with a small NAABU_TIMEOUT_MAX or a
            # large NAABU_SECONDS_PER_HOST. On failure, fall back to a single
            # chunk holding every candidate: that is the pre-chunking behaviour
            # (one capped sweep), worse coverage but never none.
            if ! split -l "$_chunk_hosts" -d -a 6 "${pdir}/nmap_candidates.txt" "${_chunkdir}/chunk."; then
                log_warn "  Naabu: could not split ${nmap_count} candidates into chunks — falling back to a single capped sweep"
                cp "${pdir}/nmap_candidates.txt" "${_chunkdir}/chunk.000000" 2>/dev/null || true
                _record_truncation "all" "naabu-sweep" "chunking failed, single capped sweep over ${nmap_count} hosts"
            fi

            local _started_at _scanned=0 _chunk_no=0 _naabu_truncated=0 _rc
            _started_at=$(date +%s)

            local _chunk _actual _this_cap _remaining
            for _chunk in "${_chunkdir}"/chunk.*; do
                [[ -s "$_chunk" ]] || continue
                _remaining=$(( _total_budget - ( $(date +%s) - _started_at ) ))
                if (( _remaining <= _base )); then
                    _naabu_truncated=1
                    break
                fi
                _chunk_no=$(( _chunk_no + 1 ))
                _actual=$(wc -l < "$_chunk" 2>/dev/null | tr -d '[:space:]')
                [[ "$_actual" =~ ^[0-9]+$ ]] || _actual=0

                # An explicit NAABU_TIMEOUT pins the per-chunk cap; otherwise it
                # scales with THIS chunk's host count, bounded by the cap.
                _this_cap=$(_scaled_scan_cap "$_actual" "$_base" "$_per_host" "$_cap")
                [[ "${NAABU_TIMEOUT:-0}" -gt 0 ]] && _this_cap="${NAABU_TIMEOUT}"
                (( _remaining < _this_cap )) && _this_cap="$_remaining"

                _rc=0
                timeout "$_this_cap" naabu \
                    -list "$_chunk" \
                    -top-ports "$_naabu_ports" \
                    -rate "$_naabu_rate" \
                    -retries "${NAABU_RETRIES:-2}" \
                    -silent -json \
                    < /dev/null 2>/dev/null >> "${pdir}/naabu_results.json" || _rc=$?

                # timeout(1) exits 124 when it had to kill the child, so a
                # truncated chunk is DETECTED rather than merely predicted.
                if (( _rc == 124 )); then
                    _naabu_truncated=1
                    log_warn "    chunk ${_chunk_no}/${_chunks}: hit its ${_this_cap}s cap and was killed — ${_actual} host(s) left unscanned"
                    break
                fi
                if (( _rc != 0 )); then
                    # A chunk that CRASHED did not necessarily scan its hosts, so
                    # it must not be counted as covered. Counting it would
                    # under-report an incomplete sweep — the same lie, one level
                    # down, that this whole block exists to remove.
                    _naabu_truncated=1
                    log_warn "    chunk ${_chunk_no}/${_chunks}: naabu exited ${_rc} — its ${_actual} host(s) are NOT counted as scanned (partial results kept)"
                    break
                fi

                cat "$_chunk" >> "${pdir}/naabu_scanned_hosts.txt" 2>/dev/null || true
                _scanned=$(( _scanned + _actual ))
                log_info "    chunk ${_chunk_no}/${_chunks}: ${_scanned}/${nmap_count} hosts scanned"
            done
            rm -rf "$_chunkdir"
            sort -u "${pdir}/naabu_scanned_hosts.txt" -o "${pdir}/naabu_scanned_hosts.txt" 2>/dev/null || true

            # Durable record of an incomplete sweep, so the run summary cannot
            # report a partial port scan as a finished one.
            if (( _naabu_truncated )); then
                local _unscanned=$(( nmap_count - _scanned ))
                (( _unscanned < 0 )) && _unscanned=0
                log_warn "  Naabu: sweep INCOMPLETE — ${_scanned}/${nmap_count} hosts scanned, ${_unscanned} unscanned"
                log_warn "    Scanned hosts: ${pdir}/naabu_scanned_hosts.txt"
                _record_truncation "all" "naabu-sweep" "${_scanned}/${nmap_count} hosts scanned"
            fi

            if [[ -s "${pdir}/naabu_results.json" ]]; then
                # -R with fromjson?: every chunk appends JSONL to this one file,
                # so a chunk killed mid-write can leave a partial last line.
                # Plain `jq -r` aborts ON that line and silently drops every
                # later chunk's ports from the inventory.
                jq -Rr 'fromjson? | "\(.ip):\(.port)"' "${pdir}/naabu_results.json" 2>/dev/null \
                    | sort -u > "${pdir}/naabu_ip_ports.txt" || true
                naabu_found=$(wc -l < "${pdir}/naabu_ip_ports.txt" 2>/dev/null | tr -d '[:space:]')
                naabu_found=${naabu_found:-0}
                local naabu_hosts
                naabu_hosts=$(cut -d: -f1 "${pdir}/naabu_ip_ports.txt" 2>/dev/null | sort -u | wc -l | tr -d '[:space:]')
                log_success "  Naabu: $naabu_found open ports on ${naabu_hosts:-0} hosts (of ${_scanned}/${nmap_count} scanned)"
            else
                log_info "  Naabu: no open ports found"
                : > "${pdir}/naabu_ip_ports.txt"
            fi
        else
            log_warn "  naabu not available, falling back to nmap-only scan"
            : > "${pdir}/naabu_ip_ports.txt"
        fi

        # ── Stage 4b: Nmap deep scan (service/version detection) ──────────
        # Two-scan strategy (mirrors reconftw's PORTSCAN_STRATEGY=naabu_nmap):
        # naabu already swept ALL candidates on top-1000 ports (Stage 4a), so
        # -sV service detection only needs to touch the hosts naabu found
        # open. Scanning all candidates again with -sV re-probes ~99% hosts
        # with nothing open — the dominant cost of the old approach.
        #   -Pn              skip ping discovery (IPs already validated via DNS)
        #   -n               skip reverse DNS (metho already knows hostnames)
        #   --max-retries 2  cap retransmits (reconftw default)
        #   --min-hostgroup/--min-parallelism  batch hosts in parallel
        # If naabu found nothing (or is absent), fall back to the fixed port
        # list over all candidates — keeps coverage when Stage 4a failed.
        if command -v nmap &>/dev/null; then
            local nmap_ports="" nmap_targets="${pdir}/nmap_candidates.txt"
            if [[ "$naabu_found" -gt 0 ]]; then
                # Cap -sV to the top-N most-common open ports (ports open on the
                # most hosts) to stop the port union from ballooning into a
                # ~1000-port × N-host scan. naabu's full per-host results are
                # still merged into ip_port_pairs below, so no port is lost from
                # the inventory — only version detection is bounded.
                # Build the -sV port union from CORROBORATED ports only.
                #
                # The union is global — one port list applied to every target —
                # so a port seen on a single odd host gets probed across the
                # whole estate. NMAP_MIN_PORT_HOSTS is that floor; well-known
                # ports (<1024) are exempt, because there are few of them and an
                # open one is almost always real.
                #
                # The floor is the SECOND line of defence, not the first. On a
                # real run 226 of 247 ports appeared on exactly 2 hosts — GCP
                # front-end artefacts — and a floor of 2 does not exclude those.
                # What removes them is NMAP_INCLUDE_CLOUD=0 (lib/classify.sh):
                # every host that answered on more than 5 ports was a Google
                # Cloud address, so excluding cloud removes the population, and
                # with it the ports. Raise this floor to 3 only if artefact
                # ports start surviving that exclusion — it costs real ports on
                # redundant pairs (two mail servers on 587, say).
                nmap_ports=$(_nmap_port_union "${pdir}/naabu_ip_ports.txt" \
                    "${NMAP_TOP_PORTS:-100}" "${NMAP_MIN_PORT_HOSTS:-2}")
                # Target list = only hosts with naabu-confirmed open ports
                cut -d: -f1 "${pdir}/naabu_ip_ports.txt" | sort -u > "${pdir}/nmap_target_hosts.txt"
                if [[ -s "${pdir}/nmap_target_hosts.txt" ]]; then
                    nmap_targets="${pdir}/nmap_target_hosts.txt"
                fi
            fi
            if [[ -z "$nmap_ports" ]]; then
                nmap_ports="21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1521,2049,3306,3389,5432,5900,5985,5986,6379,6443,8080,8443,8888,9090,9200,9443,27017"
                nmap_targets="${pdir}/nmap_candidates.txt"
            fi

            local _nmap_target_count _nmap_port_count
            _nmap_target_count=$(wc -l < "$nmap_targets" | tr -d '[:space:]')
            _nmap_port_count=$(printf '%s' "$nmap_ports" | tr ',' '\n' | grep -c . || true)
            log_info "  Stage 4b: Nmap -sV on ${_nmap_target_count} hosts × ${_nmap_port_count} ports (cap: top ${NMAP_TOP_PORTS:-100})"

            # Bound it, and DETECT the bound being hit. nmap -sV costs far more
            # per host than naabu's SYN sweep, and the fallback path above hands
            # it every candidate when naabu found nothing — so an unbounded call
            # can outlast the entire phase and still leave output that reads as
            # a finished scan. A killed nmap keeps whatever it greppably wrote,
            # which is worth having, but it has to be reported as partial.
            local _nmap_cap _nmap_rc
            _nmap_cap=$(_scaled_scan_cap "$_nmap_target_count" \
                "${NMAP_TIMEOUT_BASE:-60}" "${NMAP_SECONDS_PER_HOST:-30}" "${NMAP_TIMEOUT_MAX:-3600}")
            _nmap_rc=0
            timeout "$_nmap_cap" nmap -Pn -n -iL "$nmap_targets" \
                -p "$nmap_ports" \
                -sV --open --max-retries 2 \
                --min-hostgroup 64 --min-parallelism 16 \
                -oG "${pdir}/port_scan_results.txt" 2>/dev/null || _nmap_rc=$?
            if (( _nmap_rc == 124 )); then
                log_warn "  Nmap: hit its ${_nmap_cap}s cap over ${_nmap_target_count} hosts and was killed — version detection is PARTIAL (completed results kept)"
                _record_truncation "all" "nmap-sv" "killed at ${_nmap_cap}s over ${_nmap_target_count} hosts"
            elif (( _nmap_rc != 0 )); then
                log_warn "  Nmap exited ${_nmap_rc} — results may be incomplete (${pdir}/port_scan_results.txt)"
            fi

            # Parse nmap's greppable output, splitting identified services from
            # `tcpwrapped` handshakes. See _nmap_split_ports for why the verdict
            # is per port and why the wrapped half is side-lined rather than
            # dropped. The raw greppable output is untouched either way.
            _nmap_split_ports "${pdir}/port_scan_results.txt" \
                "${pdir}/nmap_ip_ports.txt" "${pdir}/nmap_ip_ports_tcpwrapped.txt"

            local _nmap_ident _nmap_wrapped
            _nmap_ident=$(wc -l < "${pdir}/nmap_ip_ports.txt" 2>/dev/null | tr -d '[:space:]')
            _nmap_wrapped=$(wc -l < "${pdir}/nmap_ip_ports_tcpwrapped.txt" 2>/dev/null | tr -d '[:space:]')
            log_info "  Nmap service detection: ${_nmap_ident:-0} identifiable, ${_nmap_wrapped:-0} tcpwrapped (handshake only, no service)"
            log_info "    tcpwrapped pairs are kept in phase3/nmap_ip_ports_tcpwrapped.txt, out of the port inventory"

            # Merge naabu + nmap's IDENTIFIED results (naabu may catch ports
            # nmap -sV misses, and a port naabu saw open stays in the inventory
            # even if nmap could not identify a service on it).
            cat "${pdir}/naabu_ip_ports.txt" "${pdir}/nmap_ip_ports.txt" 2>/dev/null \
                | sort -u > "${pdir}/ip_port_pairs.txt" || true
        else
            log_warn "  nmap not available, using naabu results only"
            cp "${pdir}/naabu_ip_ports.txt" "${pdir}/ip_port_pairs.txt" 2>/dev/null || true
        fi

        if [[ -s "${pdir}/ip_port_pairs.txt" ]]; then
            log_success "IP:Port pairs discovered: $(wc -l < "${pdir}/ip_port_pairs.txt")"
        else
            log_warn "No open ports found"
        fi
    fi

    # Late-window hostnames: anything that resolved AFTER Phase 1's HTTPX
    # rounds never got probed. Phase 1 is the only stage that runs httpx, so a
    # host resolved in Phase 2 or in this phase's final resolution pass stayed
    # invisible — 172 real hosts on one target were port-scanned here without
    # anyone ever checking whether they serve HTTP.
    _probe_late_resolved_hosts

    log_success "Phase 3 complete"
}

# ── Probe hostnames that resolved after Phase 1 stopped looking ────────────────
# Phase 1 runs httpx three times, all before Phase 2 and Phase 3 do their own
# resolution passes. Everything those later passes recovered was left with DNS
# records and no HTTP metadata, so it never reached final_live_web_servers.txt.
# This closes that gap without re-probing anything already known.
_probe_late_resolved_hosts() {
    local pdir="${OUTPUT_DIR}/phase3"
    local dns_tsv="${CANONICAL_DNS_TSV:-${OUTPUT_DIR}/canonical_dns.tsv}"
    local meta_tsv="${HTTPX_META_TSV:-${OUTPUT_DIR}/httpx_metadata.tsv}"
    local pending="${pdir}/.late_probe.txt"

    [[ -s "$dns_tsv" ]] || return 0
    command -v httpx &>/dev/null || return 0

    # Resolved hosts that have never been probed.
    #
    # "Already probed" means the probe LEDGER — every hostname handed to httpx,
    # whether or not it answered — NOT httpx_metadata.tsv. The metadata TSV
    # holds responders only, so diffing against it made every host that was
    # probed and stayed silent look unprobed. On a real run that re-probed 7,905
    # targets, roughly 64% of a 47-minute round, for zero new information: a
    # host that did not answer once does not answer on a second identical
    # request. It also re-inflated the per-domain rate budget for work that had
    # already been done.
    #
    # The metadata TSV is still unioned in: hosts it knows about were certainly
    # probed, and that keeps an output directory produced before the ledger
    # existed (a resumed run) from losing that knowledge.
    httpx_ledger_read > "${pending}.probed"
    if [[ -s "$meta_tsv" ]]; then
        cut -f1 "$meta_tsv" | sort -u >> "${pending}.probed"
        sort -u "${pending}.probed" -o "${pending}.probed"
    fi
    # `resolved`, plus `bogon` when METHO_PROBE_RESERVED is set — the same rule as
    # canonical_dns_extract_probeable, spelled out here because this needs the
    # global TSV path rather than whatever CANONICAL_DNS_TSV points at.
    awk -F'\t' -v probe_reserved="${METHO_PROBE_RESERVED:-0}" '
        $1 == "hostname" && $2 == "root_domain" { next }
        $7 == "resolved" { print $1; next }
        probe_reserved == "1" && $7 == "bogon" { print $1 }
    ' "$dns_tsv" | sort -u > "${pending}.resolved"
    comm -23 "${pending}.resolved" "${pending}.probed" > "$pending" || true

    local n=0
    [[ -s "$pending" ]] && n=$(wc -l < "$pending")
    rm -f "${pending}.resolved" "${pending}.probed"
    if (( n == 0 )); then
        rm -f "$pending"
        return 0
    fi

    log_info "Stage 5: Probing ${n} hostname(s) that resolved after Phase 1's HTTPX rounds"
    httpx_probe "$pending" "${pdir}/httpx_results_late.json"
    if [[ -s "${pdir}/httpx_results_late.json" ]]; then
        jq -r '.url' "${pdir}/httpx_results_late.json" 2>/dev/null | sort -u \
            > "${pdir}/live_hosts_late.txt" || : > "${pdir}/live_hosts_late.txt"
        log_success "Late-window live hosts: $(wc -l < "${pdir}/live_hosts_late.txt") of ${n}"
    else
        : > "${pdir}/live_hosts_late.txt"
        log_info "Late-window probe: none of the ${n} newly resolved hostname(s) answered HTTP"
    fi
    rm -f "$pending"
}