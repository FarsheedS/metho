#!/usr/bin/env bash
# Phase 3: IP Extraction, ASN Lookup, CDN Filtering, Port Scanning
# Resolves all discovered domains to IPs, maps IPs to ASNs (sorted by occurrence),
# filters out CDN ranges, and port scans non-CDN IPs.

run_phase3() {
    local pdir="${OUTPUT_DIR}/phase3"
    mkdir -p "$pdir"
    CURRENT_PHASE=3

    log_info "═══ PHASE 3: IP Extraction → ASN Mapping → Port Scanning ═══"

    local all_domains_file="${OUTPUT_DIR}/final/final_all_domains.txt"
    if [[ ! -s "$all_domains_file" ]]; then
        cat "${OUTPUT_DIR}"/phase1/*/all_subdomains_final.txt 2>/dev/null | sort -u > "$all_domains_file" || true
    fi

    if [[ ! -s "$all_domains_file" ]]; then
        log_error "No domains available for IP extraction"
        return 1
    fi

    local domain_count
    domain_count=$(wc -l < "$all_domains_file")
    log_info "Resolving IPs for ${domain_count} domains..."

    # ── Stage 1: DNS Resolution → IP Addresses ──────────────────────────────
    log_info "Stage 1: Resolving domains to IP addresses"

    : > "${pdir}/all_ips_raw.txt"
    : > "${pdir}/domain_ip_map.txt"

    # Use dnsx for fast bulk resolution if available
    if command -v dnsx &>/dev/null; then
        log_info "Using dnsx for bulk DNS resolution..."
        # timeout wraps dnsx (never `cat` — an instant command — which would
        # leave dnsx uncapped). dnsx reads the target list from the stdin
        # pipe, which is exactly what we want here.
        cat "$all_domains_file" | timeout "${DNSX_TIMEOUT:-600}" \
            dnsx -silent -a -json -retry 2 2>/dev/null \
            > "${pdir}/dnsx_resolution.json" || true

        # Domain→IP mapping and bare IPs from the dnsx JSONL.
        # (The previous jq was `.host as $host | .a[]? | "\($host) \(. "")"`
        # — `(. "")` indexes a string with an empty-string key, so jq errored
        # on EVERY record, dnsx_resolution.json came out empty, and ALL
        # resolution silently fell back to the slow serial dig loop.)
        jq -r 'select(.a != null) | .host as $h | .a[] | "\($h) \(.)"' \
            "${pdir}/dnsx_resolution.json" 2>/dev/null > "${pdir}/domain_ip_map.txt" || true
        jq -r '.a[]?' "${pdir}/dnsx_resolution.json" 2>/dev/null \
            >> "${pdir}/all_ips_raw.txt" || true

        local resolved_count=0
        [[ -s "${pdir}/domain_ip_map.txt" ]] && \
            resolved_count=$(cut -d' ' -f1 "${pdir}/domain_ip_map.txt" | sort -u | wc -l | tr -d ' ')
        log_info "dnsx resolved ${resolved_count} of ${domain_count} domains"
    else
        log_info "dnsx not available — resolving with dig only..."
    fi

    # dig fallback — ONLY for domains dnsx didn't resolve. A domain can be
    # missed by dnsx (resolver timeout, rate limit), so skipping this
    # entirely would lose data; running it over ALL domains (the old code)
    # duplicated work dnsx already did.
    local pending_file="${pdir}/.pending_resolution.txt"
    if [[ -s "${pdir}/domain_ip_map.txt" ]]; then
        cut -d' ' -f1 "${pdir}/domain_ip_map.txt" | sort -u > "${pdir}/.resolved_hosts.txt" || true
        comm -23 <(sort -u "$all_domains_file") "${pdir}/.resolved_hosts.txt" \
            > "$pending_file" || true
    else
        sort -u "$all_domains_file" > "$pending_file" || true
    fi

    local pending_count=0
    [[ -s "$pending_file" ]] && pending_count=$(wc -l < "$pending_file" | tr -d ' ')
    if [[ "$pending_count" -gt 0 ]]; then
        log_info "dig fallback for ${pending_count} unresolved domain(s)..."
        while read -r dom; do
            [[ -z "$dom" ]] && continue
            local ips
            # `|| true`: for an unresolvable domain grep exits 1 — under
            # set -e + pipefail the failing command substitution would
            # otherwise abort the ENTIRE pipeline mid-loop (verified).
            ips=$(dig +short "$dom" A 2>/dev/null | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true)
            for ip in $ips; do
                echo "$dom $ip" >> "${pdir}/domain_ip_map.txt"
                echo "$ip" >> "${pdir}/all_ips_raw.txt"
            done
        done < "$pending_file"
    fi
    rm -f "$pending_file" "${pdir}/.resolved_hosts.txt"

    sort -u "${pdir}/all_ips_raw.txt" > "${pdir}/all_ips.txt" 2>/dev/null || true
    rm -f "${pdir}/all_ips_raw.txt"

    local ip_count=0
    [[ -s "${pdir}/all_ips.txt" ]] && ip_count=$(wc -l < "${pdir}/all_ips.txt")
    log_success "Unique IP addresses resolved: $ip_count"

    if [[ "$ip_count" -eq 0 ]]; then
        log_warn "No IPs resolved, skipping ASN lookup and port scanning"
        return 0
    fi

    # ── Stage 2: IP → ASN Lookup via whois.cymru.com ────────────────────────
    log_info "Stage 2: Looking up ASNs via whois.cymru.com"

    # Query whois.cymru.com ONCE and cache the raw response. The previous code
    # issued two identical queries (one for asn_raw.txt, one for ip_asn_map.txt)
    # which doubled the network round-trips on a service that is often slow /
    # flaky. A single query + two local awk passes over the cache is faster and
    # keeps both derived views consistent (same response snapshot).
    local _cymru_cache="${pdir}/.cymru_raw.txt"
    {
        echo "begin"
        echo "verbose"
        cat "${pdir}/all_ips.txt"
        echo "end"
    } | nc whois.cymru.com 43 2>/dev/null > "$_cymru_cache" || true

    # View 1: ASN|Prefix|Name -> per-(asn,prefix) IP count.
    awk -F'|' '
    NR>1 {
        gsub(/^[ \t]+|[ \t]+$/, "", $1);
        gsub(/^[ \t]+|[ \t]+$/, "", $3);
        gsub(/^[ \t]+|[ \t]+$/, "", $7);

        asn="AS"$1
        key=asn "|" $7 "|" $3
        count[key]++
    }
    END {
        for (k in count) {
            split(k, parts, "|")
            printf "%s|%s|%s|%d\n", parts[1], parts[2], parts[3], count[k]
        }
    }' "$_cymru_cache" > "${pdir}/asn_raw.txt" || true

    # View 2: per-IP IP|ASN|Name|Prefix mapping.
    awk -F'|' '
    NR>1 {
        gsub(/^[ \t]+|[ \t]+$/, "", $1);
        gsub(/^[ \t]+|[ \t]+$/, "", $2);
        gsub(/^[ \t]+|[ \t]+$/, "", $3);
        gsub(/^[ \t]+|[ \t]+$/, "", $7);

        asn="AS"$1
        print $2 "|" asn "|" $3 "|" $7
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

    # ── Stage 3: CDN Filtering ──────────────────────────────────────────────
    log_info "Stage 3: Identifying CDN-associated IPs"

    : > "${pdir}/cdn_ips.txt"
    : > "${pdir}/non_cdn_ips.txt"

    if [[ -s "${pdir}/ip_asn_map.txt" ]]; then
        while IFS='|' read -r ip asn name prefix; do
            [[ -z "$ip" || -z "$asn" ]] && continue
            if is_cdn_asn "$asn"; then
                echo "$ip" >> "${pdir}/cdn_ips.txt"
            else
                echo "$ip" >> "${pdir}/non_cdn_ips.txt"
            fi
        done < "${pdir}/ip_asn_map.txt"
    fi

    sort -u "${pdir}/cdn_ips.txt" -o "${pdir}/cdn_ips.txt" 2>/dev/null || true
    sort -u "${pdir}/non_cdn_ips.txt" -o "${pdir}/non_cdn_ips.txt" 2>/dev/null || true

    local cdn_count=0 non_cdn_count=0
    [[ -s "${pdir}/cdn_ips.txt" ]] && cdn_count=$(wc -l < "${pdir}/cdn_ips.txt")
    [[ -s "${pdir}/non_cdn_ips.txt" ]] && non_cdn_count=$(wc -l < "${pdir}/non_cdn_ips.txt")

    log_info "CDN IPs: $cdn_count | Non-CDN IPs: $non_cdn_count"

    # ── Stage 4: Port Scan on Non-CDN IPs ───────────────────────────────────
    if [[ "$PORT_SCAN" == true && -s "${pdir}/non_cdn_ips.txt" ]]; then
        log_info "Stage 4: Port scanning ${non_cdn_count} non-CDN IPs"

        if command -v nmap &>/dev/null; then
            nmap -iL "${pdir}/non_cdn_ips.txt" \
                -p 21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1521,2049,3306,3389,5432,5900,5985,5986,6379,6443,8080,8443,8888,9090,9200,9443,27017 \
                --open --min-rate 500 \
                -oG "${pdir}/port_scan_results.txt" 2>/dev/null || true

            # Parse nmap greppable output: extract IP:port pairs
            : > "${pdir}/ip_port_pairs.txt"
            grep '/open/' "${pdir}/port_scan_results.txt" 2>/dev/null | while read -r line; do
                ip=$(echo "$line" | awk '{print $2}')
                echo "$line" | grep -oE '[0-9]+/open/tcp' | \
                    sed 's|/open/tcp||' | \
                    while read -r port; do
                        echo "${ip}:${port}"
                    done
            done | sort -u > "${pdir}/ip_port_pairs.txt" || true

            if [[ -s "${pdir}/ip_port_pairs.txt" ]]; then
                log_success "IP:Port pairs discovered: $(wc -l < "${pdir}/ip_port_pairs.txt")"
            else
                grep '/open/' "${pdir}/port_scan_results.txt" 2>/dev/null | \
                    awk '{print $2}' | sort -u > "${pdir}/non_cdn_live_ips.txt" || true
                log_warn "Detailed port parsing had issues, saved live IPs instead"
            fi
        else
            log_warn "nmap not available, skipping port scan"
        fi
    elif [[ "$PORT_SCAN" != true ]]; then
        log_skip "Port scanning disabled (--no-port-scan)"
    else
        log_warn "No non-CDN IPs to port scan"
    fi

    log_success "Phase 3 complete"
}
