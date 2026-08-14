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

run_phase3() {
    local pdir="${OUTPUT_DIR}/phase3"
    mkdir -p "$pdir"
    CURRENT_PHASE=3

    log_info "═══ PHASE 3: IP → Classification → Port Scanning ═══"

    # ── Stage 1: Extract IPs from Canonical DNS Dataset ─────────────────────
    log_info "Stage 1: Extracting IPs from canonical DNS dataset"

    # Final resolution pass — resolve any hostnames still pending
    canonical_dns_resolve_pending

    # Extract the domain→IP mapping from the canonical DNS dataset
    local dns_tsv="${OUTPUT_DIR}/canonical_dns.tsv"
    if [[ ! -s "$dns_tsv" ]]; then
        log_error "Canonical DNS dataset not found — cannot proceed with IP classification"
        return 1
    fi

    # Build domain_ip_map.txt from canonical DNS (hostname A_record)
    # The A column (field 4) contains semicolon-separated IPs.
    : > "${pdir}/domain_ip_map.txt"
    tail -n +2 "$dns_tsv" | awk -F'\t' '{
        if ($4 != "" && $7 == "resolved") {
            n = split($4, ips, ";")
            for (i = 1; i <= n; i++) {
                gsub(/^[ \t]+|[ \t]+$/, "", ips[i])
                if (ips[i] != "") printf "%s %s\n", $1, ips[i]
            }
        }
    }' > "${pdir}/domain_ip_map.txt"

    # Build all_ips.txt from the domain_ip_map (unique IPs)
    cut -d' ' -f2 "${pdir}/domain_ip_map.txt" | sort -u -V > "${pdir}/all_ips.txt"

    local ip_count=0
    [[ -s "${pdir}/all_ips.txt" ]] && ip_count=$(wc -l < "${pdir}/all_ips.txt")
    log_success "Unique IP addresses from canonical DNS: $ip_count"

    if [[ "$ip_count" -eq 0 ]]; then
        log_warn "No IPs resolved, skipping classification and port scanning"
        return 0
    fi

    # ── Stage 2: IP → ASN Lookup via whois.cymru.com ───────────────────────
    log_info "Stage 2: Looking up ASNs via whois.cymru.com"

    # Query whois.cymru.com ONCE and cache the raw response.
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
    if [[ "$PORT_SCAN" == true && -s "${pdir}/nmap_candidates.txt" ]]; then
        local nmap_count=0
        nmap_count=$(wc -l < "${pdir}/nmap_candidates.txt")
        log_info "Stage 4: Port scanning ${nmap_count} nmap candidates (non-CDN IPs)"

        if command -v nmap &>/dev/null; then
            nmap -iL "${pdir}/nmap_candidates.txt" \
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
        log_warn "No nmap candidates to port scan"
    fi

    log_success "Phase 3 complete"
}