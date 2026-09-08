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
    local dns_tsv="${CANONICAL_DNS_TSV:-${OUTPUT_DIR}/canonical_dns.tsv}"
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

    # ── Stage 1b: Reverse DNS (PTR) Lookups ───────────────────────────────
    # PTR lookups on resolved IPs can reveal hostnames not in any subdomain
    # source — internal naming, infrastructure hosts, CDN backend names.
    # dnsx -ptr -resp-only prints just the resolved PTR hostnames.
    if command -v dnsx &>/dev/null; then
        log_info "Stage 1b: Reverse DNS (PTR) lookups on ${ip_count} IPs"

        cat "${pdir}/all_ips.txt" | timeout "${DNSX_TIMEOUT:-600}" dnsx \
            -silent -ptr -resp-only \
            -r /opt/scripts/wordlists/resolvers.txt \
            -timeout 5 \
            2>/dev/null | sort -u > "${pdir}/ptr_hostnames.txt" || true

        if [[ -s "${pdir}/ptr_hostnames.txt" ]]; then
            local ptr_total ptr_in_scope_count=0
            ptr_total=$(wc -l < "${pdir}/ptr_hostnames.txt")

            # Filter to in-scope hostnames using the root-domain list.
            # canonical_dns_add_sources already does root-domain matching,
            # but we pre-filter to avoid adding thousands of unrelated PTR
            # names (e.g. google.com, cloudflare.com) to the dataset.
            local ptr_in_scope="${pdir}/ptr_in_scope.txt"
            : > "$ptr_in_scope"
            while IFS= read -r rd; do
                [[ -z "$rd" ]] && continue
                rd=$(normalize_hostname "$rd")
                [[ -z "$rd" ]] && continue
                local escaped_rd="${rd//./\\.}"
                grep -E "(^|\.)${escaped_rd}$" "${pdir}/ptr_hostnames.txt" 2>/dev/null >> "$ptr_in_scope"
            done < "$ROOT_DOMAINS_FILE"
            sort -u "$ptr_in_scope" -o "$ptr_in_scope" 2>/dev/null || true

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

    # Validate the response: cymru bulk mode answers with a "Bulk mode;"
    # banner line before the data rows. Without this check, a failed nc
    # (firewall, DNS hiccup, transient outage) leaves an empty cache that
    # silently degrades EVERY IP to classification "unknown".
    if ! grep -q "^Bulk mode" "$_cymru_cache" 2>/dev/null; then
        log_warn "ASN lookup via whois.cymru.com failed or returned no data — all IPs will classify as 'unknown'. Check network egress to whois.cymru.com:43."
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
    if [[ "$PORT_SCAN" == true && -s "${pdir}/nmap_candidates.txt" ]]; then
        local nmap_count=0
        nmap_count=$(wc -l < "${pdir}/nmap_candidates.txt")
        log_info "Stage 4: Port scanning ${nmap_count} nmap candidates (non-CDN IPs)"

        : > "${pdir}/ip_port_pairs.txt"

        # ── Stage 4a: Naabu fast port scan (top 1000 ports) ──────────────
        local naabu_found=0
        if command -v naabu &>/dev/null; then
            log_info "  Stage 4a: Naabu fast scan (top ${NAABU_TOP_PORTS:-1000} ports)"
            timeout "${NAABU_TIMEOUT:-600}" naabu \
                -list "${pdir}/nmap_candidates.txt" \
                -top-ports "${NAABU_TOP_PORTS:-1000}" \
                -silent -json \
                < /dev/null 2>/dev/null > "${pdir}/naabu_results.json" || true

            if [[ -s "${pdir}/naabu_results.json" ]]; then
                jq -r '"\(.ip):\(.port)"' "${pdir}/naabu_results.json" 2>/dev/null \
                    | sort -u > "${pdir}/naabu_ip_ports.txt" || true
                naabu_found=$(wc -l < "${pdir}/naabu_ip_ports.txt" 2>/dev/null || echo 0)
                local naabu_hosts
                naabu_hosts=$(cut -d: -f1 "${pdir}/naabu_ip_ports.txt" 2>/dev/null | sort -u | wc -l)
                log_success "  Naabu: $naabu_found open ports on $naabu_hosts hosts"
            else
                log_info "  Naabu: no open ports found"
                : > "${pdir}/naabu_ip_ports.txt"
            fi
        else
            log_warn "  naabu not available, falling back to nmap-only scan"
            : > "${pdir}/naabu_ip_ports.txt"
        fi

        # ── Stage 4b: Nmap deep scan (service/version detection) ──────────
        # -Pn skips host discovery (ICMP/ping) — metho already has valid IPs
        # from DNS. -sV does service version detection. If naabu found open
        # ports, nmap scans only those; otherwise it falls back to a fixed
        # port list.
        if command -v nmap &>/dev/null; then
            local nmap_ports=""
            if [[ "$naabu_found" -gt 0 ]]; then
                nmap_ports=$(cut -d: -f2 "${pdir}/naabu_ip_ports.txt" | sort -un | paste -sd, -)
            fi
            if [[ -z "$nmap_ports" ]]; then
                nmap_ports="21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1521,2049,3306,3389,5432,5900,5985,5986,6379,6443,8080,8443,8888,9090,9200,9443,27017"
            fi

            log_info "  Stage 4b: Nmap service detection on ${nmap_count} candidates"
            nmap -Pn -iL "${pdir}/nmap_candidates.txt" \
                -p "$nmap_ports" \
                -sV --open --min-rate 500 \
                -oG "${pdir}/port_scan_results.txt" 2>/dev/null || true

            # Parse nmap greppable output: extract IP:port pairs
            grep '/open/' "${pdir}/port_scan_results.txt" 2>/dev/null | while read -r line; do
                ip=$(echo "$line" | awk '{print $2}')
                echo "$line" | grep -oE '[0-9]+/open/tcp' | \
                    sed 's|/open/tcp||' | \
                    while read -r port; do
                        echo "${ip}:${port}"
                    done
            done | sort -u > "${pdir}/nmap_ip_ports.txt" || true

            # Merge naabu + nmap results (naabu may catch ports nmap -sV misses)
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
    elif [[ "$PORT_SCAN" != true ]]; then
        log_skip "Port scanning disabled (--no-port-scan)"
    else
        log_warn "No nmap candidates to port scan"
    fi

    log_success "Phase 3 complete"
}