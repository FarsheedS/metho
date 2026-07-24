#!/usr/bin/env bash
# Final Consolidation: merges all phase outputs into a clean final/ directory
# and generates RECON_SUMMARY.txt

run_consolidation() {
    local fdir="${OUTPUT_DIR}/final"
    mkdir -p "$fdir"

    log_info "═══ CONSOLIDATING ALL RESULTS ═══"

    # ── All Domains (all subdomains from Phase 1) ───────────────────────────
    cat "${OUTPUT_DIR}"/phase1/*/all_subdomains_final.txt 2>/dev/null | sort -u > "${fdir}/final_all_domains.txt" || true
    local domain_total=0
    [[ -s "${fdir}/final_all_domains.txt" ]] && domain_total=$(wc -l < "${fdir}/final_all_domains.txt")

    # ── Live Web Servers ────────────────────────────────────────────────────
    cat "${OUTPUT_DIR}"/phase1/*/live_subdomains_final.txt 2>/dev/null | sort -u > "${fdir}/final_live_web_servers.txt" || true
    local live_total=0
    [[ -s "${fdir}/final_live_web_servers.txt" ]] && live_total=$(wc -l < "${fdir}/final_live_web_servers.txt")

    # ── HTTPx Metadata (all JSON from all rounds) ───────────────────────────
    # Dedup by the `.url` field (one metadata record per live host). The old
    # `cat | sort -u` deduped only whole lines, so two records for the same
    # host that differed in any byte (timestamp, hash) both survived. Prefixing
    # each line with `.url` and unique-sorting on just that column keeps exactly
    # one record per URL, stream-safe (jq processes line by line, no slurp).
    if cat "${OUTPUT_DIR}"/phase1/*/httpx_results_final.json 2>/dev/null | \
        jq -r '(.url // empty) + "\t" + tojson' 2>/dev/null | \
        sort -u -t$'\t' -k1,1 | cut -f2- > "${fdir}/final_httpx_metadata.json" 2>/dev/null; then
        :
    else
        # Fallback: if jq/parse hiccups, keep the plain concat (no data loss).
        cat "${OUTPUT_DIR}"/phase1/*/httpx_results_final.json 2>/dev/null \
            > "${fdir}/final_httpx_metadata.json" || true
    fi

    # ── Cloud Assets (from Phase 2) ─────────────────────────────────────────
    cat "${OUTPUT_DIR}/phase2/final_cloud_assets.txt" 2>/dev/null | sort -u > "${fdir}/final_cloud_assets.txt" || true
    local cloud_total=0
    [[ -s "${fdir}/final_cloud_assets.txt" ]] && cloud_total=$(wc -l < "${fdir}/final_cloud_assets.txt")

    # ── Root Domains ────────────────────────────────────────────────────────
    local root_total=0
    local root_file="${OUTPUT_DIR}/root_domains.txt"
    [[ -s "$root_file" ]] && root_total=$(wc -l < "$root_file")

    # ── ASNs (from Phase 3) ─────────────────────────────────────────────────
    cat "${OUTPUT_DIR}/phase3/asn_list.txt" 2>/dev/null | sort -u > "${fdir}/final_asn_list.txt" || true
    local asn_total=0
    [[ -s "${fdir}/final_asn_list.txt" ]] && asn_total=$(wc -l < "${fdir}/final_asn_list.txt")

    # ── ASN Summary (sorted by occurrence) ──────────────────────────────────
    cat "${OUTPUT_DIR}/phase3/asn_summary.txt" 2>/dev/null > "${fdir}/final_asn_summary.txt" || true

    # ── Network Ranges ──────────────────────────────────────────────────────
    cat "${OUTPUT_DIR}/phase3/network_ranges.txt" 2>/dev/null | sort -u > "${fdir}/final_network_ranges.txt" || true
    local network_total=0
    [[ -s "${fdir}/final_network_ranges.txt" ]] && network_total=$(wc -l < "${fdir}/final_network_ranges.txt")

    # ── IP Addresses ────────────────────────────────────────────────────────
    cat "${OUTPUT_DIR}/phase3/all_ips.txt" 2>/dev/null | sort -u -V > "${fdir}/final_ip_addresses.txt" || true
    local ip_total=0
    [[ -s "${fdir}/final_ip_addresses.txt" ]] && ip_total=$(wc -l < "${fdir}/final_ip_addresses.txt")

    # ── IP:Port Pairs ───────────────────────────────────────────────────────
    cat "${OUTPUT_DIR}/phase3/ip_port_pairs.txt" 2>/dev/null | sort -u > "${fdir}/final_ip_port_pairs.txt" || true
    local port_pair_total=0
    [[ -s "${fdir}/final_ip_port_pairs.txt" ]] && port_pair_total=$(wc -l < "${fdir}/final_ip_port_pairs.txt")

    # ── CDN vs Non-CDN IPs ──────────────────────────────────────────────────
    cat "${OUTPUT_DIR}/phase3/cdn_ips.txt" 2>/dev/null | sort -u > "${fdir}/final_cdn_ips.txt" || true
    cat "${OUTPUT_DIR}/phase3/non_cdn_ips.txt" 2>/dev/null | sort -u > "${fdir}/final_non_cdn_ips.txt" || true

    # ── Domain→IP Mapping ───────────────────────────────────────────────────
    cat "${OUTPUT_DIR}/phase3/domain_ip_map.txt" 2>/dev/null | sort -u > "${fdir}/final_domain_ip_map.txt" || true

    # ── Summary Report ──────────────────────────────────────────────────────
    cat > "${OUTPUT_DIR}/RECON_SUMMARY.txt" <<EOF
========================================
RECONNAISSANCE PHASE COMPLETE
========================================

Root Domains Provided: ${root_total}

ASSETS DISCOVERED:
- All Subdomains:     ${domain_total}
- Live Web Servers:   ${live_total}
- Cloud Assets:       ${cloud_total}
- ASNs:               ${asn_total}
- Network Ranges:     ${network_total}
- IP Addresses:       ${ip_total}
- IP:Port Pairs:      ${port_pair_total}

FILES CREATED IN final/:
- final_all_domains.txt          (all subdomains)
- final_live_web_servers.txt     (live web server URLs)
- final_httpx_metadata.json      (full httpx JSON output)
- final_cloud_assets.txt         (cloud assets)
- final_asn_list.txt             (ASN numbers)
- final_asn_summary.txt          (ASNs sorted by IP count)
- final_network_ranges.txt       (CIDR blocks)
- final_ip_addresses.txt         (all resolved IPs)
- final_ip_port_pairs.txt        (IP:port from non-CDN scan)
- final_cdn_ips.txt              (CDN-associated IPs)
- final_non_cdn_ips.txt          (non-CDN IPs)
- final_domain_ip_map.txt        (domain→IP mapping)

LOG FILE:
- recon.log                      (timestamped log of all stages)

NEXT STEPS:
Proceed to vulnerability scanning / enumeration on live web servers.

========================================
EOF

    log_success "Summary report written to RECON_SUMMARY.txt"
    echo ""
    cat "${OUTPUT_DIR}/RECON_SUMMARY.txt"
}
