#!/usr/bin/env bash
# Final Consolidation: merges all phase outputs into a clean final/ directory
# and generates RECON_SUMMARY.txt

run_consolidation() {
    local fdir="${OUTPUT_DIR}/final"
    mkdir -p "$fdir"

    log_info "═══ CONSOLIDATING ALL RESULTS ═══"

    # Every glob below used to be a bare `phase1/*`. The canonical DNS merge
    # scopes itself to this run's roots (_root_domain_dirs), so a reused output
    # directory correctly kept a previous run's hosts out of canonical_dns.tsv —
    # but these four files did not, and quietly imported the whole of a stale
    # phase1/<other-root>/ into final_all_domains.txt, final_live_web_servers.txt,
    # final_httpx_metadata.json and final_waymore_urls.txt. Same filter, one
    # definition: collect the in-scope directories once.
    local -a _p1_dirs=()
    local _d
    while IFS= read -r _d; do
        [[ -n "$_d" ]] && _p1_dirs+=("$_d")
    done < <(_root_domain_dirs | sort)

    # ── All Domains (every hostname in the canonical dataset) ───────────────
    # Sourced from canonical_dns.tsv, not from the raw per-domain inventories.
    # The raw concatenation is Phase 1 ONLY: it misses everything Phase 2 and
    # Phase 3 add to the dataset (on a real run, 44 hostnames from dnsx-cloud and
    # 13 from ptr-reverse) and it is not case-normalized, so 51 of its rows were
    # the same hosts as canonical under different capitalization — a set
    # comparison against results/<root>/subdomains.txt produced 147 phantom
    # differences. It also meant this file disagreed with its own README line
    # ("Every subdomain across all root domains") and with the number
    # RECON_SUMMARY.txt reported.
    #
    # canonical_dns.tsv is the dataset every other deliverable already treats as
    # authoritative, so deriving from it makes the two agree by construction.
    if [[ -s "${OUTPUT_DIR}/canonical_dns.tsv" ]]; then
        awk -F'\t' '$1 != "hostname" && $1 != "" { print $1 }' \
            "${OUTPUT_DIR}/canonical_dns.tsv" 2>/dev/null | sort -u \
            > "${fdir}/final_all_domains.txt" || true
    fi
    local domain_total=0
    [[ -s "${fdir}/final_all_domains.txt" ]] && domain_total=$(wc -l < "${fdir}/final_all_domains.txt")

    # ── Live Web Servers ────────────────────────────────────────────────────
    # Phase 1's per-domain results plus Phase 3's late-window probe — hosts
    # that only resolved after Phase 1 finished looking, and which would
    # otherwise carry DNS records but never appear as live servers.
    local -a _live_srcs=()
    for _d in "${_p1_dirs[@]}"; do
        _live_srcs+=("${_d%/}/live_subdomains_final.txt")
    done
    _live_srcs+=("${OUTPUT_DIR}/phase3/live_hosts_late.txt")
    cat "${_live_srcs[@]}" 2>/dev/null | sort -u \
        > "${fdir}/final_live_web_servers.txt" || true
    local live_total=0
    [[ -s "${fdir}/final_live_web_servers.txt" ]] && live_total=$(wc -l < "${fdir}/final_live_web_servers.txt")

    # ── HTTPx Metadata (all JSON from all rounds) ───────────────────────────
    # Dedup by `.url`, KEEPING the RICHEST record per URL (most populated
    # fields). A host probed in multiple rounds can have sparser records (e.g.
    # a redirect captured early); scoring by populated-field count and taking
    # the max per URL avoids keeping a thin record over a rich one.
    #
    # Every round is read, not just the last. This file previously globbed only
    # httpx_results_final.json, so a host whose ONLY record came from round 1 or
    # round 2 — because round 3 was a delta and never re-probed it — was absent
    # from the metadata file while still present in httpx_metadata.tsv and in
    # final_live_web_servers.txt. Phase 3's late-window probe is included for the
    # same reason: those hosts are in the live-server list but their metadata was
    # in no consolidated file at all.
    local -a _httpx_jsons=()
    local _hd
    for _hd in "${_p1_dirs[@]}"; do
        local _j
        for _j in "${_hd}"httpx_results_round1.json "${_hd}"httpx_results_round2.json \
                  "${_hd}"httpx_results_final.json "${_hd}"httpx_results_late.json; do
            [[ -s "$_j" ]] && _httpx_jsons+=("$_j")
        done
    done
    [[ -s "${OUTPUT_DIR}/phase3/httpx_results_late.json" ]] && \
        _httpx_jsons+=("${OUTPUT_DIR}/phase3/httpx_results_late.json")

    if (( ${#_httpx_jsons[@]} == 0 )); then
        : > "${fdir}/final_httpx_metadata.json" 2>/dev/null || true
    elif cat "${_httpx_jsons[@]}" 2>/dev/null | \
        jq -s -r 'map(select(.url != null))
                  | group_by(.url)
                  | map( (map(. as $r | {rec:$r, score: ([$r | to_entries[] | select(.value != null)] | length)})
                         | sort_by(-.score) | .[0].rec) )
                  | .[]
                  | tojson' > "${fdir}/final_httpx_metadata.json" 2>/dev/null; then
        :
    else
        # Fallback: if jq/parse hiccups, keep the plain concat (no data loss).
        cat "${_httpx_jsons[@]}" 2>/dev/null \
            > "${fdir}/final_httpx_metadata.json" || true
    fi

    # ── Canonical DNS Dataset ───────────────────────────────────────────────
    if [[ -s "${OUTPUT_DIR}/canonical_dns.tsv" ]]; then
        cp "${OUTPUT_DIR}/canonical_dns.tsv" "${fdir}/canonical_dns.tsv"
        log_info "Canonical DNS dataset: $(awk -F'\t' '$1 != "hostname"' "${fdir}/canonical_dns.tsv" | wc -l) entries"
    fi

    # ── Subdomain-takeover candidates ───────────────────────────────────────
    # Runs here, on the merged dataset, because cname_only hosts from every root
    # have to be in one place before their targets can be de-duplicated — 51 of
    # them pointed at a single k8s ingress on the run this was written against.
    # Writes final/final_takeover_candidates.txt.
    canonical_dns_takeover_check
    local takeover_dangling=0 takeover_total=0
    if [[ -s "${fdir}/final_takeover_candidates.txt" ]]; then
        takeover_total=$(awk -F'\t' '$1 != "hostname"' "${fdir}/final_takeover_candidates.txt" | wc -l | tr -d '[:space:]')
        takeover_dangling=$(awk -F'\t' '$4 == "dangling"' "${fdir}/final_takeover_candidates.txt" | wc -l | tr -d '[:space:]')
    fi

    # ── HTTPX Metadata TSV (per-host CDN/tech/webserver companion) ──────────
    if [[ -s "${OUTPUT_DIR}/httpx_metadata.tsv" ]]; then
        cp "${OUTPUT_DIR}/httpx_metadata.tsv" "${fdir}/httpx_metadata.tsv"
    fi

    # ── Reserved-address audit trail ────────────────────────────────────────
    # The addresses behind every `bogon` host, with the range each one matched.
    # Copied into final/ because the log line that reports the exclusion points
    # at the dataset, and the dataset is not where anyone looks for a deliverable
    # — the audit is the only way to tell an RFC1918 leak from a CGNAT name from
    # a fake-IP VPN artefact, and working that out by hand costs a re-resolve per
    # host. Absent when no host resolved into reserved space.
    if [[ -s "${OUTPUT_DIR}/canonical_dns.tsv.bogon" ]]; then
        cp "${OUTPUT_DIR}/canonical_dns.tsv.bogon" "${fdir}/canonical_dns.tsv.bogon"
    fi

    # ── Waymore URLs ─────────────────────────────────────────────────────────
    # Merge all per-domain waymore URL outputs into one file, scoped to this
    # run's roots like every other glob here.
    local -a _waymore_srcs=()
    for _d in "${_p1_dirs[@]}"; do
        _waymore_srcs+=("${_d%/}/waymore_urls.txt")
    done
    cat "${_waymore_srcs[@]}" 2>/dev/null | sort -u > "${fdir}/final_waymore_urls.txt" || true
    local waymore_total=0
    [[ -s "${fdir}/final_waymore_urls.txt" ]] && waymore_total=$(wc -l < "${fdir}/final_waymore_urls.txt")

    # ── Katana Crawl Output (discovered URLs + JS assets) ───────────────────
    # Phase 1's katana crawl writes these per-root under phase1/<root>/katana/,
    # and nothing copied them into final/: real, complete data (244K+359K lines
    # of crawled URLs, 447 JS assets across both roots on the 2026-09-29 run)
    # sitting only in a phase-scoped directory, absent from RECON_SUMMARY and
    # from every other deliverable's home. Same aggregation as Waymore above.
    local -a _katana_url_srcs=() _katana_js_srcs=()
    for _d in "${_p1_dirs[@]}"; do
        _katana_url_srcs+=("${_d%/}/katana/discovered_urls.txt")
        _katana_js_srcs+=("${_d%/}/katana/javascript_assets.txt")
    done
    cat "${_katana_url_srcs[@]}" 2>/dev/null | sort -u > "${fdir}/final_discovered_urls.txt" || true
    cat "${_katana_js_srcs[@]}" 2>/dev/null | sort -u > "${fdir}/final_javascript_assets.txt" || true
    local katana_url_total=0 katana_js_total=0
    [[ -s "${fdir}/final_discovered_urls.txt" ]] && katana_url_total=$(wc -l < "${fdir}/final_discovered_urls.txt")
    [[ -s "${fdir}/final_javascript_assets.txt" ]] && katana_js_total=$(wc -l < "${fdir}/final_javascript_assets.txt")

    # ── Cloud Assets (Phase 2 aggregate ∪ FINAL canonical CNAME targets) ────
    # Phase 2 builds its aggregate mid-run, before Phase 3 resolves more hosts
    # (PTR, timeout recoveries), so its snapshot misses cloud CNAME targets that
    # only appear in canonical later — which results.sh then picks up per-root,
    # breaking "per-root ⊆ aggregate". Re-derive the CNAME-cloud set here from the
    # FINAL canonical and union it in, so the aggregate stays a true superset of
    # every per-root slice. Same source column ($6) and helpers results.sh uses.
    {
        cat "${OUTPUT_DIR}/phase2/final_cloud_assets.txt" 2>/dev/null
        if [[ -s "${OUTPUT_DIR}/canonical_dns.tsv" ]]; then
            awk -F'\t' '$1 != "hostname" && $6 != "" { n = split($6, a, ";"); for (i = 1; i <= n; i++) print a[i] }' \
                "${OUTPUT_DIR}/canonical_dns.tsv" 2>/dev/null \
                | _cloud_asset_normalize 2>/dev/null > "${fdir}/.cc_raw" || true
            if [[ -s "${fdir}/.cc_raw" ]]; then
                filter_cloud_domains "${fdir}/.cc_raw" "${fdir}/.cc_cloud" 2>/dev/null || true
                cat "${fdir}/.cc_cloud" 2>/dev/null || true
            fi
            rm -f "${fdir}/.cc_raw" "${fdir}/.cc_cloud"
        fi
    } | _cloud_asset_normalize 2>/dev/null | sort -u > "${fdir}/final_cloud_assets.txt" || true
    local cloud_total=0
    [[ -s "${fdir}/final_cloud_assets.txt" ]] && cloud_total=$(wc -l < "${fdir}/final_cloud_assets.txt")

    # ── Root Domains ───────────────────────────────────────────────────────
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
    cat "${OUTPUT_DIR}/phase3/all_resolved_ips.txt" 2>/dev/null | sort -u -V > "${fdir}/final_ip_addresses.txt" || true
    local ip_total=0
    [[ -s "${fdir}/final_ip_addresses.txt" ]] && ip_total=$(wc -l < "${fdir}/final_ip_addresses.txt")

    # IPv6 is reported separately rather than appended: this file is the IPv4
    # scan-target inventory, and mixing families into it would make every
    # consumer (and the next person reading it) handle two shapes. The AAAA
    # column used to be collected by the DNS layer and then never surfaced
    # anywhere, so an IPv6-only asset was invisible past httpx.
    cat "${OUTPUT_DIR}/phase3/all_ips_v6.txt" 2>/dev/null | sort -u > "${fdir}/final_ip_addresses_v6.txt" || true
    local ip_total_v6=0
    [[ -s "${fdir}/final_ip_addresses_v6.txt" ]] && ip_total_v6=$(wc -l < "${fdir}/final_ip_addresses_v6.txt" | tr -d '[:space:]')

    # ── IP Classification ───────────────────────────────────────────────────
    if [[ -s "${OUTPUT_DIR}/phase3/ip_classification.tsv" ]]; then
        cp "${OUTPUT_DIR}/phase3/ip_classification.tsv" "${fdir}/final_ip_classification.tsv"
    fi

    # ── IP:Port Pairs ───────────────────────────────────────────────────────
    cat "${OUTPUT_DIR}/phase3/ip_port_pairs.txt" 2>/dev/null | sort -u > "${fdir}/final_ip_port_pairs.txt" || true
    local port_pair_total=0
    [[ -s "${fdir}/final_ip_port_pairs.txt" ]] && port_pair_total=$(wc -l < "${fdir}/final_ip_port_pairs.txt")

    # ── CDN vs Non-CDN IPs ──────────────────────────────────────────────────
    cat "${OUTPUT_DIR}/phase3/cdn_ips.txt" 2>/dev/null | sort -u > "${fdir}/final_cdn_ips.txt" || true
    cat "${OUTPUT_DIR}/phase3/non_cdn_ips.txt" 2>/dev/null | sort -u > "${fdir}/final_non_cdn_ips.txt" || true

    # ── Nmap Candidates ────────────────────────────────────────────────────
    cat "${OUTPUT_DIR}/phase3/nmap_candidates.txt" 2>/dev/null | sort -u -V > "${fdir}/final_nmap_candidates.txt" || true

    # Ports that accepted a connection but identified no service (`tcpwrapped`).
    # Kept separate rather than dropped: on one run they were the ONLY record of
    # 1,765 port/host pairs. They are just not ranked beside a real service.
    cat "${OUTPUT_DIR}/phase3/nmap_ip_ports_tcpwrapped.txt" 2>/dev/null | sort -u > "${fdir}/final_ip_port_pairs_tcpwrapped.txt" || true

    # ── Domain→IP Mapping ──────────────────────────────────────────────────
    cat "${OUTPUT_DIR}/phase3/domain_ip_map.txt" 2>/dev/null | sort -u > "${fdir}/final_domain_ip_map.txt" || true

    # ── Classification Counts ────────────────────────────────────────────────
    local cdn_count=0 cloud_count=0 dedicated_count=0 unknown_count=0
    if [[ -s "${fdir}/final_ip_classification.tsv" ]]; then
        cdn_count=$(tail -n +2 "${fdir}/final_ip_classification.tsv" | awk -F'\t' '$2 == "cdn"' | wc -l | tr -d ' ')
        cloud_count=$(tail -n +2 "${fdir}/final_ip_classification.tsv" | awk -F'\t' '$2 == "cloud"' | wc -l | tr -d ' ')
        dedicated_count=$(tail -n +2 "${fdir}/final_ip_classification.tsv" | awk -F'\t' '$2 == "dedicated"' | wc -l | tr -d ' ')
        unknown_count=$(tail -n +2 "${fdir}/final_ip_classification.tsv" | awk -F'\t' '$2 == "unknown"' | wc -l | tr -d ' ')
    fi

    # ── Summary Report ──────────────────────────────────────────────────────
    cat > "${OUTPUT_DIR}/RECON_SUMMARY.txt" <<EOF
========================================
RECONNAISSANCE PHASE COMPLETE
========================================

Root Domains Provided: ${root_total}

ASSETS DISCOVERED:
- All Subdomains:     ${domain_total}
- Live Web Servers:   ${live_total}
- Waymore URLs:       ${waymore_total}
- Discovered URLs (katana): ${katana_url_total}
- JS Assets (katana): ${katana_js_total}
- Cloud Assets:       ${cloud_total}
- ASNs:               ${asn_total}
- Network Ranges:     ${network_total}
- IP Addresses:       ${ip_total}
- IPv6 Addresses:     ${ip_total_v6:-0} (inventory only - not port-scanned)
- IP:Port Pairs:      ${port_pair_total}
- Takeover Pairs:     ${takeover_total} (${takeover_dangling} dangling — target does not exist)

IP CLASSIFICATION:
- CDN IPs:            ${cdn_count}
- Cloud IPs:          ${cloud_count}
- Dedicated IPs:      ${dedicated_count}
- Unknown IPs:        ${unknown_count}

FILES CREATED IN final/:
- final_all_domains.txt          (all subdomains)
- final_live_web_servers.txt     (live web server URLs)
- final_httpx_metadata.json       (full httpx JSON with CDN/tech/webserver)
- httpx_metadata.tsv              (per-host HTTPX metadata companion to canonical_dns.tsv)
- canonical_dns.tsv               (canonical hostname→DNS dataset)
- final_waymore_urls.txt          (historical URLs from Waymore)
- final_discovered_urls.txt       (all URLs crawled by katana — content discovery, param/endpoint mining)
- final_javascript_assets.txt     (all JS file URLs crawled by katana — secret scanning, endpoint mining)
- final_cloud_assets.txt         (cloud assets)
- final_asn_list.txt             (ASN numbers)
- final_asn_summary.txt          (ASNs sorted by IP count)
- final_network_ranges.txt       (CIDR blocks)
- final_ip_addresses.txt         (all resolved IPv4 addresses)
- final_ip_addresses_v6.txt      (all resolved IPv6 addresses - inventory only)
- final_ip_classification.tsv   (IP classification: CDN/cloud/dedicated/unknown)
- final_ip_port_pairs.txt        (IP:port from non-CDN scan)
- final_cdn_ips.txt              (CDN-associated IPs)
- final_non_cdn_ips.txt          (non-CDN IPs)
- final_nmap_candidates.txt      (IPs targeted for port scanning)
- final_domain_ip_map.txt        (domain→IP mapping)
- final_takeover_candidates.txt  (cname_only hosts + CNAME target resolution verdict)
- canonical_dns.tsv.bogon        (reserved addresses stripped, with matched ranges — absent if none)

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