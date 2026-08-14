#!/usr/bin/env bash
# Phase 2: Cloud Asset Discovery
# Discovers AWS, Azure, and GCP assets associated with root domains.

run_phase2() {
    local pdir="${OUTPUT_DIR}/phase2"
    mkdir -p "$pdir"
    CURRENT_PHASE=2

    local root_domains_file="$1"
    local all_subdomains_file="$2"
    local live_web_file="$3"

    log_info "═══ PHASE 2: Cloud Asset Discovery ═══"

    # ── Stage 1: DNSx for Cloud Domains ─────────────────────────────────────
    # Per https://github.com/projectdiscovery/dnsx README: dnsx is a
    # multi-purpose DNS toolkit. Here we use it to bulk-resolve every
    # subdomain Phase 1 found against A/AAAA/CNAME/MX/NS/TXT/PTR/SRV
    # records. Cloud assets leak through CNAME chains to
    # *.cloudfront.net, *.amazonaws.com, etc., and through TXT/MX
    # records pointing to cloud-hosted email / verification services —
    # these would never be discovered by a simple A-record lookup.
    #
    # Flags (verified against the dnsx README):
    #   -a -aaaa -cname -mx -ns -txt -ptr -srv  record types to query
    #   -re        display full DNS response (not just the answer field)
    #   -json      NDJSON output (NOT -j; -j is also accepted as alias)
    #   -retry N   retries per host before giving up (default 2)
    #   -r FILE    resolver list — file or comma-separated IPs.
    #   -timeout N DNS query timeout in seconds (default 3)
    #
    # Wrapped in `timeout` so a stuck resolver can't hang the phase
    # forever; DNSX_TIMEOUT default 600s.
    if command -v dnsx &>/dev/null && [[ -s "$all_subdomains_file" ]]; then
        log_info "Stage 1: DNSx for cloud domains"
        local dnsx_start=$(_now)
        local dnsx_log="${pdir}/dnsx.stderr.log"
        : > "$dnsx_log"

        cat "$all_subdomains_file" \
            | timeout "${DNSX_TIMEOUT:-600}" dnsx -a -aaaa -cname -mx -ns -txt -ptr -srv \
                -re -json -retry 3 \
                -r /opt/scripts/wordlists/resolvers.txt \
                -timeout 5 \
                2>>"$dnsx_log" \
            | tee "${pdir}/dnsx_output.json" >/dev/null || \
                log_warn "DNSx exited non-zero (or was killed by DNSX_TIMEOUT) — see ${dnsx_log}"

        if [[ -s "${pdir}/dnsx_output.json" ]]; then
            jq -r '.cname[]?, .a[]?, .aaaa[]?, .mx[]?, .ns[]?, .txt[]?, .ptr[]?, .srv[]?' \
                "${pdir}/dnsx_output.json" 2>/dev/null > "${pdir}/dnsx_all_records.txt" || true
            filter_cloud_domains "${pdir}/dnsx_all_records.txt" "${pdir}/dnsx_cloud_domains.txt"
            local dnsx_cloud_count=0
            [[ -s "${pdir}/dnsx_cloud_domains.txt" ]] && dnsx_cloud_count=$(wc -l < "${pdir}/dnsx_cloud_domains.txt")

            # Extract newly discovered hostnames from DNS records and add to canonical dataset
            extract_domains "${pdir}/dnsx_all_records.txt" "${pdir}/dnsx_all_domains.txt" || true
            [[ -s "${pdir}/dnsx_all_domains.txt" ]] && canonical_dns_add_sources "dnsx-cloud" "${pdir}/dnsx_all_domains.txt"
            # Resolve any new hostnames discovered by DNSx
            canonical_dns_resolve_pending

            log_success "DNSx: $(wc -l < "${pdir}/dnsx_all_records.txt") records, $dnsx_cloud_count cloud-related ($(_format_duration $(($(_now) - dnsx_start))) elapsed)"
        elif [[ -s "$dnsx_log" ]]; then
            log_warn "DNSx produced no output. Last stderr lines:"
            tail -5 "$dnsx_log" | sed 's/^/    /'
        else
            log_warn "DNSx produced no output and no stderr — tool may have been killed"
        fi
    else
        log_warn "DNSx not available or no subdomains — skipping DNSx cloud scan"
    fi

    # ── Stage 2: Cloud_Enum Brute Force ─────────────────────────────────────
    # Per https://github.com/initstring/cloud_enum — this tool searches the
    # three "big-3" providers (AWS, Azure, GCP) for open / misconfigured
    # cloud storage buckets and exposed cloud services.
    #
    # Flags:
    #   -k KW       keywords to mutate; we auto-derive from root domains
    #                AND accept user-supplied ones via --cloud-enum-keywords.
    #   -nsf FILE   file of DNS resolvers
    #   -l FILE     log file path (json output)
    #   -f json     structured output for jq parsing
    #   -t N        threads
    if [[ -f /opt/tools/cloud_enum/cloud_enum.py ]]; then
        log_info "Stage 2: Cloud_Enum brute force"
        local ce_start=$(_now)
        local ce_log="${pdir}/cloud_enum.stderr.log"
        : > "$ce_log"

        # Build the keyword set. cloud_enum's -k takes ONE keyword per flag.
        local -a ce_kw=()
        if [[ -n "$CLOUD_ENUM_KEYWORDS" ]]; then
            read -ra _tmp <<< "${CLOUD_ENUM_KEYWORDS//,/ }"
            ce_kw+=("${_tmp[@]}")
        fi
        if [[ -s "$root_domains_file" ]]; then
            while read -r d; do
                [[ -z "$d" ]] && continue
                ce_kw+=("${d%%.*}")
            done < "$root_domains_file"
        fi

        if [[ ${#ce_kw[@]} -gt 0 ]]; then
            # Dedupe keywords (order-preserving) for a clean log line.
            local _seen="" _kw_list=""
            local kw
            for kw in "${ce_kw[@]}"; do
                [[ " $_seen " == *" $kw "* ]] && continue
                _seen+=" $kw"
                _kw_list+="${_kw_list:+, }$kw"
            done
            log_info "  Cloud_Enum keywords: $_kw_list (wall-clock cap ${CLOUD_ENUM_TIMEOUT:-1800}s)"

            # Emit one -k per keyword.
            local -a ce_args=(-nsf /opt/scripts/wordlists/resolvers.txt)
            for kw in "${ce_kw[@]}"; do
                ce_args+=(-k "$kw")
            done
            ce_args+=(-l "${pdir}/cloud_enum_results.json" -f json -t "$THREADS")

            timeout "${CLOUD_ENUM_TIMEOUT:-1800}" python3 \
                /opt/tools/cloud_enum/cloud_enum.py "${ce_args[@]}" 2>>"$ce_log" || \
                    log_warn "Cloud_Enum exited non-zero or was killed by CLOUD_ENUM_TIMEOUT -- see ${ce_log}"

            if [[ -s "${pdir}/cloud_enum_results.json" ]]; then
                jq -r 'select(.msg != null) | .target' "${pdir}/cloud_enum_results.json" 2>/dev/null | \
                    sort -u > "${pdir}/cloud_enum_assets.txt" || true

                # Extract any newly discovered hostnames from cloud_enum and add to canonical dataset
                extract_domains "${pdir}/cloud_enum_assets.txt" "${pdir}/cloud_enum_all_domains.txt" || true
                [[ -s "${pdir}/cloud_enum_all_domains.txt" ]] && canonical_dns_add_sources "cloud_enum" "${pdir}/cloud_enum_all_domains.txt"
                canonical_dns_resolve_pending

                local ce_count=0
                [[ -s "${pdir}/cloud_enum_assets.txt" ]] && ce_count=$(wc -l < "${pdir}/cloud_enum_assets.txt")
                log_success "Cloud_Enum: $ce_count assets discovered ($(_format_duration $(($(_now) - ce_start))) elapsed)"
            elif [[ -s "$ce_log" ]]; then
                log_warn "Cloud_Enum produced no output. Last stderr lines:"
                tail -5 "$ce_log" | sed 's/^/    /'
            else
                log_warn "Cloud_Enum produced no output and no stderr"
            fi
        else
            log_skip "Cloud_Enum skipped (no keywords available — use --cloud-enum-keywords)"
        fi
    else
        log_warn "Cloud_Enum not found — skipping cloud brute force"
    fi

    # ── Stage 3: Cloud Asset Extraction from Phase 1 Katana ──────────────────
    # Instead of re-crawling the same live web servers with Katana (which Phase 1
    # already crawled), we filter Phase 1's Katana URLs for cloud-hosted endpoints.
    # This avoids a redundant second crawl and saves significant wall-clock time.
    log_info "Stage 3: Extracting cloud assets from Phase 1 Katana crawl data"
    local katana_start=$(_now)

    # Collect Katana URLs from all Phase 1 domain directories
    local p1_katana_urls="${pdir}/.katana_urls.tmp"
    : > "$p1_katana_urls"

    for ddir in "${OUTPUT_DIR}"/phase1/*/; do
        [[ -d "$ddir" ]] || continue
        if [[ -s "${ddir}katana/discovered_urls.txt" ]]; then
            cat "${ddir}katana/discovered_urls.txt" >> "$p1_katana_urls"
        fi
    done

    if [[ -s "$p1_katana_urls" ]]; then
        sort -u "$p1_katana_urls" -o "$p1_katana_urls"
        local katana_url_count
        katana_url_count=$(wc -l < "$p1_katana_urls")

        # Filter for cloud domains
        filter_cloud_domains "$p1_katana_urls" "${pdir}/katana_cloud_assets.txt"

        local ka_cloud=0
        [[ -s "${pdir}/katana_cloud_assets.txt" ]] && ka_cloud=$(wc -l < "${pdir}/katana_cloud_assets.txt")

        log_success "Katana cloud assets: ${ka_cloud} from ${katana_url_count} Phase 1 URLs ($(_format_duration $(($(_now) - katana_start))) total)"
    else
        log_info "No Katana URLs from Phase 1 — skipping cloud asset extraction"
        : > "${pdir}/katana_cloud_assets.txt"
    fi

    rm -f "$p1_katana_urls"

    # ── Stage 4: Consolidate Cloud Assets ───────────────────────────────────
    log_info "Consolidating cloud assets"

    cat \
        "${pdir}/dnsx_cloud_domains.txt" \
        "${pdir}/cloud_enum_assets.txt" \
        "${pdir}/katana_cloud_assets.txt" \
        2>/dev/null | sort -u > "${pdir}/final_cloud_assets.txt" || true

    if [[ -s "${pdir}/final_cloud_assets.txt" ]]; then
        log_success "Total unique cloud assets: $(wc -l < "${pdir}/final_cloud_assets.txt")"
    else
        log_warn "No cloud assets discovered"
    fi
}