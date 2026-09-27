#!/usr/bin/env bash
# Phase 2: Cloud Asset Discovery
# Discovers AWS, Azure, and GCP assets associated with root domains.
#
# This phase does NOT re-resolve the entire hostname corpus. Instead, it uses
# the canonical DNS dataset (populated in Phase 1) as the source of truth and
# only queries DNS for cloud-specific record types (CNAME, MX, NS, TXT) that
# reveal cloud infrastructure. Any newly discovered hostnames are merged into
# the canonical dataset and resolved incrementally.

run_phase2() {
    local pdir="${OUTPUT_DIR}/phase2"
    mkdir -p "$pdir"
    CURRENT_PHASE=2

    # Only the root-domain set is needed here: Phase 2 queries the canonical
    # DNS dataset (populated in Phase 1) for cloud record types and uses the
    # root domains as cloud_enum keywords. It does not consume the Phase 1
    # all-subdomains / live-web intermediate lists.
    local root_domains_file="$1"

    log_info "═══ PHASE 2: Cloud Asset Discovery ═══"

    # ── Stage 1: Cloud DNS Record Discovery ──────────────────────────────────
    # Query CNAME, MX, NS, and TXT records for all hostnames in the canonical
    # dataset to discover cloud infrastructure. CNAME chains pointing to
    # *.cloudfront.net, *.amazonaws.com, etc. and TXT/MX records pointing to
    # cloud-hosted services would never be discovered by a simple A-record
    # lookup.
    #
    # We do NOT re-resolve the entire corpus — we use the canonical DNS dataset
    # as the source of truth and only query these additional record types to
    # find cloud-specific patterns. Any new hostnames discovered in CNAME chains
    # are added to the canonical dataset and resolved incrementally.
    if command -v dnsx &>/dev/null; then
        log_info "Stage 1: DNSx cloud record discovery"
        local dnsx_start=$(_now)
        local dnsx_log="${pdir}/dnsx.stderr.log"
        : > "$dnsx_log"

        # Extract resolved hostnames from the canonical DNS dataset rather than
        # re-reading the Phase 1 output files. This ensures we only query hosts
        # that actually resolved, and avoids re-resolving the entire corpus.
        #
        # `resolved` = has an address, so `cname_only` hosts are NOT queried here.
        # That is deliberate rather than an oversight: their CNAME is already in
        # the dataset, and a name with no address is unlikely to carry MX/NS/TXT.
        # Their takeover-relevant CNAMEs still reach the cloud-asset report,
        # which re-derives cloud assets from the CNAME column for every status
        # (lib/results.sh).
        local canonical_hosts="${pdir}/.canonical_hosts.txt"
        canonical_dns_extract_resolved > "$canonical_hosts"

        if [[ -s "$canonical_hosts" ]]; then
            log_info "  Querying $(wc -l < "$canonical_hosts") resolved hosts for cloud record types (CNAME/MX/NS/TXT)"

            # Redirect rather than `| tee … >/dev/null`: identical output, and it
            # keeps timeout(1)'s exit status capturable so a cap kill can be told
            # apart from a real failure. This pass feeds both the cloud-asset
            # report and new hostnames into the dataset, so a silent partial run
            # understates both.
            local _p2_rc=0
            cat "$canonical_hosts" \
                | timeout "${DNSX_TIMEOUT}" dnsx -cname -mx -ns -txt \
                    -json -retry "${DNSX_RETRY}" \
                    -r "${RESOLVERS_FILE:-/opt/scripts/wordlists/resolvers.txt}" \
                    -timeout "$(_dnsx_query_timeout)" \
                    -t "$(_dnsx_threads)" \
                    > "${pdir}/dnsx_output.json" 2>>"$dnsx_log" || _p2_rc=$?
            if _was_capped "$_p2_rc"; then
                _record_truncation "all" "dnsx-cloud-records" "hit its ${DNSX_TIMEOUT}s cap — cloud records are partial"
                log_warn "DNSx cloud-record pass was KILLED at its ${DNSX_TIMEOUT}s cap — records are PARTIAL"
            elif (( _p2_rc != 0 )); then
                log_warn "DNSx exited non-zero (${_p2_rc}) — see ${dnsx_log}"
            fi

            if [[ -s "${pdir}/dnsx_output.json" ]]; then
                # Extract all DNS records for cloud domain filtering
                jq -r '.cname[]?, .mx[]?, .ns[]?, .txt[]?' \
                    "${pdir}/dnsx_output.json" 2>/dev/null > "${pdir}/dnsx_all_records.txt" || true
                filter_cloud_domains "${pdir}/dnsx_all_records.txt" "${pdir}/dnsx_cloud_domains.txt"
                local dnsx_cloud_count=0
                [[ -s "${pdir}/dnsx_cloud_domains.txt" ]] && dnsx_cloud_count=$(wc -l < "${pdir}/dnsx_cloud_domains.txt")

                # Extract hostnames from the DNS records. Only IN-SCOPE ones
                # (suffix of a user-supplied root domain) may enter the
                # canonical dataset: records include third-party values (SPF
                # "include:_spf.google.com", MX "aspmx.l.google.com", CNAME
                # targets like "d3vfd.s3.amazonaws.com") that are cloud
                # SIGNALS, not attack-surface hosts. Unfiltered, their IPs
                # flowed into Phase 3 classification → nmap_candidates and got
                # PORT-SCANNED — out-of-scope scanning against third parties.
                # The full unfiltered list is kept (dnsx_all_domains.txt) and
                # the cloud-relevant subset is reported via
                # filter_cloud_domains above; only scope-matching hostnames
                # are resolved/tracked below.
                extract_domains "${pdir}/dnsx_all_records.txt" "${pdir}/dnsx_all_domains.txt" || true
                local in_scope_file="${pdir}/dnsx_in_scope_domains.txt"
                filter_in_scope_hostnames "${pdir}/dnsx_all_domains.txt" "$in_scope_file"
                [[ -s "$in_scope_file" ]] && canonical_dns_add_sources "dnsx-cloud" "$in_scope_file"

                # Resolve any newly discovered hostnames incrementally
                canonical_dns_resolve_pending

                log_success "DNSx: $(wc -l < "${pdir}/dnsx_all_records.txt") records, $dnsx_cloud_count cloud-related ($(_format_duration $(($(_now) - dnsx_start))) elapsed)"
            elif [[ -s "$dnsx_log" ]]; then
                log_warn "DNSx produced no output. Last stderr lines:"
                tail -5 "$dnsx_log" | sed 's/^/    /'
            else
                log_warn "DNSx produced no output and no stderr — tool may have been killed"
            fi
        else
            log_warn "No resolved hosts in canonical DNS dataset — skipping DNSx cloud scan"
        fi

        rm -f "$canonical_hosts"
    else
        log_warn "DNSx not available — skipping cloud DNS record discovery"
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
            log_info "  Cloud_Enum keywords: $_kw_list (wall-clock cap ${CLOUD_ENUM_TIMEOUT:-900}s)"

            # Emit one -k per keyword. cloud_enum parses its resolver file
            # with dnspython, which accepts BARE IP ADDRESSES ONLY — the DoH
            # proxy's "127.0.0.1:PORT" form is rejected outright. Swap in a
            # plain-IP list, or drop the flag entirely (cloud_enum then falls
            # back to its own default resolver).
            local nsf_file
            nsf_file=$(_plain_ip_resolver_file)
            # The getter stays silent so its stdout is only ever the path;
            # reporting happens here, from what it returned.
            if [[ -z "$nsf_file" ]]; then
                log_warn "cloud_enum needs a resolver file of bare IPs and neither the active one nor the system resolver qualifies — its DNS checks will be skipped"
            elif [[ "$nsf_file" != "${RESOLVERS_FILE:-}" ]]; then
                if _doh_plain_resolver_available; then
                    # The DoH proxy answers on a bare IP too, so cloud_enum stays
                    # on the same transport as every other tool. Previously this
                    # branch could not exist and cloud_enum always left DoH.
                    log_info "cloud_enum: using the DoH proxy's plain-IP listener (127.0.0.1) — same DNS view as the rest of the run"
                else
                    log_warn "cloud_enum cannot read the active resolver file (it accepts bare IPs only) — falling back to the system resolver ($(head -1 "$nsf_file")) for its DNS checks"
                fi
            fi
            local -a ce_args=()
            [[ -n "$nsf_file" ]] && ce_args+=(-nsf "$nsf_file")
            for kw in "${ce_kw[@]}"; do
                ce_args+=(-k "$kw")
            done
            ce_args+=(-l "${pdir}/cloud_enum_results.json" -f json -t "$THREADS")

            local _ce_rc=0
            timeout "${CLOUD_ENUM_TIMEOUT:-900}" python3 \
                /opt/tools/cloud_enum/cloud_enum.py "${ce_args[@]}" 2>>"$ce_log" || _ce_rc=$?
            if _was_capped "$_ce_rc"; then
                # Observed: a real run spent its full 900s and was killed with
                # 54 assets logged. The assets found are kept, but the run went
                # on to report COMPLETE — cloud_enum was the one capped stage
                # whose loss left no trace at all.
                _record_truncation "all" "cloud_enum" "hit its ${CLOUD_ENUM_TIMEOUT:-900}s cap — cloud assets are partial"
                log_warn "Cloud_Enum was KILLED at its ${CLOUD_ENUM_TIMEOUT:-900}s cap — cloud-asset coverage is PARTIAL (assets logged so far are kept)"
            elif (( _ce_rc != 0 )); then
                log_warn "Cloud_Enum exited non-zero (${_ce_rc}) -- see ${ce_log}"
            fi
            # A non-zero exit does not necessarily mean the results are gone:
            # cloud_enum appends to its JSON log as it goes, so whatever it
            # logged before stopping is still parsed below. The usual trigger
            # is an unhandled dns.resolver.NoAnswer inside cloud_enum itself
            # (it does not catch it), which aborts the run mid-way.

            if [[ -s "${pdir}/cloud_enum_results.json" ]]; then
                # cloud_enum interleaves banner/status lines with JSON objects
                # in its "json" output. A bare `jq` on the raw file chokes on
                # the first non-JSON line, exits non-zero, and silently drops
                # ALL findings (we saw 116 findings → "0 assets"). Read every
                # line as a raw string and parse defensively so non-JSON
                # banner lines are skipped instead of aborting the parse.
                jq -R 'fromjson? // empty | select(.msg != null) | .target' \
                    "${pdir}/cloud_enum_results.json" 2>/dev/null | \
                    sort -u > "${pdir}/cloud_enum_assets.txt" || true

                # Extract any newly discovered hostnames from cloud_enum and add
                # to the canonical dataset — but only in-scope ones. cloud_enum
                # reports the buckets it finds by NAME (some-bucket.s3.amazonaws.com,
                # …elb.amazonaws.com), which are AWS-owned endpoints, not hosts of
                # the target. Ingesting them unfiltered sent their IPs straight
                # into nmap_candidates and got Amazon's S3 frontends port-scanned.
                extract_domains "${pdir}/cloud_enum_assets.txt" "${pdir}/cloud_enum_all_domains.txt" || true
                local ce_in_scope="${pdir}/cloud_enum_in_scope_domains.txt"
                filter_in_scope_hostnames "${pdir}/cloud_enum_all_domains.txt" "$ce_in_scope"
                if [[ -s "$ce_in_scope" ]]; then
                    canonical_dns_add_sources "cloud_enum" "$ce_in_scope"
                    canonical_dns_resolve_pending
                else
                    local _ce_dropped=0
                    [[ -s "${pdir}/cloud_enum_all_domains.txt" ]] && _ce_dropped=$(wc -l < "${pdir}/cloud_enum_all_domains.txt")
                    (( _ce_dropped > 0 )) && log_info "  Cloud_Enum: ${_ce_dropped} discovered hostname(s) are out of scope (third-party cloud endpoints) — recorded as cloud assets, not resolved or scanned"
                fi

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