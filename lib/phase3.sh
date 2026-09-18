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

    # Final resolution pass — resolve any hostnames still pending, and retry
    # ones lost to transient timeouts earlier in the run (the include_timeouts
    # mode only fires if the transport has actually been answering, so a dead
    # network never triggers a pointless re-grind).
    canonical_dns_resolve_pending include_timeouts

    # Settle the remaining "timeout" rows into "does not exist" vs "we could
    # not ask". Without this the dataset cannot say whether a 90%-unresolved
    # corpus is a dead corpus or a dead transport, which is the first question
    # anyone asks after a run like that.
    canonical_dns_label_nxdomain

    # Extract the domain→IP mapping from the canonical DNS dataset
    local dns_tsv="${CANONICAL_DNS_TSV:-${OUTPUT_DIR}/canonical_dns.tsv}"
    if [[ ! -s "$dns_tsv" ]]; then
        log_error "Canonical DNS dataset not found — cannot proceed with IP classification"
        return 1
    fi

    # Build domain_ip_map.txt from canonical DNS (hostname A_record)
    # The A column (field 4) contains semicolon-separated IPs.
    : > "${pdir}/domain_ip_map.txt"
    # The input file MUST be passed explicitly: an awk with no file argument
    # reads stdin, so dropping it here silently produced an empty map, zero
    # IPs, and a run that skipped classification and port scanning entirely.
    awk -F'\t' '$1 == "hostname" && $2 == "root_domain" { next } {
        if ($4 != "" && $7 == "resolved") {
            n = split($4, ips, ";")
            for (i = 1; i <= n; i++) {
                gsub(/^[ \t]+|[ \t]+$/, "", ips[i])
                if (ips[i] != "") printf "%s %s\n", $1, ips[i]
            }
        }
    }' "$dns_tsv" > "${pdir}/domain_ip_map.txt"

    # Build all_ips.txt from the domain_ip_map (unique IPs)
    cut -d' ' -f2 "${pdir}/domain_ip_map.txt" | sort -u -V > "${pdir}/all_ips.txt"

    local ip_count=0
    [[ -s "${pdir}/all_ips.txt" ]] && ip_count=$(wc -l < "${pdir}/all_ips.txt")
    log_success "Unique IP addresses from canonical DNS: $ip_count"

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

        cat "${pdir}/all_ips.txt" | timeout "${DNSX_TIMEOUT}" dnsx \
            -silent -ptr -resp-only \
            -r "${RESOLVERS_FILE:-/opt/scripts/wordlists/resolvers.txt}" \
            -timeout "$(_dnsx_query_timeout)" \
            -t "$(_dnsx_threads)" \
            2>/dev/null | sort -u > "${pdir}/ptr_hostnames.txt" || true

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
        awk -F'\t' '$1 == "hostname" && $2 == "root_domain" { next } {
            if ($4 != "" && $7 == "resolved") {
                n = split($4, ips, ";")
                for (i = 1; i <= n; i++) {
                    gsub(/^[ \t]+|[ \t]+$/, "", ips[i])
                    if (ips[i] != "") printf "%s %s\n", $1, ips[i]
                }
            }
        }' "$dns_tsv" > "${pdir}/domain_ip_map.txt"
        cut -d' ' -f2 "${pdir}/domain_ip_map.txt" | sort -u -V > "${pdir}/all_ips.txt"
        local _ip_count_before_ptr="$ip_count"
        ip_count=$(wc -l < "${pdir}/all_ips.txt")
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
            # Scale the wall-clock cap with the target count instead of using a
            # fixed one. A 600s cap over 423 hosts × 1000 ports at 1000 pps
            # needs ~423s of pure sending with zero retransmits, so the sweep in
            # the observed run was killed mid-scan and its coverage silently
            # became "whatever fitted in ten minutes".
            local naabu_timeout="${NAABU_TIMEOUT:-0}"
            if [[ "$naabu_timeout" -le 0 ]]; then
                local _naabu_ideal=$(( NAABU_TIMEOUT_BASE + nmap_count * NAABU_SECONDS_PER_HOST ))
                local _naabu_cap="${NAABU_TIMEOUT_MAX:-3600}"
                naabu_timeout="$_naabu_ideal"
                if (( naabu_timeout > _naabu_cap )); then
                    naabu_timeout="$_naabu_cap"
                    # Silently truncating a sweep is how coverage quietly
                    # becomes "whatever fitted": say so, and say what to raise.
                    log_warn "  Naabu cap reached: ${nmap_count} hosts need ~${_naabu_ideal}s at ${NAABU_RATE:-1000} pps but NAABU_TIMEOUT_MAX=${_naabu_cap}s."
                    log_warn "  The scan WILL be truncated. Raise NAABU_TIMEOUT_MAX, raise NAABU_RATE, or lower NAABU_TOP_PORTS to cover everything."
                fi
            fi
            log_info "  Stage 4a: Naabu fast scan (top ${NAABU_TOP_PORTS:-1000} ports, rate ${NAABU_RATE:-1000} pps, cap ${naabu_timeout}s)"
            timeout "$naabu_timeout" naabu \
                -list "${pdir}/nmap_candidates.txt" \
                -top-ports "${NAABU_TOP_PORTS:-1000}" \
                -rate "${NAABU_RATE:-1000}" \
                -retries "${NAABU_RETRIES:-2}" \
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
                if [[ "${NMAP_TOP_PORTS:-100}" -gt 0 ]]; then
                    nmap_ports=$(cut -d: -f2 "${pdir}/naabu_ip_ports.txt" \
                        | sort | uniq -c | sort -rn \
                        | awk -v n="${NMAP_TOP_PORTS:-100}" 'NR<=n {print $2}' \
                        | sort -un | paste -sd, -)
                else
                    nmap_ports=$(cut -d: -f2 "${pdir}/naabu_ip_ports.txt" | sort -un | paste -sd, -)
                fi
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
            _nmap_target_count=$(wc -l < "$nmap_targets")
            _nmap_port_count=$(printf '%s' "$nmap_ports" | tr ',' '\n' | grep -c .)
            log_info "  Stage 4b: Nmap -sV on ${_nmap_target_count} hosts × ${_nmap_port_count} ports (cap: top ${NMAP_TOP_PORTS:-100})"
            nmap -Pn -n -iL "$nmap_targets" \
                -p "$nmap_ports" \
                -sV --open --max-retries 2 \
                --min-hostgroup 64 --min-parallelism 16 \
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

    # Resolved hosts with no HTTPX metadata row yet.
    if [[ -s "$meta_tsv" ]]; then
        cut -f1 "$meta_tsv" | sort -u > "${pending}.probed"
    else
        : > "${pending}.probed"
    fi
    awk -F'\t' '$1 == "hostname" && $2 == "root_domain" { next } $7 == "resolved" { print $1 }' \
        "$dns_tsv" | sort -u > "${pending}.resolved"
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