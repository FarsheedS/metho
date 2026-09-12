#!/usr/bin/env bash
# ── Canonical DNS Dataset ──────────────────────────────────────────────────────
#
# The canonical DNS dataset is the single source of truth for hostname-to-IP
# mappings across all phases.  Hostnames are added by each discovery tool with
# their source tracked in the `discovery_sources` column.  DNS resolution is
# performed incrementally — only newly-added ("pending") hostnames are resolved
# in each round — and the results are merged back into the dataset.
#
# Format: TSV (tab-separated values)
# Columns:
#   hostname            FQDN being tracked
#   root_domain         eTLD+1 root domain this hostname belongs to
#   discovery_sources   semicolon-separated list of tools that found this hostname
#   A                   semicolon-separated IPv4 addresses
#   AAAA                semicolon-separated IPv6 addresses
#   CNAME               semicolon-separated CNAME targets
#   resolution_status   resolved | nxdomain | timeout | pending
#
# The file lives at ${OUTPUT_DIR}/canonical_dns.tsv
# and is initialized once at pipeline start, then updated incrementally.

# ── Initialize ─────────────────────────────────────────────────────────────────
# Create the canonical DNS TSV with its header row.
init_canonical_dns() {
    local tsv="${CANONICAL_DNS_TSV:-${OUTPUT_DIR}/canonical_dns.tsv}"
    printf 'hostname\troot_domain\tdiscovery_sources\tA\tAAAA\tCNAME\tresolution_status\n' > "$tsv"
    log_info "Initialized canonical DNS dataset: $tsv"
}

# ── Normalize a hostname ──────────────────────────────────────────────────────
# Strip leading *. wildcard, lowercase, strip trailing dot.
normalize_hostname() {
    echo "$1" | sed 's/^\*\.//; s/\.$//' | tr '[:upper:]' '[:lower:]'
}

# ── Match a hostname to a known root domain ───────────────────────────────────
# match_root_domain <hostname>
#
# Returns the known root domain that <hostname> belongs to: either an exact
# match or a suffix match (".root_domain"). Reads the list of user-supplied
# root domains from ROOT_DOMAINS_FILE. Returns empty string if no known root
# domain matches.
#
# We deliberately do NOT infer the root domain from the hostname's last two
# labels — that breaks ccTLDs such as "example.co.uk" (→ "co.uk") and
# "example.com.au" (→ "com.au"). The root domain is taken from the set
# supplied to Metho instead.
match_root_domain() {
    local host="$1"
    [[ -z "$host" ]] && { echo ""; return; }
    [[ -z "${ROOT_DOMAINS_FILE:-}" || ! -s "$ROOT_DOMAINS_FILE" ]] && { echo ""; return; }

    local rd
    while IFS= read -r rd; do
        [[ -z "$rd" ]] && continue
        rd=$(normalize_hostname "$rd")
        [[ -z "$rd" ]] && continue
        # Exact match (the root domain itself) or suffix match (a subdomain).
        if [[ "$host" == "$rd" || "$host" == *".${rd}" ]]; then
            echo "$rd"
            return
        fi
    done < "$ROOT_DOMAINS_FILE"

    echo ""
}

# ── Add hostnames with their source ───────────────────────────────────────────
# canonical_dns_add_sources <source_name> <hostnames_file> [root_domain]
#
# Reads hostnames from <hostnames_file> (one per line, already filtered to
# in-scope), normalizes them, and adds them to the canonical TSV.
#   - New hostnames get resolution_status=pending and the given source.
#   - Existing hostnames get the source appended to discovery_sources (deduped)
#     — the source is retained and merged, never overwritten.
#   - If <root_domain> is given, every hostname is assigned to it. This is the
#     preferred path when the caller already knows the root domain (e.g. inside
#     process_domain, where it is the domain being processed).
#   - Otherwise the root domain is matched against the known root domains
#     (same matching rules as match_root_domain: exact or .suffix, first
#     root in ROOT_DOMAINS_FILE wins — never derived from hostname labels).
#
# Performance: the merge is a SINGLE awk pass (batch loaded into an in-memory
# array, TSV streamed once). The previous implementation re-scanned — and for
# changes rewrote — the ENTIRE TSV once per input hostname, making a 25k-line
# passive-enum merge for one domain take ~30 minutes (O(N²) in file rewrites).
canonical_dns_add_sources() {
    local source="$1" hostnames_file="$2" explicit_root="${3:-}"
    local tsv="${CANONICAL_DNS_TSV:-${OUTPUT_DIR}/canonical_dns.tsv}"

    if [[ ! -f "$tsv" ]]; then
        init_canonical_dns
    fi

    # Normalize the whole batch up-front (trim, strip *. and trailing dot,
    # lowercase, drop empties, dedupe). One pipeline, not one per hostname.
    local norm="${tsv}.add_norm"
    grep -v '^[[:space:]]*$' "$hostnames_file" 2>/dev/null \
        | sed 's/^[[:space:]]*//;s/[[:space:]]*$//;s/^\*\.//;s/\.$//' \
        | tr '[:upper:]' '[:lower:]' \
        | grep -v '^$' \
        | sort -u > "$norm" || true

    local added=0 skipped=0

    if [[ -s "$norm" ]]; then
        local norm_root=""
        [[ -n "$explicit_root" ]] && norm_root=$(normalize_hostname "$explicit_root")

        local counts="${tsv}.add_counts"
        local tmp="${tsv}.add_tmp"

        # File 1 ($norm): normalized new hostnames, one per line.
        # File 2 ($tsv):  the canonical TSV (header on line 1).
        awk -F'\t' -v OFS='\t' -v src="$source" -v xr="$norm_root" \
            -v roots_file="${ROOT_DOMAINS_FILE:-}" -v counts_file="$counts" '
            # Load the root-domain list once for suffix matching.
            BEGIN {
                nroots = 0
                if (roots_file != "") {
                    while ((getline rl < roots_file) > 0) {
                        rl = tolower(rl)
                        sub(/^[[:space:]]+/, "", rl); sub(/[[:space:]]+$/, "", rl)
                        sub(/^\*\./, "", rl); sub(/\.$/, "", rl)
                        if (rl != "") roots[++nroots] = rl
                    }
                    close(roots_file)
                }
            }
            # Exact match, or ".<root>" suffix — index arithmetic avoids
            # regex-escaping the dots in root domains.
            function match_root(h,    i, suf) {
                for (i = 1; i <= nroots; i++) {
                    if (h == roots[i]) return roots[i]
                    suf = "." roots[i]
                    if (substr(h, length(h) - length(suf) + 1) == suf) return roots[i]
                }
                return ""
            }
            NR == FNR {
                if (!($0 in new_root)) order[++n] = $0
                rd = (xr != "") ? xr : match_root($0)
                if (!($0 in new_root) || (new_root[$0] == "" && rd != "")) new_root[$0] = rd
                next
            }
            # The TSV header (line 1 of file 2) must be preserved in the
            # output — dropping it here turned every later call into seeing
            # the first data row as the "header" (silently skipped),
            # corrupting the dataset. Print it, then process data rows.
            FNR == 1 { print; next }
            {
                if ($1 in new_root) {
                    consumed[$1] = 1
                    if (index(";" $3 ";", ";" src ";") == 0)
                        $3 = ($3 == "" ? src : $3 ";" src)
                    if ($2 == "" && new_root[$1] != "") $2 = new_root[$1]
                    updated++
                }
                print
            }
            END {
                for (i = 1; i <= n; i++) {
                    h = order[i]
                    if (!(h in consumed)) {
                        printf "%s\t%s\t%s\t\t\t\tpending\n", h, new_root[h], src
                        added++
                    }
                }
                printf "ADDED=%d\nUPDATED=%d\n", added, updated > counts_file
            }
        ' "$norm" "$tsv" > "$tmp" && mv "$tmp" "$tsv"

        if [[ -s "$counts" ]]; then
            added=$(sed -n 's/^ADDED=//p' "$counts")
            skipped=$(sed -n 's/^UPDATED=//p' "$counts")
        fi
        rm -f "$counts"
    fi

    rm -f "$norm"
    log_info "Canonical DNS: added $added new hostnames from $source, updated $skipped existing"
}

# ── Resolve pending hostnames via DNSx ─────────────────────────────────────────
# canonical_dns_resolve_pending [include_timeouts]
#
# Extracts all hostnames with resolution_status=pending, runs them through
# dnsx for A/AAAA/CNAME resolution, and updates the TSV in-place.
# Any extra flags (e.g., -r resolvers.txt) are passed through to dnsx.
#
# With the argument "include_timeouts" (and only if DNS has been seen working
# in this run — METHO_DNS_WORKING=1), previously-timed-out hosts are retried
# once more. Used by the FINAL passes (Phase 1 Stage 7, Phase 3 Stage 1) so
# hosts lost to a transient resolver slowdown get a second chance without
# re-grinding the whole corpus on every delta round.
#
# Robustness:
#   * Effective dnsx wall-clock cap scales with the batch size
#     (max(DNSX_TIMEOUT, pending/50), capped at 3600s) — a fixed 600s cap on a
#     300K-host batch killed dnsx mid-run and permanently mislabeled every
#     unprocessed host as "timeout" (never retried: only "pending" re-resolves).
#   * Total-failure fallback: if dnsx returns NOTHING for the batch, the
#     system resolver (Docker's 127.0.0.11 / resolv.conf) is probed and, if it
#     answers, the whole batch is retried through it. Covers networks that
#     block direct UDP/53 to external resolvers (corporate VPN etc.) while
#     their own resolver keeps working — no startup health-check can catch a
#     network that breaks (or recovers) mid-run.
canonical_dns_resolve_pending() {
    local tsv="${CANONICAL_DNS_TSV:-${OUTPUT_DIR}/canonical_dns.tsv}"
    local pending_file="${tsv}.pending_hosts"
    local dnsx_json="${tsv}.pending_dnsx"

    if [[ ! -s "$tsv" ]]; then
        log_warn "canonical_dns_resolve_pending: TSV does not exist"
        return
    fi

    # Extract pending hostnames — plus, on final passes, timed-out ones (retry)
    # but only when DNS has been seen working this run.
    if [[ "${1:-}" == "include_timeouts" && "${METHO_DNS_WORKING:-0}" == "1" ]]; then
        awk -F'\t' '$7 == "pending" || $7 == "timeout" {print $1}' "$tsv" > "$pending_file"
    else
        awk -F'\t' '$7 == "pending" {print $1}' "$tsv" > "$pending_file"
    fi

    local pending_count=0
    [[ -s "$pending_file" ]] && pending_count=$(wc -l < "$pending_file")

    if [[ "$pending_count" -eq 0 ]]; then
        log_info "Canonical DNS: no pending hostnames to resolve"
        rm -f "$pending_file" "$dnsx_json"
        return
    fi

    log_info "Canonical DNS: resolving $pending_count pending hostnames via DNSx"

    # Reserved/bogon IP guard. A fake-IP VPN (Clash/mihomo/Surge in fake-ip
    # mode) returns RFC 2544 benchmark addresses (198.18.0.0/15) for every
    # domain, which then pollute the canonical dataset and make nmap scan
    # phantom hosts (every port "open" via the proxy). After the merge below
    # we strip ALL reserved ranges from A/AAAA fields so they never reach
    # classification or nmap. A host whose IPs are ALL reserved is marked
    # "bogon" (not "resolved") so it is excluded from downstream probing.

    if ! command -v dnsx &>/dev/null; then
        log_error "dnsx not found — cannot resolve pending hostnames"
        rm -f "$pending_file" "$dnsx_json"
        return 1
    fi

    # Scale the wall-clock cap with batch size: a fixed 600s cap killed dnsx
    # mid-batch on large corpora and permanently mislabeled unprocessed hosts
    # as "timeout". 1s per 50 hosts ≈ 2.5× headroom at ~2000 q/s, capped at 1h.
    local eff_timeout="${DNSX_TIMEOUT:-600}"
    local _scaled=$(( pending_count / 50 ))
    (( _scaled > eff_timeout )) && eff_timeout=$_scaled
    (( eff_timeout > 3600 )) && eff_timeout=3600

    : > "$dnsx_json"

    cat "$pending_file" | timeout "$eff_timeout" dnsx \
        -silent -a -aaaa -cname -json -retry 2 \
        -r "${RESOLVERS_FILE:-/opt/scripts/wordlists/resolvers.txt}" \
        -timeout 5 \
        2>"${dnsx_json}.stderr" > "$dnsx_json" || true

    # Resolver-health check: dnsx's [WRN] line is the only signal that the
    # RESOLVERS (not the domains) are failing — e.g. a network that blocks
    # outbound UDP/53 to public resolvers makes the entire shipped list dead
    # while dnsx still exits 0. Surface it loudly instead of letting every
    # host silently become "timeout".
    if grep -q "domains failed to resolve" "${dnsx_json}.stderr" 2>/dev/null; then
        local _failed_n
        _failed_n=$(grep -oE "[0-9]+ domains failed" "${dnsx_json}.stderr" | head -1 | grep -oE "^[0-9]+")
        if [[ -n "$_failed_n" && "$_failed_n" -ge "$pending_count" ]]; then
            log_warn "dnsx failed to resolve ${_failed_n}/${pending_count} hosts — if this is ALL of them, the resolvers list (wordlists/resolvers.txt) is likely unreachable from this network"
        fi
    fi

    # ── Total-failure fallback: retry the batch through the system resolver ──
    # Zero results for a non-empty batch means the configured resolvers are
    # unreachable (blocked UDP/53, dead custom list, network flap). If the
    # network's own resolver answers, redo the batch through it — a working
    # pipeline beats a dead one. (No-op when RESOLVERS_FILE already IS the
    # system resolver, e.g. after a custom-list health-check fallback.)
    if [[ ! -s "$dnsx_json" ]]; then
        local sys_dns
        sys_dns=$(_probe_system_resolver)
        if [[ -n "$sys_dns" && "$sys_dns" != "${RESOLVERS_FILE:-}" ]]; then
            log_warn "Canonical DNS: dnsx returned 0 results for ${pending_count} hosts — retrying via system resolver (${sys_dns}) ..."
            cat "$pending_file" | timeout "$eff_timeout" dnsx \
                -silent -a -aaaa -cname -json -retry 2 \
                -r "$sys_dns" \
                -timeout 5 \
                2>>"${dnsx_json}.stderr" >> "$dnsx_json" || true
        fi
    fi

    rm -f "${dnsx_json}.stderr"

    # Single-pass merge: stream the TSV once, applying the dnsx results held
    # in an in-memory map. The previous implementation re-rewrote the whole
    # TSV once per dnsx JSON line (O(N×M) full-file rewrites — tens of
    # minutes on a large corpus). jq pre-parses the JSONL ONCE into a flat
    # host\tA\tAAAA\tCNAME\tstatus map; awk then joins in one pass.
    awk -F'\t' -v OFS='\t' '
        $7 == "pending" { $7 = "timeout" }
        { print }
    ' "$tsv" > "${tsv}.pre_resolve"

    if [[ -s "$dnsx_json" ]]; then
        local dnsx_map="${tsv}.dnsx_map"
        # dnsx JSON fields: .host, .a[], .aaaa[], .cname[]. A record with
        # empty A/AAAA/CNAME is ambiguous (SERVFAIL/timeout vs no-answer) —
        # we keep it as "timeout": mislabeling a timeout as "nxdomain" would
        # permanently write off a host that may actually be live, while
        # "timeout" honestly signals "unresolved — retry if you care".
        jq -r '
            (.host | ascii_downcase | sub("^[*][.]"; "") | sub("[.]$"; "")) as $h
            | [$h,
               (if .a then (.a | join(";")) else "" end),
               (if .aaaa then (.aaaa | join(";")) else "" end),
               (if .cname then (.cname | join(";")) else "" end),
               (if (.a // [] | length) == 0 and (.aaaa // [] | length) == 0 and (.cname // [] | length) == 0
                then "timeout" else "resolved" end)]
            | @tsv
        ' "$dnsx_json" > "$dnsx_map" 2>/dev/null || : > "$dnsx_map"

        awk -F'\t' -v OFS='\t' -v NR_FILE="$dnsx_map" '
            BEGIN {
                while ((getline dl < NR_FILE) > 0) {
                    split(dl, d, "\t")
                    if (d[1] == "" || d[1] == "host") continue
                    da[d[1]] = d[2]; daaaa[d[1]] = d[3]
                    dcname[d[1]] = d[4];    dst[d[1]] = d[5]
                }
                close(NR_FILE)
            }
            FNR == 1 { next }
            {
                if ($1 in dst) {
                    if (da[$1]    != "") $4 = da[$1]
                    if (daaaa[$1] != "") $5 = daaaa[$1]
                    if (dcname[$1]!= "") $6 = dcname[$1]
                    $7 = dst[$1]
                }
                print
            }
        ' "${tsv}.pre_resolve" > "${tsv}.resolved" \
            && mv "${tsv}.resolved" "$tsv" \
            || mv "${tsv}.pre_resolve" "$tsv"
        rm -f "${tsv}.pre_resolve" "$dnsx_map"
    else
        mv "${tsv}.pre_resolve" "$tsv"
    fi

    # ── Bogon/reserved-IP filter pass ───────────────────────────────────────
    # Strip reserved IP ranges from A/AAAA in a single idempotent awk pass
    # over the finalized TSV. Runs after every resolve round regardless of
    # whether dnsx produced output. A host left with no A/AAAA/CNAME that was
    # "resolved" is reclassified "bogon" so it is excluded from HTTPx/nmap.
    local _bogon_stripped=0
    awk -F'\t' -v OFS='\t' '
        function is_reserved(ip,    a, n, o1, o2, o3) {
            if (ip == "") return 0
            n = split(ip, a, ".")
            if (n != 4) return 1
            o1 = a[1]+0; o2 = a[2]+0; o3 = a[3]+0
            if (o1 == 0) return 1
            if (o1 == 10) return 1
            if (o1 == 100 && o2 >= 64 && o2 <= 127) return 1
            if (o1 == 127) return 1
            if (o1 == 169 && o2 == 254) return 1
            if (o1 == 172 && o2 >= 16 && o2 <= 31) return 1
            if (o1 == 192 && o2 == 0 && (o3 == 0 || o3 == 2)) return 1
            if (o1 == 192 && o2 == 168) return 1
            if (o1 == 198 && (o2 == 18 || o2 == 19)) return 1
            if (o1 == 198 && o2 == 51 && o3 == 100) return 1
            if (o1 == 203 && o2 == 0 && o3 == 113) return 1
            if (o1 >= 224) return 1
            return 0
        }
        function filter_reserved(ips,    a, i, k, out, t) {
            k = split(ips, a, ";")
            out = ""
            for (i = 1; i <= k; i++) {
                t = a[i]
                gsub(/^[ \t]+|[ \t]+$/, "", t)
                if (t == "" || is_reserved(t)) continue
                out = (out == "") ? t : out ";" t
            }
            return out
        }
        FNR == 1 { print; next }
        {
            $4 = filter_reserved($4)
            $5 = filter_reserved($5)
            if ($4 == "" && $5 == "" && $6 == "" && $7 == "resolved") $7 = "bogon"
            print
        }
    ' "$tsv" > "${tsv}.bogon_filtered" && mv "${tsv}.bogon_filtered" "$tsv"

    # Report
    local resolved=0 nxdomain=0 timeout=0 bogon=0 still_pending=0
    resolved=$(awk -F'\t' '$7 == "resolved" {count++} END {print count+0}' "$tsv")
    nxdomain=$(awk -F'\t' '$7 == "nxdomain" {count++} END {print count+0}' "$tsv")
    timeout=$(awk -F'\t' '$7 == "timeout" {count++} END {print count+0}' "$tsv")
    bogon=$(awk -F'\t' '$7 == "bogon" {count++} END {print count+0}' "$tsv")
    still_pending=$(awk -F'\t' '$7 == "pending" {count++} END {print count+0}' "$tsv")

    log_success "Canonical DNS: resolved=$resolved, nxdomain=$nxdomain, timeout=$timeout, bogon=$bogon, pending=$still_pending"

    # Expose last-pass counts so callers can detect a dead-DNS environment
    # (fake-IP VPN or unreachable resolvers: nothing resolves, everything
    # bogon/timeout). Set in the current shell (this is a function, not a
    # subshell) so the calling stage can read them right after.
    CANONICAL_LAST_RESOLVED=$resolved
    CANONICAL_LAST_BOGON=$bogon
    CANONICAL_LAST_TIMEOUT=$timeout
    # Remember across the whole run that DNS has worked at least once. Final
    # passes use this to decide whether retrying "timeout" hosts is worthwhile
    # (never true if nothing has EVER resolved — the network is just dead).
    if [[ "$resolved" -gt 0 ]]; then
        METHO_DNS_WORKING=1
    fi

    if [[ "$bogon" -gt 0 ]]; then
        log_warn "Canonical DNS: $bogon host(s) resolved to reserved/bogon IPs (e.g. 198.18.x.x fake-IP VPN, RFC1918). Excluded from downstream probing/nmap. Verify Docker DNS bypasses fake-ip mode."
    fi

    rm -f "$pending_file" "$dnsx_json"
}

# ── Merge HTTPX metadata into the canonical dataset ────────────────────────────
# canonical_dns_merge_httpx <httpx_json_file>
#
# Reads HTTPX JSONL output and stores CDN/tech/webserver/content_length metadata.
# Since the canonical DNS TSV doesn't have columns for HTTPX metadata (it's
# hostname→DNS focused), this function creates a companion file:
#   ${OUTPUT_DIR}/httpx_metadata.tsv
# with columns: hostname  cdn  technologies  webserver  content_length  status_code  title  url
canonical_dns_merge_httpx() {
    local httpx_json="$1"
    local meta_tsv="${HTTPX_META_TSV:-${OUTPUT_DIR}/httpx_metadata.tsv}"

    if [[ ! -s "$httpx_json" ]]; then
        log_warn "canonical_dns_merge_httpx: $httpx_json is empty or missing"
        return
    fi

    # Write header if file doesn't exist yet
    if [[ ! -s "$meta_tsv" ]]; then
        printf 'hostname\tcdn\ttechnologies\twebserver\tcontent_length\tstatus_code\ttitle\turl\n' > "$meta_tsv"
    fi

    # Single-pass merge (was: one full-file awk rewrite per JSONL line —
    # O(N×M)). jq flattens the whole JSONL once; awk streams the TSV once,
    # updating existing rows and appending new ones in the same pass.
    local flat="${meta_tsv}.flat"
    # httpx "tech" is a JSON array of STRINGS (not objects), per the Result
    # struct in runner/types.go — join directly. webserver field is
    # "webserver" (json tag), NOT "server".
    jq -r '
        (.host | ascii_downcase | sub("^[*][.]"; "") | sub("[.]$"; "")) as $h
        | [$h,
           (if .cdn != null then (.cdn | tostring) else "" end),
           (if .tech then (.tech | join(";")) else "" end),
           (.webserver // ""),
           (.content_length // ""),
           (.status_code // ""),
           (.title // ""),
           (.url // "")]
        | @tsv
    ' "$httpx_json" > "$flat" 2>/dev/null || : > "$flat"

    local tmp="${meta_tsv}.tmp"
    awk -F'\t' -v OFS='\t' -v FLAT="$flat" '
        BEGIN {
            while ((getline fl < FLAT) > 0) {
                split(fl, f, "\t")
                if (f[1] == "" || f[1] == "hostname") continue
                # Last record per host wins (later rounds overwrite earlier).
                m_host[++n] = f[1]
                m[f[1]] = fl
            }
            close(FLAT)
        }
        FNR == 1 { print; next }
        {
            if ($1 in m) {
                print m[$1]
                seen[$1] = 1
            } else {
                print
            }
        }
        END {
            for (i = 1; i <= n; i++)
                if (!(m_host[i] in seen)) print m[m_host[i]]
        }
    ' "$meta_tsv" > "$tmp" && mv "$tmp" "$meta_tsv"
    rm -f "$flat"

    log_info "Canonical DNS: merged HTTPX metadata from $httpx_json"
}

# ── Extract all hostnames from the canonical dataset ──────────────────────────
canonical_dns_extract_hostnames() {
    local tsv="${CANONICAL_DNS_TSV:-${OUTPUT_DIR}/canonical_dns.tsv}"
    if [[ ! -s "$tsv" ]]; then
        echo ""
        return
    fi
    # Skip header, print column 1
    tail -n +2 "$tsv" | awk -F'\t' '{print $1}'
}

# ── Extract all unique resolved IPs (A records) ──────────────────────────────
canonical_dns_extract_ips() {
    local tsv="${CANONICAL_DNS_TSV:-${OUTPUT_DIR}/canonical_dns.tsv}"
    if [[ ! -s "$tsv" ]]; then
        echo ""
        return
    fi
    # Skip header, extract A column, split on semicolons, dedup
    tail -n +2 "$tsv" | awk -F'\t' '{
        n = split($4, ips, ";")
        for (i = 1; i <= n; i++) {
            gsub(/^[ \t]+|[ \t]+$/, "", ips[i])
            if (ips[i] != "") print ips[i]
        }
    }' | sort -u
}

# ── Extract hostnames with a specific resolution status ───────────────────────
canonical_dns_extract_by_status() {
    local status="$1"
    local tsv="${CANONICAL_DNS_TSV:-${OUTPUT_DIR}/canonical_dns.tsv}"
    if [[ ! -s "$tsv" ]]; then
        echo ""
        return
    fi
    awk -F'\t' -v s="$status" '$7 == s {print $1}' "$tsv"
}

# ── Get all resolved hostnames (status = resolved) ────────────────────────────
canonical_dns_extract_resolved() {
    canonical_dns_extract_by_status "resolved"
}

# ── Look up HTTPX CDN flag for a hostname ─────────────────────────────────────
# Returns "true" or "false" based on httpx_metadata.tsv
get_httpx_cdn_for_host() {
    local host="$1"
    local meta_tsv="${HTTPX_META_TSV:-${OUTPUT_DIR}/httpx_metadata.tsv}"
    if [[ ! -s "$meta_tsv" ]]; then
        echo "false"
        return
    fi
    local cdn
    cdn=$(awk -F'\t' -v h="$host" '$1 == h {print $2; exit}' "$meta_tsv" 2>/dev/null)
    if [[ "$cdn" == "true" ]]; then
        echo "true"
    else
        echo "false"
    fi
}

# ── Merge per-domain canonical DNS TSVs into the global TSV ───────────────────
# After parallel Phase 1 processing, each domain has its own canonical_dns.tsv
# and httpx_metadata.tsv in phase1/<domain>/. This function merges them into the
# global ${OUTPUT_DIR}/canonical_dns.tsv and ${OUTPUT_DIR}/httpx_metadata.tsv
# that Phase 2 and Phase 3 consume.
#
# Merge rules for canonical_dns.tsv:
#   - Group by hostname (column 1)
#   - discovery_sources: union (semicolon-joined, deduped)
#   - A/AAAA/CNAME: union (semicolon-joined, deduped)
#   - root_domain: first non-empty wins
#   - resolution_status: prefer resolved > nxdomain > timeout > pending > bogon
#
# Merge rules for httpx_metadata.tsv:
#   - Group by hostname (column 1)
#   - Last record per host wins (same as canonical_dns_merge_httpx)
merge_per_domain_dns() {
    local global_tsv="${OUTPUT_DIR}/canonical_dns.tsv"
    local global_meta="${OUTPUT_DIR}/httpx_metadata.tsv"
    local p1_dir="${OUTPUT_DIR}/phase1"

    log_info "Merging per-domain canonical DNS datasets..."

    # ── Merge canonical_dns.tsv ─────────────────────────────────────────────
    # Collect all per-domain TSVs (skip the global one if it exists in phase1/)
    local per_domain_tsvs=()
    local d
    for d in "$p1_dir"/*/; do
        [[ -d "$d" ]] || continue
        if [[ -s "${d}canonical_dns.tsv" ]]; then
            per_domain_tsvs+=("${d}canonical_dns.tsv")
        fi
    done

    if [[ ${#per_domain_tsvs[@]} -gt 0 ]]; then
        printf 'hostname\troot_domain\tdiscovery_sources\tA\tAAAA\tCNAME\tresolution_status\n' > "$global_tsv"

        # Single awk pass: read all per-domain TSVs (skipping headers), group by
        # hostname, merge fields. Status priority: resolved=1, nxdomain=2,
        # timeout=3, pending=4, bogon=5 (lower = higher priority).
        awk -F'\t' -v OFS='\t' '
            function status_rank(s) {
                if (s == "resolved") return 1
                if (s == "nxdomain") return 2
                if (s == "timeout") return 3
                if (s == "pending") return 4
                if (s == "bogon") return 5
                return 6
            }
            # Merge a semicolon-separated field: add new values not already present
            function merge_field(old, new,    a, b, i, j, seen, out) {
                if (new == "") return old
                split(old, a, ";")
                split(new, b, ";")
                out = ""
                for (i in a) {
                    if (a[i] != "" && !(a[i] in seen)) { seen[a[i]] = 1; out = (out == "") ? a[i] : out ";" a[i] }
                }
                for (j in b) {
                    if (b[j] != "" && !(b[j] in seen)) { seen[b[j]] = 1; out = (out == "") ? b[j] : out ";" b[j] }
                }
                return out
            }
            FNR == 1 { next }  # skip headers
            {
                h = $1
                if (h == "") next
                if (!(h in seen)) { order[++n] = h; seen[h] = 1 }
                # root_domain: first non-empty wins
                if (rd[h] == "" && $2 != "") rd[h] = $2
                # discovery_sources: union
                src[h] = merge_field(src[h], $3)
                # A/AAAA/CNAME: union
                a[h] = merge_field(a[h], $4)
                aaaa[h] = merge_field(aaaa[h], $5)
                cname[h] = merge_field(cname[h], $6)
                # resolution_status: best rank wins
                if (status_rank($7) < status_rank(st[h])) st[h] = $7
                if (st[h] == "") st[h] = $7
            }
            END {
                for (i = 1; i <= n; i++) {
                    h = order[i]
                    printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", h, rd[h], src[h], a[h], aaaa[h], cname[h], st[h]
                }
            }
        ' "${per_domain_tsvs[@]}" >> "$global_tsv"

        local entry_count=0
        [[ -s "$global_tsv" ]] && entry_count=$(tail -n +2 "$global_tsv" | wc -l)
        log_success "Merged canonical DNS: $entry_count entries from ${#per_domain_tsvs[@]} per-domain TSVs"
        # METHO_DNS_WORKING is set inside the per-domain subshells during Phase 1
        # and does not survive into this (parent) shell — re-derive it from the
        # merged dataset so Phase 3's final timeout-retry pass knows DNS worked.
        if awk -F'\t' 'NR>1 && $7 == "resolved" { found=1; exit } END { exit !found }' "$global_tsv"; then
            METHO_DNS_WORKING=1
        fi
    else
        log_warn "No per-domain canonical_dns.tsv files found to merge"
    fi

    # ── Merge httpx_metadata.tsv ────────────────────────────────────────────
    local per_domain_metas=()
    for d in "$p1_dir"/*/; do
        [[ -d "$d" ]] || continue
        if [[ -s "${d}httpx_metadata.tsv" ]]; then
            per_domain_metas+=("${d}httpx_metadata.tsv")
        fi
    done

    if [[ ${#per_domain_metas[@]} -gt 0 ]]; then
        printf 'hostname\tcdn\ttechnologies\twebserver\tcontent_length\tstatus_code\ttitle\turl\n' > "$global_meta"

        # Last record per host wins (same semantics as canonical_dns_merge_httpx).
        awk -F'\t' -v OFS='\t' '
            FNR == 1 { next }  # skip headers
            {
                if ($1 == "") next
                if (!($1 in seen)) order[++n] = $1
                seen[$1] = 1
                rec[$1] = $0  # last wins
            }
            END {
                for (i = 1; i <= n; i++) print rec[order[i]]
            }
        ' "${per_domain_metas[@]}" >> "$global_meta"

        local meta_count=0
        [[ -s "$global_meta" ]] && meta_count=$(tail -n +2 "$global_meta" | wc -l)
        log_info "Merged HTTPx metadata: $meta_count entries from ${#per_domain_metas[@]} per-domain files"
    fi
}