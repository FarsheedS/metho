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
#   resolution_status   resolved | cname_only | nxdomain | timeout | bogon | pending
#                       (resolved = has at least one A/AAAA address; cname_only =
#                        a CNAME answer with no address, i.e. a dangling-CNAME /
#                        takeover candidate held out of the probe set)
#
# The file lives at ${OUTPUT_DIR}/canonical_dns.tsv
# and is initialized once at pipeline start, then updated incrementally.

# ── Initialize ─────────────────────────────────────────────────────────────────
# Create the canonical DNS TSV with its header row.
init_canonical_dns() {
    local tsv="${CANONICAL_DNS_TSV:-${OUTPUT_DIR}/canonical_dns.tsv}"
    printf 'hostname\troot_domain\tdiscovery_sources\tA\tAAAA\tCNAME\tresolution_status\n' > "$tsv"
    # The reserved-address audit log is reset HERE, once per dataset, and only
    # appended to thereafter. It used to be truncated at the start of every
    # resolve pass, so it only ever held the LAST pass's strips while the
    # reported bogon count was the cumulative TSV state: a real run's global
    # file held 11 hosts against 514 bogon rows, i.e. the audit trail the
    # reserved-IP filter was changed to produce did not actually exist for any
    # host stripped in an earlier pass.
    rm -f "${tsv}.bogon"
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
            -v roots_file="${ROOT_DOMAINS_FILE:-}" -v counts_file="$counts" \
            -v nrecheck="${METHO_NXDOMAIN_RECHECK:-0}" '
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
            # The TSV header must be preserved in the output — dropping it
            # turned every later call into seeing the first data row as the
            # "header" (silently skipped), corrupting the dataset. Identify it
            # by its first field, never by line number: the file is rewritten
            # by several passes, and a positional FNR==1 test silently eats a
            # real hostname the moment the header is missing.
            $1 == "hostname" { print; next }
            {
                if ($1 in new_root) {
                    consumed[$1] = 1
                    if (index(";" $3 ";", ";" src ";") == 0)
                        $3 = ($3 == "" ? src : $3 ";" src)
                    if ($2 == "" && new_root[$1] != "") $2 = new_root[$1]
                    # Re-discovery does NOT normally re-open a settled row.
                    # CT logs are historical, so the same dead names reappear
                    # on every run — resetting them each time would re-grind
                    # the whole NXDOMAIN pile and undo the one-query-per-name
                    # settling that keeps bulk DNS off a constrained network.
                    # Set METHO_NXDOMAIN_RECHECK=1 to re-open them anyway,
                    # for when a name is genuinely expected to have come back
                    # (a decommissioned hostname reused for a new service) and
                    # one extra resolution pass is worth paying for.
                    if (nrecheck == "1" && ($7 == "nxdomain" || $7 == "bogon" || $7 == "cname_only")) $7 = "pending"
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

# ── Run one dnsx resolution pass ───────────────────────────────────────────────
# _dnsx_resolve_to <input_file> <output_json> <resolver_spec> <wall_clock_cap>
#
# Appends JSONL to <output_json> and diagnostics to <output_json>.stderr. The
# caller is responsible for truncating both before the first pass of a batch.
# Shared by the primary pass and every fallback so the flags can never drift
# apart between them.
_dnsx_resolve_to() {
    local input="$1" out="$2" resolver="$3" cap="$4"
    cat "$input" | timeout "$cap" dnsx \
        -silent -a -aaaa -cname -json \
        -retry "${DNSX_RETRY}" \
        -r "$resolver" \
        -timeout "$(_dnsx_query_timeout)" \
        -t "$(_dnsx_threads)" \
        2>>"${out}.stderr" >> "$out" || true
}

# Per-query timeout handed to dnsx. A DoH answer travels as an HTTPS POST
# through the local proxy, so it is inherently slower than a UDP reply from a
# resolver on the same continent; a UDP-tuned value makes dnsx abandon queries
# the proxy is still working on, which reads downstream as "timeout".
# The DoH budget must exceed the proxy's worst case: it may try every
# configured endpoint once, each with its own request timeout. At the defaults
# (3 endpoints × 4s) that is 12s, so dnsx's window is 15s — otherwise dnsx
# abandons the query while the proxy is still working on it and records a
# "timeout" for a host that was about to be answered.
_dnsx_query_timeout() {
    if [[ "${DNS_MODE}" == "doh" ]]; then
        echo "${DNSX_QUERY_TIMEOUT_DOH:-15}"
    else
        echo "${DNSX_QUERY_TIMEOUT:-5}"
    fi
}

# Concurrency handed to each dnsx invocation, per transport.
#
# Every Phase 1 worker runs its own dnsx batch concurrently with the others,
# and in DoH mode all of those batches share ONE local proxy with a fixed
# worker pool. PARALLEL_DOMAINS × DNSX_THREADS is therefore the real in-flight
# count against that pool: at 3 domains × 100 threads it is 300 requests
# against 48 workers, and the queueing that follows pushes queries past dnsx's
# own per-query timeout — which the pipeline then records as "timeout" on
# hosts that were about to be answered.
#
# UDP has no shared bottleneck (12.7K independent resolvers), so it keeps the
# higher default.
_dnsx_threads() {
    if [[ -n "${DNSX_THREADS:-}" ]]; then
        echo "$DNSX_THREADS"
        return
    fi
    if [[ "${DNS_MODE}" == "doh" ]]; then
        echo "${DNSX_THREADS_DOH:-64}"
    else
        echo "${DNSX_THREADS_UDP:-100}"
    fi
}

# ── Resolve pending hostnames via DNSx ─────────────────────────────────────────
# canonical_dns_resolve_pending [include_timeouts]
#
# Extracts all hostnames with resolution_status=pending, runs them through
# dnsx for A/AAAA/CNAME resolution, and updates the TSV in-place.
# Any extra flags (e.g., -r resolvers.txt) are passed through to dnsx.
#
# With the argument "include_timeouts" (and only while METHO_DNS_WORKING=1 —
# i.e. the transport has been answering), previously-timed-out hosts are
# retried once more. Used by the FINAL passes (Phase 1 Stage 7, Phase 3
# Stage 1) so hosts lost to a transient resolver slowdown get a second chance
# without re-grinding the whole corpus on every delta round.
#
# Robustness:
#   * Effective dnsx wall-clock cap scales with the batch size
#     (max(DNSX_TIMEOUT, pending/50), capped at 3600s) — a fixed 600s cap on a
#     300K-host batch killed dnsx mid-run and permanently mislabeled every
#     unprocessed host as "timeout" (never retried: only "pending" re-resolves).
#   * Transport escalation: when a batch's ANSWER rate collapses, the whole
#     batch is retried through the other transport (system resolver or the
#     built-in UDP pool) before any result is recorded. The previous
#     implementation retried only on EXACTLY zero results, which a
#     partially-degraded path never produces — the run that motivated this
#     resolved 1% of its corpus and escalated zero times.
canonical_dns_resolve_pending() {
    local tsv="${CANONICAL_DNS_TSV:-${OUTPUT_DIR}/canonical_dns.tsv}"
    local pending_file="${tsv}.pending_hosts"
    local dnsx_json="${tsv}.pending_dnsx"

    if [[ ! -s "$tsv" ]]; then
        log_warn "canonical_dns_resolve_pending: TSV does not exist"
        return
    fi

    # Extract pending hostnames — plus, on final passes, timed-out ones, but
    # only when the transport has been HEALTHY this run (see the health block
    # at the end of this function). Health means "queries are being answered",
    # not "many names resolved": a corpus harvested from Certificate
    # Transparency is legitimately about half NXDOMAIN, and treating that as
    # failure would disable the retry that recovers genuinely lost hosts.
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
    local eff_timeout="${DNSX_TIMEOUT}"
    local _scaled=$(( pending_count / 50 ))
    (( _scaled > eff_timeout )) && eff_timeout=$_scaled
    (( eff_timeout > 3600 )) && eff_timeout=3600

    # Make sure the transport is still alive before a batch depends on it: a
    # long multi-domain run outlives the proxy's process by many hours.
    _ensure_dns_transport || true

    local _primary="${RESOLVERS_FILE:-/opt/scripts/wordlists/resolvers.txt}"
    : > "$dnsx_json"
    : > "${dnsx_json}.stderr"
    _dnsx_resolve_to "$pending_file" "$dnsx_json" "$_primary" "$eff_timeout"

    # ── Health signal: answer rate, not resolution rate ─────────────────────
    # dnsx's "[WRN] N domains failed to resolve" counts QUERY ERRORS — a
    # resolver that never answered. It is NOT the count of NXDOMAINs: a name
    # that does not exist is a perfectly successful query that dnsx reports as
    # a normal negative answer. So
    #     answered = attempted - errors
    # and an answered/(attempted) ratio below the floor means the transport is
    # broken, regardless of how many names actually exist.
    #
    # This replaces a resolution-rate heuristic that could not tell the two
    # apart. On a real 28K-hostname run, ~43% of the "timeout" pile turned out
    # to exist and resolve fine on an independent resolver — a rate-based gate
    # called that environment healthy because a handful of hosts resolved.
    local _failed_n=0
    # Names in this batch that came back with an address or a CNAME. Filled in
    # by the dnsx-JSON parse below; stays 0 when dnsx produced no output at all.
    # Reported alongside the blackhole count so the health line cannot be read
    # as "we got answers" when it only means "we were not refused".
    local _with_records=0
    if grep -q "domains failed to resolve" "${dnsx_json}.stderr" 2>/dev/null; then
        _failed_n=$(grep -oE "[0-9]+ domains failed" "${dnsx_json}.stderr" | head -1 | grep -oE "^[0-9]+" || echo 0)
        _failed_n=${_failed_n:-0}
    fi
    local _answered=$(( pending_count - _failed_n ))
    (( _answered < 0 )) && _answered=0

    local _min_pct="${DNS_MIN_ANSWER_PCT:-50}"
    local _min_batch="${DNS_MIN_HEALTH_BATCH:-20}"
    local _transport="${DNS_TRANSPORT_LABEL:-${DNS_MODE}}"

    if [[ "$_failed_n" -ge "$pending_count" && "$pending_count" -gt 0 ]]; then
        log_warn "dnsx failed to resolve ${_failed_n}/${pending_count} hosts — the resolver list (${_primary}) is unreachable from this network"
    fi

    # ── Transport escalation ────────────────────────────────────────────────
    # A broken transport is retried through the other one BEFORE the results
    # are merged: an answered name always beats a lost one, and waiting for a
    # later stage only re-grinds the same pile. The old code did this only
    # when dnsx returned EXACTLY zero results, which a partially-degraded path
    # never does — during the observed run it silently wrote off 12k hosts.
    if (( pending_count > 0 )) && (( _answered * 100 < pending_count * _min_pct )); then
        local _fallback
        _fallback=$(_fallback_resolver_file "$_primary")
        if [[ -n "$_fallback" && "$_fallback" != "$_primary" ]]; then
            log_warn "DNS transport '${_transport}' answered only ${_answered}/${pending_count} queries — retrying the batch via the fallback transport ($_fallback) ..."
            local _before_fb _err_before
            _before_fb=$(wc -l < "$dnsx_json" 2>/dev/null || echo 0)
            _err_before=$(wc -l < "${dnsx_json}.stderr" 2>/dev/null || echo 0)
            _dnsx_resolve_to "$pending_file" "$dnsx_json" "$_fallback" "$eff_timeout"
            local _after_fb _fb_ok
            _after_fb=$(wc -l < "$dnsx_json" 2>/dev/null || echo 0)
            _fb_ok=$(( _after_fb - _before_fb ))
            if (( _fb_ok > 0 )); then
                log_success "Fallback transport recovered ${_fb_ok} additional answer line(s) for this batch"
                DNS_TRANSPORT_LABEL="${_transport}+fallback"
            fi

            # The two passes share one stderr file, so the fallback's own error
            # count only exists in its slice of it. Reading the file from the
            # top (as an earlier version did) always returned the PRIMARY
            # pass's number and made the health flag describe the transport
            # that had just failed.
            local _fb_failed
            _fb_failed=$(tail -n "+$(( _err_before + 1 ))" "${dnsx_json}.stderr" 2>/dev/null \
                | grep -oE "[0-9]+ domains failed" | head -1 | grep -oE "^[0-9]+") || true
            if [[ -n "${_fb_failed:-}" ]] && (( _fb_failed < _failed_n )); then
                _failed_n="$_fb_failed"
            fi
        else
            log_warn "DNS transport '${_transport}' answered only ${_answered}/${pending_count} queries and no fallback transport is usable from this network"
        fi
    fi

    # Recompute the answered count from the (possibly improved) error figure so
    # the health flag below describes the transport that actually served the
    # batch. Both passes count their own errors against the same batch, so the
    # signal kept is the BEST pass, never the sum.
    _answered=$(( pending_count - _failed_n ))
    (( _answered < 0 )) && _answered=0

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
        # dnsx JSON fields: .host, .a[], .aaaa[], .cname[].
        #
        # Three outcomes, and the distinction is load-bearing:
        #   A or AAAA present        -> "resolved"    (has an address; safe to probe)
        #   only a CNAME, no address -> "cname_only"  (see below)
        #   nothing at all           -> "timeout"     (SERVFAIL / no answer)
        #
        # "timeout" is deliberately NOT "nxdomain": mislabeling an unresolved
        # host as nonexistent would write it off permanently, while "timeout"
        # honestly says "unresolved — retry if you care".
        #
        # "cname_only" exists because the rule used to be
        #     (no A and no AAAA and no CNAME) -> timeout, ELSE resolved
        # so a bare CNAME answer was recorded as "resolved" with an empty
        # address column. On a real 28,323-hostname run that put 1,678 rows
        # (13.7% of everything handed to httpx) into the probe set carrying no
        # address at all; an independent 40-name sample of that set found ~80%
        # NXDOMAIN elsewhere and ~18% returning a CNAME whose target no longer
        # resolves. Those are two different findings and neither is "resolved":
        #   - the NXDOMAIN majority is probe time burned on names that cannot
        #     answer, and
        #   - the dangling-CNAME minority is a takeover candidate, which belongs
        #     in the report rather than in a probe list labelled "live".
        jq -r '
            (.host | ascii_downcase | sub("^[*][.]"; "") | sub("[.]$"; "")) as $h
            | (if .a then (.a | join(";")) else "" end) as $a
            | (if .aaaa then (.aaaa | join(";")) else "" end) as $aaaa
            | (if .cname then (.cname | join(";")) else "" end) as $cname
            | [$h, $a, $aaaa, $cname,
               (if $a != "" or $aaaa != "" then "resolved"
                elif $cname != "" then "cname_only"
                else "timeout" end)]
            | @tsv
        ' "$dnsx_json" > "$dnsx_map" 2>/dev/null || : > "$dnsx_map"

        # Record-bearing count for the health line below. "The transport did
        # not blackhole these hosts" and "these names have records" are
        # different questions, and only this number answers the second.
        _with_records=$(awk -F'\t' '$2 != "" || $3 != "" || $4 != "" {c++} END {print c+0}' "$dnsx_map" 2>/dev/null)
        _with_records=${_with_records:-0}

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
            # Identify the header by CONTENT and PRESERVE it. This pass is what
            # used to destroy it: `FNR == 1 { next }` dropped line 1
            # unconditionally, so the first resolution after init_canonical_dns
            # silently removed the header row — and every downstream consumer
            # that then skipped "line 1" ate a real hostname instead.
            $1 == "hostname" && $2 == "root_domain" { print; next }
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
    #
    # Every stripped address is recorded in "${tsv}.bogon" with the range that
    # matched. A bogon count with no evidence behind it cannot be audited: the
    # previous version erased the address AND left no trace, so working out
    # whether a "bogon" host was an RFC1918 leak, a CGNAT name or a fake-IP
    # VPN artefact meant re-resolving the hosts by hand.
    #
    # The two families are classified separately. The previous version ran the
    # IPv4 octet parser over BOTH columns, and `split(ip, a, ".")` on an IPv6
    # literal returns one field — so `n != 4` was true for every AAAA record
    # and the entire IPv6 column was destroyed on every run, while an
    # IPv6-only host was reclassified "bogon" and dropped from every
    # downstream stage (HTTPx, nmap, IP extraction).
    # Append, never truncate: each pass can strip addresses the earlier passes
    # never saw (a host can gain an address later), and the operator reading
    # this file wants every strip this dataset produced, not the last pass's.
    # Duplicate lines across passes are possible and harmless; the report counts
    # bogon hosts from the TSV, not from here.
    #
    # The append has to be an awk `>>`, not `>`: awk's `>` truncates the target
    # on the first write OF EACH awk INVOCATION, so a per-pass `>` re-erased the
    # log on every pass no matter what the shell did around it. That — plus the
    # per-pass `rm -f` that used to sit here — is why a real run's global file
    # held 11 hosts against 514 bogon rows.
    local _bogon_log="${tsv}.bogon"
    awk -F'\t' -v OFS='\t' -v bogon_log="$_bogon_log" '
        # ── IPv4 ────────────────────────────────────────────────────────────
        # Sets `why` on a match so the audit log can name the range.
        function v4_reserved(ip,    a, n, o1, o2, o3) {
            n = split(ip, a, ".")
            if (n != 4) { why = "malformed-v4"; return 1 }
            o1 = a[1]+0; o2 = a[2]+0; o3 = a[3]+0
            if (o1 == 0)   { why = "0.0.0.0/8";     return 1 }
            if (o1 == 10)  { why = "10.0.0.0/8";    return 1 }
            if (o1 == 100 && o2 >= 64 && o2 <= 127) { why = "100.64.0.0/10 CGNAT"; return 1 }
            if (o1 == 127) { why = "127.0.0.0/8";   return 1 }
            if (o1 == 169 && o2 == 254) { why = "169.254.0.0/16"; return 1 }
            if (o1 == 172 && o2 >= 16 && o2 <= 31) { why = "172.16.0.0/12"; return 1 }
            if (o1 == 192 && o2 == 0 && (o3 == 0 || o3 == 2)) { why = "192.0.0.0/24 / 192.0.2.0/24"; return 1 }
            if (o1 == 192 && o2 == 168) { why = "192.168.0.0/16"; return 1 }
            if (o1 == 198 && (o2 == 18 || o2 == 19)) { why = "198.18.0.0/15 RFC2544"; return 1 }
            if (o1 == 198 && o2 == 51 && o3 == 100) { why = "198.51.100.0/24"; return 1 }
            if (o1 == 203 && o2 == 0 && o3 == 113) { why = "203.0.113.0/24"; return 1 }
            if (o1 >= 224) { why = "224.0.0.0/4 multicast+reserved"; return 1 }
            return 0
        }
        # ── IPv6 ────────────────────────────────────────────────────────────
        # Textual prefix matching: awk has no 128-bit integer, and every range
        # that matters here is a clean prefix. Anything unmatched is treated
        # as routable, so the IPv6 side is deliberately the permissive one —
        # over-stripping is what lost the data in the first place.
        function v6_reserved(ip,    t, a, n) {
            t = tolower(ip)
            if (t == "::" || t == "::1") { why = "v6 unspecified/loopback"; return 1 }
            # IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible forms: judge the
            # embedded address by the v4 rules, not by the v6 prefix.
            if (index(t, "::ffff:") == 1 || index(t, "::ffff:0:") == 1) {
                n = split(t, a, ":")
                if (v4_reserved(a[n])) { why = why " (v4-mapped)"; return 1 }
                return 0
            }
            if (substr(t, 1, 2) == "fc" || substr(t, 1, 2) == "fd") {
                why = "fc00::/7 ULA"; return 1
            }
            if (substr(t, 1, 3) == "fe8" || substr(t, 1, 3) == "fe9" \
             || substr(t, 1, 3) == "fea" || substr(t, 1, 3) == "feb") {
                why = "fe80::/10 link-local"; return 1
            }
            if (substr(t, 1, 3) == "fec" || substr(t, 1, 3) == "fed" \
             || substr(t, 1, 3) == "fee" || substr(t, 1, 3) == "fef") {
                why = "fec0::/10 site-local (deprecated)"; return 1
            }
            if (substr(t, 1, 2) == "ff") { why = "ff00::/8 multicast"; return 1 }
            if (index(t, "2001:db8") == 1) { why = "2001:db8::/32 documentation"; return 1 }
            return 0
        }
        function is_reserved(ip,    a, n) {
            if (ip == "") return 0
            why = ""
            if (index(ip, ":") > 0) return v6_reserved(ip)
            return v4_reserved(ip)
        }
        function filter_reserved(ips, host,    a, i, k, out, t) {
            k = split(ips, a, ";")
            out = ""
            for (i = 1; i <= k; i++) {
                t = a[i]
                gsub(/^[ \t]+|[ \t]+$/, "", t)
                if (t == "") continue
                if (is_reserved(t)) {
                    print host "\t" t "\t" why >> bogon_log
                    continue
                }
                out = (out == "") ? t : out ";" t
            }
            return out
        }
        $1 == "hostname" && $2 == "root_domain" { print; next }
        {
            $4 = filter_reserved($4, $1)
            $5 = filter_reserved($5, $1)
            # A row that was "resolved" and lost every address to the filter is
            # a private-address record, whether or not it also carries a CNAME.
            # The old guard also required $6 == "", so a host whose only address
            # was CGNAT but which had a CNAME stayed "resolved" with an empty
            # address column — the same mislabel cname_only now covers, and the
            # reason those hosts reached httpx with no address to dial.
            if ($4 == "" && $5 == "" && $7 == "resolved") $7 = "bogon"
            print
        }
    ' "$tsv" > "${tsv}.bogon_filtered" && mv "${tsv}.bogon_filtered" "$tsv"

    # Report
    local resolved=0 nxdomain=0 timeout=0 bogon=0 still_pending=0 cname_only=0
    resolved=$(awk -F'\t' '$7 == "resolved" {count++} END {print count+0}' "$tsv")
    cname_only=$(awk -F'\t' '$7 == "cname_only" {count++} END {print count+0}' "$tsv")
    nxdomain=$(awk -F'\t' '$7 == "nxdomain" {count++} END {print count+0}' "$tsv")
    timeout=$(awk -F'\t' '$7 == "timeout" {count++} END {print count+0}' "$tsv")
    bogon=$(awk -F'\t' '$7 == "bogon" {count++} END {print count+0}' "$tsv")
    still_pending=$(awk -F'\t' '$7 == "pending" {count++} END {print count+0}' "$tsv")

    log_success "Canonical DNS: resolved=$resolved, cname_only=$cname_only, nxdomain=$nxdomain, timeout=$timeout, bogon=$bogon, pending=$still_pending"

    # Expose last-pass counts so callers can detect a dead-DNS environment
    # (fake-IP VPN or unreachable resolvers: nothing resolves, everything
    # bogon/timeout). Set in the current shell (this is a function, not a
    # subshell) so the calling stage can read them right after.
    CANONICAL_LAST_RESOLVED=$resolved
    CANONICAL_LAST_BOGON=$bogon
    CANONICAL_LAST_TIMEOUT=$timeout

    # ── DNS-health gate for include_timeouts retries ────────────────────────
    # "Healthy" means the TRANSPORT answered the queries — not that many names
    # resolved. A batch of 28K hostnames harvested from Certificate
    # Transparency is expected to be ~half NXDOMAIN; that is a working
    # resolver reporting real negatives, and it must NOT disable retries.
    # What disables them is a transport that could not answer at all.
    #
    # Both directions are gated on a minimum batch size. The previous
    # implementation only guarded the UNSET direction, so a 10-host batch that
    # happened to resolve 8 flipped the flag to healthy and re-armed a
    # 28,927-host re-grind that took 10 minutes and recovered 173 names.
    if (( pending_count >= _min_batch )); then
        if (( _answered * 100 >= pending_count * _min_pct )); then
            METHO_DNS_WORKING=1
            log_info "DNS health: transport '${DNS_TRANSPORT_LABEL:-${DNS_MODE}}' blackholed $(( pending_count - _answered ))/$pending_count hosts — below the $(( 100 - _min_pct ))% ceiling, so the transport is answering; timeout retries enabled"
            log_info "  ${_with_records}/${pending_count} of this batch returned an address or CNAME; the rest are negatives (NXDOMAIN/SERVFAIL), which the label pass below separates"
        else
            METHO_DNS_WORKING=0
            log_warn "DNS health: transport '${DNS_TRANSPORT_LABEL:-${DNS_MODE}}' blackholed $(( pending_count - _answered ))/$pending_count hosts — above the $(( 100 - _min_pct ))% ceiling; DNS UNHEALTHY, timeout retries disabled"
        fi
    else
        log_info "DNS health: batch of $pending_count is below the ${_min_batch}-query floor — health flag unchanged (was ${METHO_DNS_WORKING:-0})"
    fi

    # Persist the observation next to the dataset it was made against.
    #
    # Both the per-domain workers and the merge need this, and a shell variable
    # set inside a Phase 1 subshell does not survive it. Without the file the
    # merge had to GUESS, and it guessed with a resolution-rate heuristic that
    # answers a different question (see merge_per_domain_dns).
    printf '%s\n' "${METHO_DNS_WORKING:-0}" > "${tsv}.dns_health" 2>/dev/null || true

    if [[ "$bogon" -gt 0 ]]; then
        log_warn "Canonical DNS: $bogon host(s) resolved only to reserved/private addresses — excluded from port scanning."
        log_warn "  Address and matched range for each: ${_bogon_log}"
        # 198.18.0.0/15 is RFC 2544 benchmark space that a fake-IP VPN
        # (Clash/mihomo/Surge in fake-ip mode) substitutes for EVERY name it
        # resolves — but presence of the range is NOT evidence of injection.
        # On a real run the range appeared on 56 internal-looking Vodafone
        # names while the same dataset also carried 10.0.0.0/8 and 172.16.0.0/12
        # records for the same host population, and an independent query to a
        # public DoH endpoint returned those 198.18 addresses directly. They
        # are genuine published records for a carrier-internal range.
        #
        # A VPN can only substitute an answer it is on the path of, so the
        # range is a fake-IP signature only when the answer came through the
        # system resolver. On the DoH transport the local resolver is bypassed
        # by construction, which makes presence alone meaningless. The previous
        # wording asserted the VPN case whenever the range was present and sent
        # the operator to hunt a VPN problem that was not there — the same
        # defect as the unconditional text it replaced, just narrower.
        # The verdict is read from the audit file, so an ABSENT file is not
        # evidence of absence — it is absence of evidence. Saying otherwise is
        # how one run reported "present" from its per-domain pass and "not
        # present" from every merged pass, over the same 1,067 hosts, while the
        # merged .bogon was simply never written. Gate on the file existing
        # first; a genuinely empty-but-present file still means "no such range".
        if [[ ! -s "${_bogon_log}" ]]; then
            log_info "  Reserved-address detail is unavailable here (${_bogon_log} is empty) — the ${bogon} host(s) are still held out of scanning, but the address/range breakdown cannot be reported from this dataset. Per-domain logs under phase1/<domain>/ carry the evidence."
        elif grep -qE '(^|[[:space:]])198\.1[89]\.' "${_bogon_log}" 2>/dev/null; then
            if [[ "${DNS_TRANSPORT_LABEL:-${DNS_MODE}}" == "doh" ]]; then
                log_info "  198.18.0.0/15 (RFC 2544) is present, but every answer came from DoH — the local resolver is bypassed, so treat these as genuine published records, not a fake-IP VPN."
            else
                log_warn "  198.18.0.0/15 (RFC 2544) is present and answers came through the system resolver ('${DNS_TRANSPORT_LABEL:-${DNS_MODE}}') — check whether the VPN's fake-ip mode is substituting answers."
            fi
        else
            log_info "  No 198.18.0.0/15 present — these are genuine private-address records, not a fake-IP VPN."
        fi
        # "Unreachable from the internet" is not the same as "unreachable from
        # you". On a network routed into the target's private or CGNAT space
        # these hosts answer normally — two internal OpenSearch clusters replied
        # HTTP 200 from 100.64.x on a real run — so the exclusion has to be
        # visible and reversible rather than silent.
        if [[ "${METHO_PROBE_RESERVED:-0}" == "1" ]]; then
            log_info "  These hosts ARE being HTTP-probed (--probe-reserved) and are excluded only from port scanning."
        else
            log_info "  They are held out of the HTTP probe set too. If your network routes into that space they are reachable — set --probe-reserved to probe them (they stay out of naabu/nmap either way)."
        fi
    fi

    if [[ "$cname_only" -gt 0 ]]; then
        # Not a warning: a CNAME pointing at a name that no longer resolves is a
        # subdomain-takeover candidate, which is a finding, not a failure. It is
        # reported here and kept out of the probe set, because httpx cannot
        # connect to a name with no address and would only burn its timeout.
        log_info "Canonical DNS: $cname_only hostname(s) returned a CNAME but no address — held out of the probe set."
        log_info "  Each is either a dangling CNAME (takeover candidate) or a name that resolves only through another view."
        log_info "  Reported in: $tsv (resolution_status=cname_only)"
    fi

    rm -f "$pending_file" "$dnsx_json"
}

# ── Distinguish "this name does not exist" from "we could not ask" ─────────────
# canonical_dns_label_nxdomain
#
# Every hostname that produced no A/AAAA/CNAME is currently recorded as
# "timeout", which conflates two very different things:
#
#   * the name does not exist (NXDOMAIN) — settled, nothing was lost, and
#     re-resolving it on a later run is pure waste; and
#   * the resolver never answered — unresolved, possibly a live host that a
#     working transport would have found.
#
# Without the distinction the dataset cannot answer the only question that
# matters after a run that resolves 1% of its corpus: "is this a dead corpus
# or a dead transport?" During the observed run all 28,716 unanswered rows
# said "timeout", while an independent resolver showed ~43% of them exist.
#
# dnsx reports the rcode in JSON, but only for hosts it is asked to emit: with
# `-a -aaaa -cname` a host with no records of those types produces no line at
# all, which is why the rcode was never available. `-rcode nxdomain` with no
# record-type flags emits exactly the hosts that authoritatively do not exist.
#
# Runs once, at the end of the pipeline, over whatever is still unresolved —
# bounded by a wall-clock cap rather than a host cap so a large corpus is
# labelled as far as it gets instead of being skipped outright.
canonical_dns_label_nxdomain() {
    local tsv="${CANONICAL_DNS_TSV:-${OUTPUT_DIR}/canonical_dns.tsv}"
    [[ -s "$tsv" ]] || return 0

    if [[ "${METHO_NXDOMAIN_LABEL:-1}" == "0" ]]; then
        log_info "Canonical DNS: NXDOMAIN labelling disabled (METHO_NXDOMAIN_LABEL=0) — unresolved hosts stay 'timeout'"
        return 0
    fi

    local pile="${tsv}.nx_pile" map="${tsv}.nx_map" raw="${tsv}.nx_raw"
    awk -F'\t' '$1 == "hostname" && $2 == "root_domain" { next } $7 == "timeout" { print $1 }' \
        "$tsv" > "$pile"

    local n=0
    [[ -s "$pile" ]] && n=$(wc -l < "$pile")
    if (( n == 0 )); then
        rm -f "$pile"
        return 0
    fi
    if ! command -v dnsx &>/dev/null; then
        rm -f "$pile"
        return 0
    fi

    local cap="${DNSX_TIMEOUT}"
    local scaled=$(( n / 50 ))
    (( scaled > cap )) && cap=$scaled
    (( cap > 3600 )) && cap=3600

    log_info "Canonical DNS: confirming NXDOMAIN for ${n} unresolved hostname(s) (rcode pass, ${cap}s cap)"

    : > "$raw"
    cat "$pile" | timeout "$cap" dnsx \
        -silent -rcode nxdomain -json \
        -retry "${DNSX_RETRY}" \
        -r "${RESOLVERS_FILE:-/opt/scripts/wordlists/resolvers.txt}" \
        -timeout "$(_dnsx_query_timeout)" \
        -t "$(_dnsx_threads)" \
        2>/dev/null > "$raw" || true

    jq -r '(.host | ascii_downcase | sub("^[*][.]"; "") | sub("[.]$"; ""))' "$raw" 2>/dev/null \
        | sort -u > "$map" || : > "$map"

    local confirmed=0
    [[ -s "$map" ]] && confirmed=$(wc -l < "$map")

    if (( confirmed > 0 )); then
        awk -F'\t' -v OFS='\t' -v NR_FILE="$map" '
            BEGIN { while ((getline dl < NR_FILE) > 0) if (dl != "") nx[dl] = 1; close(NR_FILE) }
            $1 == "hostname" && $2 == "root_domain" { print; next }
            { if ($7 == "timeout" && ($1 in nx)) $7 = "nxdomain"; print }
        ' "$tsv" > "${tsv}.nx_applied" && mv "${tsv}.nx_applied" "$tsv"
        log_success "Canonical DNS: ${confirmed} hostname(s) confirmed NXDOMAIN — settled, not lost (the remaining $(awk -F'\t' '$7 == "timeout" {c++} END {print c+0}' "$tsv") 'timeout' rows are genuinely unresolved)"
    else
        log_warn "Canonical DNS: NXDOMAIN confirmation returned nothing for ${n} hostname(s) — they stay 'timeout' (unresolved, not proven dead)"
    fi

    rm -f "$pile" "$map" "$raw"
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

# ── Hostnames eligible for HTTP probing ───────────────────────────────────────
# Always the `resolved` set — hosts with an address. With METHO_PROBE_RESERVED=1
# it also includes `bogon` hosts, whose every address is reserved/private and was
# therefore stripped from the dataset.
#
# Why that is worth having: a `bogon` host is unreachable *from the internet*,
# which is not the same as unreachable from the operator. On a network routed
# into the target's private or CGNAT space those hosts answer normally — on a
# real run two internal OpenSearch clusters returned HTTP 200 from 100.64.x and
# were dropped from the probe set with no way to bring them back.
#
# HTTP ONLY, and off by default:
#   * httpx re-resolves every name itself, so it needs no recorded address. A
#     private space that is reachable is a space httpx can talk to.
#   * Port scanning is a different action. naabu and nmap need the address, and
#     aiming them at private space is far less defensible than one HTTP request
#     to a hostname the target's own DNS published. `bogon` hosts stay out of the
#     IP dataset, the ASN lookup, the classification, naabu and nmap regardless
#     of this flag — that split is deliberate, not an oversight.
#   * Off by default because the cost is real when the space is NOT routed: every
#     such host then costs an httpx timeout, and the address may route to
#     something unrelated to the target. 549 hosts sat in this bucket on that run
#     and 2 were live, so the flag is worth setting when you know, and the bogon
#     report says how many hosts are being held back when it is not.
canonical_dns_extract_probeable() {
    {
        canonical_dns_extract_resolved
        if [[ "${METHO_PROBE_RESERVED:-0}" == "1" ]]; then
            canonical_dns_extract_by_status "bogon"
        fi
    } | grep -v '^$' | sort -u
}



# ── Classify CNAME pairs against the resolved target sets ────────────────────
#   _takeover_classify <pairs.tsv> <alive.txt> <dead.txt>
#
# Pure: no network, no globals — the verdict logic is separated out so it can be
# unit-tested directly, since the expensive half of the check (resolution) is not
# something the test suite should exercise against real DNS.
#
# pairs.tsv rows are <hostname> <root_domain> <cname_target> [discovery_sources].
# Emits the same shape with a verdict inserted before the sources column.
_takeover_classify() {
    awk -F'\t' -v OFS='\t' -v alive="$2" -v dead="$3" '
        BEGIN {
            while ((getline l < alive) > 0) if (l != "") a[l] = 1
            close(alive)
            while ((getline l < dead) > 0) if (l != "") d[l] = 1
            close(dead)
        }
        NF < 3 { next }
        {
            t = tolower($3)
            sub(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, "", t)
            sub(/[\/:;?].*$/, "", t)
            sub(/^\.+/, "", t)
            if (t == "") next
            if (t in d)       v = "dangling"
            else if (t in a)  v = "alive"
            else              v = "unresolved"
            print $1, $2, t, v, $4
        }
    ' "$1"
}

# ── Dangling-CNAME (subdomain takeover) check ────────────────────────────────
#   canonical_dns_takeover_check
#
# The pipeline already computes the signal and then does nothing with it. A host
# whose only DNS answer is a CNAME (`resolution_status == cname_only`) is held out
# of the probe set because it has no address to dial — correct — but that is also
# the exact shape of a takeover candidate, and on a real run there were 1,166 of
# them, several pointing at other organisations' infrastructure
# (admin-lloydsemm.vodafone.com → cust015-padc-lb.vmshosting.co.uk,
# adminauth.officespaces.iot.vodafone.com → adminauth.vbofficespaces.com).
#
# The check itself is the CNAME chain resolution nobody was running: resolve each
# target and see whether it still exists.
#
#   target confirmed NXDOMAIN        → `dangling`    the chain points at a name
#                                                     that does not exist; anyone
#                                                     who can register it inherits
#                                                     the traffic
#   target resolves with an address  → `alive`       not a candidate
#   target answers nothing at all    → `unresolved`  weaker: could be a resolver
#                                                     view difference or a target
#                                                     that is NXDOMAIN only on
#                                                     some paths. Ranked below
#                                                     `dangling`, above nothing.
#
# Reuses _dnsx_resolve_to and the rcode pass, so the DoH transport, per-query
# timeouts, retry count and concurrency are the same ones the rest of the run
# used — a takeover verdict decided through a different resolver than the dataset
# would disagree with the dataset for no reason.
#
# Bounded two ways, and says so: METHO_TAKEOVER_MAX_TARGETS caps how many targets
# are resolved, and the rcode pass is capped like every other dnsx batch. Either
# bound being hit is recorded as a truncation, per the pipeline's contract that an
# absent stage_truncations.txt is what "complete" means.
#
# METHO_TAKEOVER_CHECK=0 disables it.
canonical_dns_takeover_check() {
    [[ "${METHO_TAKEOVER_CHECK:-1}" == "0" ]] && return 0
    local tsv="${CANONICAL_DNS_TSV:-${OUTPUT_DIR}/canonical_dns.tsv}"
    local fdir="${OUTPUT_DIR}/final"
    local out="${fdir}/final_takeover_candidates.txt"
    local work="${OUTPUT_DIR}/phase3/.takeover"
    mkdir -p "$fdir" "$work" 2>/dev/null || true

    local pairs="${work}/pairs.tsv"
    awk -F'\t' -v OFS='\t' '
        $1 == "hostname" && $2 == "root_domain" { next }
        $7 == "cname_only" && $6 != "" {
            n = split($6, a, ";")
            for (i = 1; i <= n; i++) if (a[i] != "") print $1, $2, a[i], $3
        }
    ' "$tsv" 2>/dev/null > "$pairs" || true

    local pair_count=0
    [[ -s "$pairs" ]] && pair_count=$(wc -l < "$pairs")
    if (( pair_count == 0 )); then
        log_info "Takeover check: no cname_only hosts — nothing to test"
        printf 'hostname\troot_domain\tcname_target\tverdict\tdiscovery_sources\n' > "$out"
        rm -rf "$work"
        return 0
    fi
    if ! command -v dnsx &>/dev/null; then
        log_warn "Takeover check: dnsx unavailable — skipping ${pair_count} cname_only pair(s)"
        printf 'hostname\troot_domain\tcname_target\tverdict\tdiscovery_sources\n' > "$out"
        rm -rf "$work"
        return 0
    fi

    # Distinct targets are what cost queries; the same ELB is typically pointed at
    # by dozens of hosts (51 hosts shared one k8s ingress on the run above).
    cut -f3 "$pairs" | _cloud_asset_normalize | sort -u > "${work}/targets.txt"
    local target_count=0
    [[ -s "${work}/targets.txt" ]] && target_count=$(wc -l < "${work}/targets.txt")

    local max_targets="${METHO_TAKEOVER_MAX_TARGETS:-5000}"
    if (( target_count > max_targets )); then
        head -n "$max_targets" "${work}/targets.txt" > "${work}/targets.capped"
        mv "${work}/targets.capped" "${work}/targets.txt"
        _record_truncation "all" "takeover-check" "${target_count} distinct CNAME targets exceed METHO_TAKEOVER_MAX_TARGETS=${max_targets} — ${max_targets} tested"
        log_warn "Takeover check: ${target_count} distinct targets exceed the ${max_targets} cap — testing the first ${max_targets} (raise METHO_TAKEOVER_MAX_TARGETS)"
        target_count=$max_targets
    fi

    log_info "Takeover check: resolving ${target_count} distinct CNAME target(s) behind ${pair_count} cname_only host(s)"

    local cap="${DNSX_TIMEOUT}"
    local scaled=$(( target_count / 50 ))
    (( scaled > cap )) && cap=$scaled
    (( cap > 3600 )) && cap=3600

    : > "${work}/resolve.json"
    _dnsx_resolve_to "${work}/targets.txt" "${work}/resolve.json" \
        "${RESOLVERS_FILE:-/opt/scripts/wordlists/resolvers.txt}" "$cap"

    # Targets that answered with an address are alive. dnsx only emits what it
    # resolves, so "absent from this list" means "gave us nothing".
    jq -r 'select(((.a // []) | length > 0) or ((.aaaa // []) | length > 0))
           | .host | ascii_downcase' "${work}/resolve.json" 2>/dev/null \
        | sort -u > "${work}/alive.txt" || : > "${work}/alive.txt"

    # Everything else gets the rcode pass, which separates a positively dead name
    # from one we merely could not ask about. Only a confirmed NXDOMAIN is called
    # dangling, matching the settlement policy used everywhere else.
    comm -23 "${work}/targets.txt" "${work}/alive.txt" > "${work}/unknown.txt" 2>/dev/null || true
    : > "${work}/dead.txt"
    if [[ -s "${work}/unknown.txt" ]]; then
        local n_cap="${DNSX_TIMEOUT}"
        local n_unknown
        n_unknown=$(wc -l < "${work}/unknown.txt" | tr -d '[:space:]')
        local n_scaled=$(( n_unknown / 50 ))
        (( n_scaled > n_cap )) && n_cap=$n_scaled
        (( n_cap > 3600 )) && n_cap=3600
        cat "${work}/unknown.txt" | timeout "$n_cap" dnsx \
            -silent -rcode nxdomain -json \
            -retry "${DNSX_RETRY}" \
            -r "${RESOLVERS_FILE:-/opt/scripts/wordlists/resolvers.txt}" \
            -timeout "$(_dnsx_query_timeout)" \
            -t "$(_dnsx_threads)" \
            2>/dev/null \
            | jq -r '(.host | ascii_downcase)' 2>/dev/null \
            | sort -u > "${work}/dead.txt" || : > "${work}/dead.txt"
    fi

    # Verdict per (host, target) pair, then a per-host roll-up so the file reads
    # "this host is dangling" rather than making the operator join targets back.
    printf 'hostname\troot_domain\tcname_target\tverdict\tdiscovery_sources\n' > "$out"
    _takeover_classify "$pairs" "${work}/alive.txt" "${work}/dead.txt" | sort -u >> "$out"

    local n_dangling=0 n_alive=0 n_unres=0
    n_dangling=$(awk -F'\t' '$4 == "dangling"' "$out" | wc -l | tr -d '[:space:]')
    n_alive=$(awk -F'\t' '$4 == "alive"' "$out" | wc -l | tr -d '[:space:]')
    n_unres=$(awk -F'\t' '$4 == "unresolved"' "$out" | wc -l | tr -d '[:space:]')

    if (( n_dangling > 0 )); then
        log_warn "Takeover check: ${n_dangling} DANGLING CNAME pair(s) — the target does not exist. See final/final_takeover_candidates.txt"
    fi
    log_success "Takeover check: ${n_dangling} dangling, ${n_unres} unresolved, ${n_alive} alive (from ${pair_count} cname_only host(s))"
    rm -rf "$work"
    return 0
}

# ── Merge the per-domain reserved-address audit logs ─────────────────────────
#   _bogon_merge_global <global_tsv> <per-domain tsv>...
#
# Unions every <per-domain-tsv>.bogon into <global_tsv>.bogon, reset once so a
# reused output directory cannot accumulate a previous run's evidence. Missing
# per-domain logs are normal (a domain with no reserved records never writes
# one) and are skipped silently; if NO domain produced one the global file is
# created empty, which the caller distinguishes from "no evidence available".
_bogon_merge_global() {
    local global_tsv="$1"; shift
    local out="${global_tsv}.bogon"
    : > "$out" 2>/dev/null || true
    local f
    for f in "$@"; do
        [[ -s "${f}.bogon" ]] && cat "${f}.bogon" >> "$out" 2>/dev/null
    done
    if [[ -s "$out" ]]; then
        sort -u "$out" -o "$out" 2>/dev/null || true
    fi
    return 0
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
#   - resolution_status: prefer resolved > cname_only > nxdomain > timeout > pending > bogon
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
    while IFS= read -r d; do
        [[ -n "$d" && -s "${d}canonical_dns.tsv" ]] && per_domain_tsvs+=("${d}canonical_dns.tsv")
    done < <(_root_domain_dirs)

    if [[ ${#per_domain_tsvs[@]} -gt 0 ]]; then
        printf 'hostname\troot_domain\tdiscovery_sources\tA\tAAAA\tCNAME\tresolution_status\n' > "$global_tsv"

        # Single awk pass: read all per-domain TSVs (skipping headers), group by
        # hostname, merge fields. Status priority: resolved=1, cname_only=2,
        # nxdomain=3, timeout=4, pending=5, bogon=6 (lower = higher priority).
        # cname_only ranks below resolved so that a host with an address in any
        # per-domain TSV keeps that address, and above nxdomain because a CNAME
        # answer is strictly more information than a negative.
        awk -F'\t' -v OFS='\t' '
            function status_rank(s) {
                if (s == "resolved") return 1
                if (s == "cname_only") return 2
                if (s == "nxdomain") return 3
                if (s == "timeout") return 4
                if (s == "pending") return 5
                if (s == "bogon") return 6
                return 7
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
            # Skip headers by content. A positional FNR==1 skip drops the first
            # real hostname of every per-domain TSV, which is exactly how
            # hosts discovered early were lost from the merged dataset.
            $1 == "hostname" && $2 == "root_domain" { next }
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

        # ── Merge the reserved-address audit logs ───────────────────────────
        # The per-domain pass STRIPS reserved addresses as it resolves, so by the
        # time the global TSV is assembled from those rows there is nothing left
        # in it to audit: every bogon row has empty A/AAAA by construction. The
        # evidence lives only in each domain's canonical_dns.tsv.bogon.
        #
        # The global file was never built from them, which produced a run that
        # contradicted itself in the same log. The per-domain pass printed
        # "198.18.0.0/15 (RFC 2544) is present" (126 matching rows in
        # phase1/vodafone.com/canonical_dns.tsv.bogon), and every merged pass
        # afterwards printed "No 198.18.0.0/15 present" — because the verdict is
        # decided by grepping ${tsv}.bogon, the file did not exist, and grep on a
        # missing file reports absence rather than ignorance. The bogon COUNT was
        # always right (it is read from TSV status), so only the verdict and the
        # trail were wrong — but the verdict is what tells an operator whether
        # 1,067 excluded hosts are a fake-IP VPN artefact or genuine published
        # private records, and it was answering from no evidence at all.
        #
        # Concatenated here rather than re-derived, so the merged file is exactly
        # the per-domain evidence and cannot drift from it.
        _bogon_merge_global "$global_tsv" "${per_domain_tsvs[@]}"

        local entry_count=0
        [[ -s "$global_tsv" ]] && entry_count=$(awk -F'\t' '$1 != "hostname"' "$global_tsv" | wc -l)
        log_success "Merged canonical DNS: $entry_count entries from ${#per_domain_tsvs[@]} per-domain TSVs"
        # METHO_DNS_WORKING is set inside the per-domain subshells during Phase 1
        # and does not survive into this (parent) shell. Read it back from the
        # per-dataset health files rather than re-deriving it.
        #
        # This used to be re-derived as "at least 2% of hostnames resolved" —
        # a different question from the one the flag asks, and the resolve path
        # above says why: the flag is about the TRANSPORT ("did the resolver
        # answer at all?"), and a resolution rate cannot answer it, because a
        # healthy transport on a genuinely dead corpus resolves ~0% while a dead
        # transport on a 3%-resolved corpus passes the test. So the same flag
        # meant one thing during Phase 1 and another in Phase 3, and the Phase 3
        # retry was governed by the weaker definition.
        METHO_DNS_WORKING=0
        local _health_file _health_any=0 _hd
        while IFS= read -r _hd; do
            _health_file="${_hd}canonical_dns.tsv.dns_health"
            if [[ -s "$_health_file" ]] && \
               [[ "$(head -1 "$_health_file" 2>/dev/null | tr -d '[:space:]')" == "1" ]]; then
                _health_any=1
            fi
        done < <(_root_domain_dirs)
        if (( _health_any )); then
            METHO_DNS_WORKING=1
            log_info "DNS health after merge: at least one domain observed a responsive transport — timeout retries enabled for Phase 3"
        else
            log_info "DNS health after merge: no domain recorded a responsive transport — timeout retries disabled for Phase 3"
        fi
    else
        log_warn "No per-domain canonical_dns.tsv files found to merge"
    fi

    # ── Merge httpx_metadata.tsv ────────────────────────────────────────────
    local per_domain_metas=()
    while IFS= read -r d; do
        [[ -n "$d" && -s "${d}httpx_metadata.tsv" ]] && per_domain_metas+=("${d}httpx_metadata.tsv")
    done < <(_root_domain_dirs)

    if [[ ${#per_domain_metas[@]} -gt 0 ]]; then
        printf 'hostname\tcdn\ttechnologies\twebserver\tcontent_length\tstatus_code\ttitle\turl\n' > "$global_meta"

        # Last record per host wins (same semantics as canonical_dns_merge_httpx).
        awk -F'\t' -v OFS='\t' '
            $1 == "hostname" { next }  # skip the metadata header
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
        [[ -s "$global_meta" ]] && meta_count=$(awk -F'\t' '$1 != "hostname"' "$global_meta" | wc -l)
        log_info "Merged HTTPx metadata: $meta_count entries from ${#per_domain_metas[@]} per-domain files"
    fi

    # ── Merge per-domain probe ledgers ──────────────────────────────────────
    merge_probe_ledgers
}

# ── This run's per-domain artifact directories ────────────────────────────────
# `phase1/*/` also matches directories left by earlier, unrelated runs in a
# reused output directory. Merging those imports hostnames nobody asked for this
# time, and — worse — their httpx_probed.txt entries make Phase 3 skip hosts
# this run resolved but never probed, because a previous run probed them.
# Filter to the root set actually being processed this run.
#
# Falls back to every directory when no root list is available (a caller that
# invokes the merge directly, as the test suite does), so behaviour is only
# narrowed when there is something to narrow by.
_root_domain_dirs() {
    local root_file="${OUTPUT_DIR}/root_domains.txt"
    local this_run=() _rd d base _r _match
    if [[ -s "$root_file" ]]; then
        while IFS= read -r _rd; do
            [[ -n "$_rd" ]] && this_run+=("$_rd")
        done < "$root_file"
    fi
    for d in "${OUTPUT_DIR}/phase1"/*/; do
        [[ -d "$d" ]] || continue
        if [[ ${#this_run[@]} -eq 0 ]]; then
            echo "$d"
            continue
        fi
        base="$(basename "$d")"
        _match=0
        for _r in "${this_run[@]}"; do
            if [[ "$base" == "$_r" ]]; then _match=1; break; fi
        done
        (( _match )) && echo "$d"
    done
}

# ── Merge per-domain probe ledgers into the global one ────────────────────────
# Union of every hostname any Phase 1 worker handed to httpx, responders and
# silent hosts alike. Phase 3's late pass diffs against it so it probes only
# genuinely-new hosts, instead of re-probing everything that was probed and
# stayed silent (7,905 targets — ~64% of a 47-minute round — on a real run).
#
# Callable on its own, and called that way from recon.sh when Phase 1 is
# skipped: merge_per_domain_dns only runs inside run_phase1, so `--skip-phase 1`
# would otherwise leave the global ledger empty (setup_dirs deletes it) and
# Phase 3 would silently re-probe the whole resolved set — the exact regression
# the ledger exists to prevent.
merge_probe_ledgers() {
    local global_ledger="${OUTPUT_DIR}/httpx_probed.txt"
    local p1_dir="${OUTPUT_DIR}/phase1"
    local per_domain_ledgers=() d
    while IFS= read -r d; do
        [[ -n "$d" && -s "${d}httpx_probed.txt" ]] && per_domain_ledgers+=("${d}httpx_probed.txt")
    done < <(_root_domain_dirs)

    if [[ ${#per_domain_ledgers[@]} -eq 0 ]]; then
        # Say so. An empty ledger is not neutral: it makes Phase 3 treat every
        # resolved host as never probed. Silence here is how a re-probe storm
        # becomes invisible.
        log_info "Probe ledger: no per-domain ledger found — Phase 3 will treat every resolved host as unprobed"
        return 0
    fi

    cat "${per_domain_ledgers[@]}" 2>/dev/null | sort -u > "$global_ledger" || true
    local ledger_count=0
    [[ -s "$global_ledger" ]] && ledger_count=$(wc -l < "$global_ledger" | tr -d '[:space:]')
    log_info "Merged probe ledger: ${ledger_count:-0} hostname(s) already probed by Phase 1"
}