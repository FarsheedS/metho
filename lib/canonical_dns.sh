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
    local tsv="${OUTPUT_DIR}/canonical_dns.tsv"
    printf 'hostname\troot_domain\tdiscovery_sources\tA\tAAAA\tCNAME\tresolution_status\n' > "$tsv"
    log_info "Initialized canonical DNS dataset: $tsv"
}

# ── Normalize a hostname ──────────────────────────────────────────────────────
# Strip leading *. wildcard, lowercase, strip trailing dot.
normalize_hostname() {
    echo "$1" | sed 's/^\*\.//; s/\.$//' | tr '[:upper:]' '[:lower:]'
}

# ── Add hostnames with their source ───────────────────────────────────────────
# canonical_dns_add_sources <source_name> <hostnames_file> [root_domain]
#
# Reads hostnames from <hostnames_file> (one per line, already filtered to
# in-scope), normalizes them, and adds them to the canonical TSV.
#   - New hostnames get resolution_status=pending and the given source.
#   - Existing hostnames get the source appended to discovery_sources (deduped).
#   - If root_domain is not given, it is derived from the hostname.
canonical_dns_add_sources() {
    local source="$1" hostnames_file="$2"
    local tsv="${OUTPUT_DIR}/canonical_dns.tsv"

    if [[ ! -s "$hostnames_file" ]]; then
        log_warn "canonical_dns_add_sources: $hostnames_file is empty or missing, skipping"
        return
    fi

    # Ensure the TSV exists with a header
    if [[ ! -s "$tsv" ]]; then
        init_canonical_dns
    fi

    local added=0 skipped=0

    while IFS= read -r raw_host; do
        [[ -z "$raw_host" ]] && continue
        local host
        host=$(normalize_hostname "$raw_host")
        [[ -z "$host" ]] && continue

        # Derive root_domain: the last two labels of the hostname.
        # This works for e.g. "sub.example.com" → "example.com".
        # For single-label hosts (rare), use the host itself.
        local root_domain
        root_domain=$(echo "$host" | awk -F. '{if(NF>=2) print $(NF-1)"."$NF; else print $0}')

        # Check if hostname already exists in the TSV
        local existing_line
        existing_line=$(awk -F'\t' -v h="$host" '$1 == h {print NR; exit}' "$tsv" 2>/dev/null || true)

        if [[ -n "$existing_line" ]]; then
            # Hostname exists — append source to discovery_sources if not already present
            local current_sources
            current_sources=$(awk -F'\t' -v h="$host" '$1 == h {print $3; exit}' "$tsv")
            if [[ ";${current_sources};" != *";${source};"* ]]; then
                # Append the new source
                local new_sources="${current_sources};${source}"
                # Use a temp file for safe in-place editing
                local tmp="${tsv}.tmp"
                awk -F'\t' -v h="$host" -v s="$new_sources" -v OFS='\t' '
                    $1 == h { $3 = s }
                    { print }
                ' "$tsv" > "$tmp" && mv "$tmp" "$tsv"
            fi
            ((skipped++)) || true
        else
            # New hostname — add as pending
            printf '%s\t%s\t%s\t\t\t\tpending\n' "$host" "$root_domain" "$source" >> "$tsv"
            ((added++)) || true
        fi
    done < "$hostnames_file"

    log_info "Canonical DNS: added $added new hostnames from $source, updated $skipped existing"
}

# ── Resolve pending hostnames via DNSx ─────────────────────────────────────────
# canonical_dns_resolve_pending [extra_flags...]
#
# Extracts all hostnames with resolution_status=pending, runs them through
# dnsx for A/AAAA/CNAME resolution, and updates the TSV in-place.
# Any extra flags (e.g., -r resolvers.txt) are passed through to dnsx.
canonical_dns_resolve_pending() {
    local tsv="${OUTPUT_DIR}/canonical_dns.tsv"
    local pending_file="${OUTPUT_DIR}/.pending_hosts.txt"
    local dnsx_json="${OUTPUT_DIR}/.pending_dnsx.json"

    if [[ ! -s "$tsv" ]]; then
        log_warn "canonical_dns_resolve_pending: TSV does not exist"
        return
    fi

    # Extract pending hostnames
    awk -F'\t' '$7 == "pending" {print $1}' "$tsv" > "$pending_file"

    local pending_count=0
    [[ -s "$pending_file" ]] && pending_count=$(wc -l < "$pending_file")

    if [[ "$pending_count" -eq 0 ]]; then
        log_info "Canonical DNS: no pending hostnames to resolve"
        rm -f "$pending_file" "$dnsx_json"
        return
    fi

    log_info "Canonical DNS: resolving $pending_count pending hostnames via DNSx"

    if ! command -v dnsx &>/dev/null; then
        log_error "dnsx not found — cannot resolve pending hostnames"
        rm -f "$pending_file" "$dnsx_json"
        return 1
    fi

    : > "$dnsx_json"

    cat "$pending_file" | timeout "${DNSX_TIMEOUT:-600}" dnsx \
        -silent -a -aaaa -cname -json -retry 2 \
        -r /opt/scripts/wordlists/resolvers.txt \
        -timeout 5 \
        2>/dev/null > "$dnsx_json" || true

    # Build a lookup of hostname → DNS results from dnsx JSONL
    local dnsx_tmp="${tsv}.dnsx_tmp"

    # Mark all pending hosts as "timeout" initially (will be overridden if dnsx resolves them)
    local tmp="${tsv}.resolve_tmp"

    # Start with a copy
    cp "$tsv" "$tmp"

    # First, mark all pending hosts as timeout (default — overridden if dnsx resolves them)
    awk -F'\t' -v OFS='\t' '
        $7 == "pending" { $7 = "timeout" }
        { print }
    ' "$tmp" > "${tmp}.2" && mv "${tmp}.2" "$tmp"

    # Then update from dnsx results
    if [[ -s "$dnsx_json" ]]; then
        # Parse dnsx JSONL: for each record, extract host, A, AAAA, CNAME
        # dnsx JSON fields: .host, .a[], .aaaa[], .cname[]
        while IFS= read -r line; do
            local host a_records aaaa_records cname_records
            host=$(echo "$line" | jq -r '.host // empty' 2>/dev/null)
            [[ -z "$host" ]] && continue
            host=$(normalize_hostname "$host")

            a_records=$(echo "$line" | jq -r 'if .a then (.a | join(";")) else "" end' 2>/dev/null)
            aaaa_records=$(echo "$line" | jq -r 'if .aaaa then (.aaaa | join(";")) else "" end' 2>/dev/null)
            cname_records=$(echo "$line" | jq -r 'if .cname then (.cname | join(";")) else "" end' 2>/dev/null)

            local status="resolved"
            # If we have no A, AAAA, or CNAME records, check if it's an nxdomain
            if [[ -z "$a_records" && -z "$aaaa_records" && -z "$cname_records" ]]; then
                # dnsx returns the host with empty records for timeouts;
                # nxdomain typically produces no output at all.
                # If we got here with empty records, it's likely a timeout.
                status="nxdomain"
            fi

            # Update the TSV row for this hostname
            awk -F'\t' -v h="$host" -v a="$a_records" -v aaaa="$aaaa_records" \
                -v cname="$cname_records" -v st="$status" -v OFS='\t' '
                $1 == h {
                    if (a != "") $4 = a
                    if (aaaa != "") $5 = aaaa
                    if (cname != "") $6 = cname
                    $7 = st
                }
                { print }
            ' "$tmp" > "${tmp}.3" && mv "${tmp}.3" "$tmp"
        done < "$dnsx_json"
    fi

    # Replace the original TSV with the updated one
    mv "$tmp" "$tsv"

    # Report
    local resolved=0 nxdomain=0 timeout=0 still_pending=0
    resolved=$(awk -F'\t' '$7 == "resolved" {count++} END {print count+0}' "$tsv")
    nxdomain=$(awk -F'\t' '$7 == "nxdomain" {count++} END {print count+0}' "$tsv")
    timeout=$(awk -F'\t' '$7 == "timeout" {count++} END {print count+0}' "$tsv")
    still_pending=$(awk -F'\t' '$7 == "pending" {count++} END {print count+0}' "$tsv")

    log_success "Canonical DNS: resolved=$resolved, nxdomain=$nxdomain, timeout=$timeout, pending=$still_pending"

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
    local meta_tsv="${OUTPUT_DIR}/httpx_metadata.tsv"

    if [[ ! -s "$httpx_json" ]]; then
        log_warn "canonical_dns_merge_httpx: $httpx_json is empty or missing"
        return
    fi

    # Write header if file doesn't exist yet
    if [[ ! -s "$meta_tsv" ]]; then
        printf 'hostname\tcdn\ttechnologies\twebserver\tcontent_length\tstatus_code\ttitle\turl\n' > "$meta_tsv"
    fi

    # Parse each JSONL line and extract metadata
    while IFS= read -r line; do
        local host cdn tech webserver content_length status_code title url
        host=$(echo "$line" | jq -r '.host // empty' 2>/dev/null)
        [[ -z "$host" ]] && continue
        host=$(normalize_hostname "$host")

        cdn=$(echo "$line" | jq -r 'if .cdn != null then (.cdn | tostring) else "" end' 2>/dev/null)
        # httpx "tech" is a JSON array of STRINGS (not objects), per the
        # Result struct in runner/types.go: `Technologies []string json:"tech"`.
        # Join directly — no per-element .name extraction needed.
        tech=$(echo "$line" | jq -r 'if .tech then (.tech | join(";")) else "" end' 2>/dev/null)
        # httpx web-server field is "webserver" (json tag), NOT "server".
        webserver=$(echo "$line" | jq -r '.webserver // ""' 2>/dev/null)
        content_length=$(echo "$line" | jq -r '.content_length // ""' 2>/dev/null)
        status_code=$(echo "$line" | jq -r '.status_code // ""' 2>/dev/null)
        title=$(echo "$line" | jq -r '.title // ""' 2>/dev/null)
        url=$(echo "$line" | jq -r '.url // ""' 2>/dev/null)

        # Check if host already exists in metadata — if so, update; if not, append
        local existing
        existing=$(awk -F'\t' -v h="$host" '$1 == h {print NR; exit}' "$meta_tsv" 2>/dev/null || true)
        if [[ -n "$existing" ]]; then
            # Update existing row — prefer the richer record (more fields filled)
            local tmp="${meta_tsv}.tmp"
            awk -F'\t' -v h="$host" -v c="$cdn" -v t="$tech" -v w="$webserver" \
                -v cl="$content_length" -v sc="$status_code" -v ti="$title" -v u="$url" \
                -v OFS='\t' '
                $1 == h {
                    $2 = c; $3 = t; $4 = w; $5 = cl; $6 = sc; $7 = ti; $8 = u
                }
                { print }
            ' "$meta_tsv" > "$tmp" && mv "$tmp" "$meta_tsv"
        else
            printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                "$host" "$cdn" "$tech" "$webserver" "$content_length" "$status_code" "$title" "$url" \
                >> "$meta_tsv"
        fi
    done < "$httpx_json"

    log_info "Canonical DNS: merged HTTPX metadata from $httpx_json"
}

# ── Extract all hostnames from the canonical dataset ──────────────────────────
canonical_dns_extract_hostnames() {
    local tsv="${OUTPUT_DIR}/canonical_dns.tsv"
    if [[ ! -s "$tsv" ]]; then
        echo ""
        return
    fi
    # Skip header, print column 1
    tail -n +2 "$tsv" | awk -F'\t' '{print $1}'
}

# ── Extract all unique resolved IPs (A records) ──────────────────────────────
canonical_dns_extract_ips() {
    local tsv="${OUTPUT_DIR}/canonical_dns.tsv"
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
    local tsv="${OUTPUT_DIR}/canonical_dns.tsv"
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
    local meta_tsv="${OUTPUT_DIR}/httpx_metadata.tsv"
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