#!/usr/bin/env bash
# ── Deterministic IP / CDN / ASN Classification ───────────────────────────────
#
# This library provides deterministic IP classification based on:
#   1. HTTPX CDN metadata (explicit CDN detection)
#   2. ASN matching against configured CDN/cloud/dedicated ASN lists
#   3. ASN organization name matching against configured provider name lists
#
# Classification rules (applied in this exact order):
#   IF HTTPX explicitly reports CDN = true            → "cdn"
#   ELSE IF ASN/provider matches CDN config          → "cdn"
#   ELSE IF ASN/provider matches cloud config        → "cloud"
#   ELSE IF ASN/provider matches dedicated config    → "dedicated"
#   ELSE                                              → "unknown"
#
# An IP receives exactly ONE primary classification.
# CDN IPs are retained in results but excluded from nmap scanning.

# ── Load ASN configuration ────────────────────────────────────────────────────
# Sources config/asn_providers.sh (or override via --asn-config).
# Populates: CDN_ASNS, CDN_PROVIDER_NAMES, CLOUD_ASNS, CLOUD_PROVIDER_NAMES,
#            DEDICATED_ASNS, DEDICATED_PROVIDER_NAMES
load_asn_config() {
    local config_file="${ASN_CONFIG_FILE:-/opt/scripts/config/asn_providers.sh}"

    if [[ ! -f "$config_file" ]]; then
        log_error "ASN config file not found: $config_file"
        log_error "Use --asn-config FILE or ensure config/asn_providers.sh is installed"
        return 1
    fi

    # Source the config — it defines bash arrays
    source "$config_file"

    # Validate that the arrays were actually loaded
    if [[ ${#CDN_ASNS[@]} -eq 0 ]]; then
        log_error "ASN config loaded but CDN_ASNS is empty — check $config_file"
        return 1
    fi

    log_info "Loaded ASN config: ${#CDN_ASNS[@]} CDN ASNs, ${#CLOUD_ASNS[@]} cloud ASNs, ${#DEDICATED_ASNS[@]} dedicated ASNs"
}

# ── Classify a single IP ──────────────────────────────────────────────────────
# classify_ip <ip> <asn> <asn_org> <httpx_cdn>
#
# Returns one of: cdn, cloud, dedicated, unknown
#
# Arguments:
#   ip         — the IP address (e.g., "1.2.3.4")
#   asn        — ASN string (e.g., "AS13335"), may be empty
#   asn_org    — ASN organization name (e.g., "Cloudflare, Inc."), may be empty
#   httpx_cdn  — "true" or "false" from HTTPX CDN detection, may be empty
classify_ip() {
    local ip="$1" asn="$2" asn_org="$3" httpx_cdn="$4"

    # Rule 1: HTTPX explicitly reports CDN = true
    if [[ "$httpx_cdn" == "true" ]]; then
        echo "cdn"
        return
    fi

    # Normalize asn_org to lowercase for substring matching
    local asn_org_lower
    asn_org_lower=$(echo "$asn_org" | tr '[:upper:]' '[:lower:]')

    # Rule 2: ASN matches CDN config
    local cdn_asn
    for cdn_asn in "${CDN_ASNS[@]}"; do
        [[ "$asn" == "$cdn_asn" ]] && { echo "cdn"; return; }
    done

    # Rule 3: ASN org name matches CDN provider names (substring match)
    local name
    for name in "${CDN_PROVIDER_NAMES[@]}"; do
        [[ "$asn_org_lower" == *"$name"* ]] && { echo "cdn"; return; }
    done

    # Rule 4: ASN matches cloud config
    local cloud_asn
    for cloud_asn in "${CLOUD_ASNS[@]}"; do
        [[ "$asn" == "$cloud_asn" ]] && { echo "cloud"; return; }
    done

    # Rule 5: ASN org name matches cloud provider names
    for name in "${CLOUD_PROVIDER_NAMES[@]}"; do
        [[ "$asn_org_lower" == *"$name"* ]] && { echo "cloud"; return; }
    done

    # Rule 6: ASN matches dedicated hosting config
    local dedicated_asn
    for dedicated_asn in "${DEDICATED_ASNS[@]}"; do
        [[ "$asn" == "$dedicated_asn" ]] && { echo "dedicated"; return; }
    done

    # Rule 7: ASN org name matches dedicated hosting provider names
    for name in "${DEDICATED_PROVIDER_NAMES[@]}"; do
        [[ "$asn_org_lower" == *"$name"* ]] && { echo "dedicated"; return; }
    done

    # Rule 8: Default — unknown
    echo "unknown"
}

# ── Build IP classification datasets ─────────────────────────────────────────
# write_ip_datasets <domain_ip_map_file> <ip_asn_map_file> <output_dir>
#
# Reads:
#   domain_ip_map_file  — TSV: hostname IP (from canonical DNS)
#   ip_asn_map_file     — TSV: IP|ASN|Org|Prefix (from cymru whois)
#   httpx_metadata.tsv   — HTTPX CDN/tech/webserver metadata
#
# Produces in <output_dir>:
#   all_resolved_ips.txt     — all unique resolved IPs
#   cdn_ips.txt              — IPs classified as CDN
#   non_cdn_ips.txt           — IPs classified as cloud + dedicated + unknown
#   nmap_candidates.txt      — IPs classified as dedicated + cloud + unknown (same as non_cdn minus CDN)
#   ip_classification.tsv    — IP  classification  associated_hostnames  root_domains  ASN  ASN_org
write_ip_datasets() {
    local domain_ip_map="$1"
    local ip_asn_map="$2"
    local pdir="$3"

    local class_tsv="${pdir}/ip_classification.tsv"
    local meta_tsv="${OUTPUT_DIR}/httpx_metadata.tsv"

    log_info "Building IP classification datasets..."

    # Header
    printf 'IP\tclassification\tassociated_hostnames\troot_domains\tASN\tASN_org\n' > "$class_tsv"

    # Build associative arrays for ASN data and HTTPX metadata
    # Since pure bash associative arrays can't hold multiple fields per key,
    # we use temp files and awk for the join.

    # Step 1: Build a file of IP → hostname(s) and root_domain(s) from domain_ip_map
    # domain_ip_map format: "hostname IP" (space-separated, one line per pair)
    local ip_hosts="${pdir}/.ip_hosts.tmp"
    : > "$ip_hosts"
    if [[ -s "$domain_ip_map" ]]; then
        # First, get hostname→root_domain mapping from canonical DNS
        local dns_tsv="${OUTPUT_DIR}/canonical_dns.tsv"
        # Join domain_ip_map with canonical_dns on hostname to get root_domain
        # domain_ip_map: hostname IP
        # canonical_dns.tsv: hostname\troot_domain\t...
        # Output: IP hostname root_domain
        awk -F'\t' 'NR==FNR { h2rd[$1] = $2; next }
        { print $2, $1, h2rd[$1] }' "$dns_tsv" "$domain_ip_map" > "${ip_hosts}.raw"
        # Aggregate: for each IP, collect all hostnames and root_domains
        awk '{
            ip = $1; host = $2; rd = $3
            if (ip == "" || ip == "hostname") next
            hosts[ip] = (ip in hosts) ? hosts[ip] ";" host : host
            if (rd != "") {
                if (!(ip in rds)) rds[ip] = rd
                else if (index(rds[ip], rd) == 0) rds[ip] = rds[ip] ";" rd
            }
        }
        END {
            for (ip in hosts) {
                printf "%s\t%s\t%s\n", ip, hosts[ip], rds[ip]
            }
        }' "${ip_hosts}.raw" > "$ip_hosts"
        rm -f "${ip_hosts}.raw"
    fi

    # Step 2: Build a file of IP → ASN and ASN_org from ip_asn_map
    # ip_asn_map format: IP|ASN|Org|Prefix (pipe-separated)
    local ip_asn="${pdir}/.ip_asn_lookup.tmp"
    : > "$ip_asn"
    if [[ -s "$ip_asn_map" ]]; then
        awk -F'|' 'NR>1 || $1 != "IP" {
            gsub(/^[ \t]+|[ \t]+$/, "", $1)
            gsub(/^[ \t]+|[ \t]+$/, "", $2)
            gsub(/^[ \t]+|[ \t]+$/, "", $3)
            # Skip header-like lines
            if ($1 == "IP" || $1 == "") next
            asn = ($2 != "") ? "AS" $2 : ""
            printf "%s\t%s\t%s\n", $1, asn, $3
        }' "$ip_asn_map" > "$ip_asn"
    fi

    # Step 3: Build IP → HTTPX CDN lookup from httpx_metadata.tsv
    # For each IP, check if ANY of its associated hostnames has CDN=true in HTTPX
    local ip_httpx_cdn="${pdir}/.ip_httpx_cdn.tmp"
    : > "$ip_httpx_cdn"
    if [[ -s "$meta_tsv" ]] && [[ -s "$ip_hosts" ]]; then
        # First build hostname→cdn lookup from httpx metadata
        local host_cdn="${pdir}/.host_cdn.tmp"
        awk -F'\t' 'NR>1 { print $1 "\t" $2 }' "$meta_tsv" > "$host_cdn"

        # For each IP, check all its hostnames for CDN=true
        while IFS=$'\t' read -r ip hosts rest; do
            [[ -z "$ip" ]] && continue
            local cdn_found="false"
            IFS=';' read -ra host_arr <<< "$hosts"
            for h in "${host_arr[@]}"; do
                local h_cdn
                h_cdn=$(awk -F'\t' -v hh="$h" '$1 == hh {print $2; exit}' "$host_cdn" 2>/dev/null)
                if [[ "$h_cdn" == "true" ]]; then
                    cdn_found="true"
                    break
                fi
            done
            printf '%s\t%s\n' "$ip" "$cdn_found" >> "$ip_httpx_cdn"
        done < "$ip_hosts"
        rm -f "$host_cdn"
    fi

    # Step 4: For each IP, classify and write to ip_classification.tsv
    local all_ips="${pdir}/all_ips.tmp"
    : > "$all_ips"

    if [[ -s "$ip_hosts" ]]; then
        # Get unique IPs from ip_hosts
        cut -f1 "$ip_hosts" | sort -u > "$all_ips"
    elif [[ -s "$ip_asn" ]]; then
        # Fallback: use IPs from ASN map
        cut -f1 "$ip_asn" | sort -u > "$all_ips"
    fi

    local cdn_count=0 cloud_count=0 dedicated_count=0 unknown_count=0

    while IFS= read -r ip; do
        [[ -z "$ip" ]] && continue

        # Look up associated hostnames and root domains
        local hosts="" root_domains=""
        if [[ -s "$ip_hosts" ]]; then
            local line
            line=$(awk -F'\t' -v i="$ip" '$1 == i {print $0; exit}' "$ip_hosts" 2>/dev/null)
            if [[ -n "$line" ]]; then
                hosts=$(echo "$line" | cut -f2)
                root_domains=$(echo "$line" | cut -f3)
            fi
        fi

        # Look up ASN and org
        local asn="" asn_org=""
        if [[ -s "$ip_asn" ]]; then
            local line
            line=$(awk -F'\t' -v i="$ip" '$1 == i {print $0; exit}' "$ip_asn" 2>/dev/null)
            if [[ -n "$line" ]]; then
                asn=$(echo "$line" | cut -f2)
                asn_org=$(echo "$line" | cut -f3)
            fi
        fi

        # Look up HTTPX CDN flag
        local httpx_cdn="false"
        if [[ -s "$ip_httpx_cdn" ]]; then
            local line
            line=$(awk -F'\t' -v i="$ip" '$1 == i {print $2; exit}' "$ip_httpx_cdn" 2>/dev/null)
            [[ "$line" == "true" ]] && httpx_cdn="true"
        fi

        # Classify
        local classification
        classification=$(classify_ip "$ip" "$asn" "$asn_org" "$httpx_cdn")

        # Write to classification TSV
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$ip" "$classification" "$hosts" "$root_domains" "$asn" "$asn_org" >> "$class_tsv"

        # Count
        case "$classification" in
            cdn)       ((cdn_count++)) || true ;;
            cloud)     ((cloud_count++)) || true ;;
            dedicated) ((dedicated_count++)) || true ;;
            unknown)   ((unknown_count++)) || true ;;
        esac
    done < "$all_ips"

    # Step 5: Produce the separate IP files
    if [[ -s "$class_tsv" ]]; then
        # all_resolved_ips.txt
        tail -n +2 "$class_tsv" | cut -f1 | sort -u -V > "${pdir}/all_resolved_ips.txt"

        # cdn_ips.txt
        awk -F'\t' '$2 == "cdn" {print $1}' "$class_tsv" | sort -u -V > "${pdir}/cdn_ips.txt"

        # non_cdn_ips.txt (cloud + dedicated + unknown)
        awk -F'\t' '$2 != "cdn" {print $1}' "$class_tsv" | sort -u -V > "${pdir}/non_cdn_ips.txt"

        # nmap_candidates.txt (dedicated + cloud + unknown — same as non-CDN)
        # This is intentionally identical to non_cdn_ips.txt for the default case.
        # In the future, one could exclude "cloud" IPs from nmap if desired.
        cp "${pdir}/non_cdn_ips.txt" "${pdir}/nmap_candidates.txt"
    else
        : > "${pdir}/all_resolved_ips.txt"
        : > "${pdir}/cdn_ips.txt"
        : > "${pdir}/non_cdn_ips.txt"
        : > "${pdir}/nmap_candidates.txt"
    fi

    log_success "IP classification: CDN=$cdn_count, Cloud=$cloud_count, Dedicated=$dedicated_count, Unknown=$unknown_count"

    # Clean up temp files
    rm -f "$ip_hosts" "$ip_asn" "$ip_httpx_cdn" "$all_ips"

    # Log the classification details
    if [[ -s "$class_tsv" ]]; then
        log_info "Classification breakdown:"
        log_info "  CDN IPs:       $cdn_count"
        log_info "  Cloud IPs:     $cloud_count"
        log_info "  Dedicated IPs: $dedicated_count"
        log_info "  Unknown IPs:   $unknown_count"
        log_info "  Nmap targets:  $(wc -l < "${pdir}/nmap_candidates.txt" 2>/dev/null || echo 0)"
    fi
}