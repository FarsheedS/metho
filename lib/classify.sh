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
        # domain_ip_map: hostname<space>IP (written by phase3 with a single
        # space separator — NOT a tab). The earlier -F"\t" here never split
        # it, silently producing empty hosts/root_domains downstream.
        # Output: IP hostname root_domain
        awk 'NR==FNR { h2rd[$1] = $2; next }
        { print $2, $1, h2rd[$1] }' "$dns_tsv" "$domain_ip_map" > "${ip_hosts}.raw"
        # Aggregate: for each IP, collect all hostnames and root_domains.
        # NOTE: do NOT use `(ip in hosts)` in a ternary — mawk (Debian's
        # default awk) CREATES the array element when testing `in` on some
        # paths, so every first host got a spurious leading ";". Test the
        # accumulated string length instead.
        awk '{
            ip = $1; host = $2; rd = $3
            if (ip == "" || ip == "hostname") next
            if (length(hosts[ip]) > 0) hosts[ip] = hosts[ip] ";" host
            else hosts[ip] = host
            if (rd != "") {
                if (length(rds[ip]) == 0) rds[ip] = rd
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
    # ip_asn_map format: IP|ASN|Org|Prefix (pipe-separated, ASN already "AS"-prefixed
    # by Phase 3's awk). We trim whitespace and skip the header line only.
    local ip_asn="${pdir}/.ip_asn_lookup.tmp"
    : > "$ip_asn"
    if [[ -s "$ip_asn_map" ]]; then
        awk -F'|' 'NR>1 || $1 != "IP" {
            gsub(/^[ \t]+|[ \t]+$/, "", $1)   # IP
            gsub(/^[ \t]+|[ \t]+$/, "", $2)   # ASN (already "AS" + number)
            gsub(/^[ \t]+|[ \t]+$/, "", $3)   # Org name (may contain spaces, no pipes)
            # Skip header-like lines
            if ($1 == "IP" || $1 == "") next
            # ASN is already prefixed with "AS" by Phase 3 — do NOT prepend again.
            printf "%s\t%s\t%s\n", $1, $2, $3
        }' "$ip_asn_map" > "$ip_asn"
    fi

    # Step 3: Build IP → HTTPX CDN lookup from httpx_metadata.tsv
    # For each IP, true if ANY associated hostname has CDN=true in HTTPX.
    # Single awk pass (was: one awk spawn per hostname per IP).
    local ip_httpx_cdn="${pdir}/.ip_httpx_cdn.tmp"
    : > "$ip_httpx_cdn"
    if [[ -s "$meta_tsv" ]] && [[ -s "$ip_hosts" ]]; then
        awk -F'\t' -v OFS='\t' -v META="$meta_tsv" '
            BEGIN {
                while ((getline ml < META) > 0) {
                    split(ml, mm, "\t")
                    if (mm[1] != "" && mm[1] != "hostname" && mm[2] == "true")
                        cdn_host[mm[1]] = 1
                }
                close(META)
            }
            FNR == 1 { next }
            {
                n = split($2, hh, ";")
                found = "false"
                for (i = 1; i <= n; i++)
                    if (hh[i] in cdn_host) { found = "true"; break }
                print $1, found
            }
        ' "$ip_hosts" > "$ip_httpx_cdn"
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

    # Batch classification: one awk pass applies the SAME rule order as
    # classify_ip (httpx cdn → cdn asn → cdn org-substring → cloud asn →
    # cloud org-substring → dedicated asn → dedicated org-substring →
    # unknown). The previous per-IP bash loop (an echo + substring scan per
    # IP) ran at ~100 IPs/s — minutes for a large corpus; this is seconds.
    # The ASN/provider arrays are passed as files to keep the awk program
    # free of shell-quoting hazards.
    local _cd="${pdir}/.cfg_cdn_asn"    _cn="${pdir}/.cfg_cdn_names"
    local _cl="${pdir}/.cfg_cloud_asn"  _cln="${pdir}/.cfg_cloud_names"
    local _de="${pdir}/.cfg_ded_asn"    _den="${pdir}/.cfg_ded_names"
    printf '%s\n' "${CDN_ASNS[@]:-}"        > "$_cd"
    printf '%s\n' "${CDN_PROVIDER_NAMES[@]:-}"   > "$_cn"
    printf '%s\n' "${CLOUD_ASNS[@]:-}"      > "$_cl"
    printf '%s\n' "${CLOUD_PROVIDER_NAMES[@]:-}" > "$_cln"
    printf '%s\n' "${DEDICATED_ASNS[@]:-}"  > "$_de"
    printf '%s\n' "${DEDICATED_PROVIDER_NAMES[@]:-}" > "$_den"

    awk -F'\t' -v OFS='\t' \
        -v out="$class_tsv" \
        -v f_hosts="$ip_hosts" -v f_asn="$ip_asn" -v f_cdn="$ip_httpx_cdn" \
        -v f_cdn_asn="$_cd" -v f_cdn_nm="$_cn" \
        -v f_cloud_asn="$_cl" -v f_cloud_nm="$_cln" \
        -v f_ded_asn="$_de" -v f_ded_nm="$_den" '
        function load_keys(f,   l) { while ((getline l < f) > 0) if (l != "") cfg[f, l] = 1; close(f) }
        function load_map(f, m,   l, p) {
            while ((getline l < f) > 0) {
                split(l, p, "\t")
                if (p[1] != "") m[p[1]] = p[2] "\t" p[3]
            }
            close(f)
        }
        # Substring org-name match against a provider-name set file.
        function org_match(nmf, org_l,   l) {
            if (org_l == "") return 0
            while ((getline l < nmf) > 0)
                if (l != "" && index(org_l, l) > 0) { close(nmf); return 1 }
            close(nmf)
            return 0
        }
        BEGIN {
            load_keys(f_cdn_asn); load_keys(f_cloud_asn); load_keys(f_ded_asn)
            load_map(f_hosts, hosts_map)   # ip \t hosts \t root_domains
            load_map(f_asn, asn_map)       # ip \t asn \t org
            load_map(f_cdn, cdn_map)       # ip \t true/false
        }
        {
            ip = $1
            split(hosts_map[ip], hh, "\t"); hosts = hh[1]; rds = hh[2]
            split(asn_map[ip], aa, "\t");   asn = aa[1];   org = aa[2]
            org_l = tolower(org)
            hcdn = (cdn_map[ip] == "true") ? "true" : "false"
            cls = "unknown"
            if (hcdn == "true") cls = "cdn"
            else if ((f_cdn_asn, asn) in cfg) cls = "cdn"
            else if (org_match(f_cdn_nm, org_l)) cls = "cdn"
            else if ((f_cloud_asn, asn) in cfg) cls = "cloud"
            else if (org_match(f_cloud_nm, org_l)) cls = "cloud"
            else if ((f_ded_asn, asn) in cfg) cls = "dedicated"
            else if (org_match(f_ded_nm, org_l)) cls = "dedicated"
            printf "%s\t%s\t%s\t%s\t%s\t%s\n", ip, cls, hosts, rds, asn, org >> out
        }
    ' "$all_ips"

    cdn_count=$(awk -F'\t' 'FNR>1 && $2=="cdn" {n++} END{print n+0}' "$class_tsv")
    cloud_count=$(awk -F'\t' 'FNR>1 && $2=="cloud" {n++} END{print n+0}' "$class_tsv")
    dedicated_count=$(awk -F'\t' 'FNR>1 && $2=="dedicated" {n++} END{print n+0}' "$class_tsv")
    unknown_count=$(awk -F'\t' 'FNR>1 && $2=="unknown" {n++} END{print n+0}' "$class_tsv")
    rm -f "$_cd" "$_cn" "$_cl" "$_cln" "$_de" "$_den"

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