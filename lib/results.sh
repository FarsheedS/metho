#!/usr/bin/env bash
# ── Per-Root-Domain Final Results ──────────────────────────────────────────────
#
# A presentation layer that carves the GLOBAL canonical datasets into clean,
# human-consumable per-root-domain result directories:
#
#   output/results/<root-domain>/
#       subdomains.txt         in-scope hostnames for this root
#       dns_records.tsv        canonical DNS info for those hosts
#       live_hosts.tsv         HTTPX results (url, status, title, tech, …)
#       ips.txt                unique IPs associated with this root
#       ip_asn.tsv             IP, ASN, org, classification
#       nmap_results/          nmap output for this root's IPs
#       cloud_assets.txt       cloud assets attributed to this root
#       waymore_urls.txt       historical URLs for this root
#       discovery_sources.tsv  hostname → discovery provenance
#
# Design rules (see the enhancement spec):
#   * Pure filtering/consolidation of EXISTING global datasets — no tools are
#     re-run, no raw artifacts are copied/duplicated.
#   * hostname→root_domain comes ONLY from the canonical DNS dataset's
#     root_domain column (never derived from the hostname's labels).
#   * Many-to-many IP↔root relationships are preserved: an IP shared by hosts
#     in different roots appears in every applicable root's results.
#   * All outputs are deduplicated.
#   * Existing phase1/phase2/phase3 + canonical files are untouched — this is
#     an additional, additive layer run after all phases complete.

# ── Generate per-root-domain result directories ───────────────────────────────
# Reads ROOT_DOMAINS_FILE and the global datasets, writing one directory per
# root under ${OUTPUT_DIR}/results/<root>/.
generate_per_root_results() {
    local results_dir="${OUTPUT_DIR}/results"
    mkdir -p "$results_dir"

    local dns_tsv="${OUTPUT_DIR}/canonical_dns.tsv"
    if [[ ! -s "$dns_tsv" ]]; then
        log_warn "generate_per_root_results: canonical_dns.tsv missing — nothing to slice"
        return 0
    fi

    # Global datasets we slice from (each may be absent if its phase was skipped).
    local meta_tsv="${OUTPUT_DIR}/httpx_metadata.tsv"
    local class_tsv="${OUTPUT_DIR}/phase3/ip_classification.tsv"
    local ip_port_pairs="${OUTPUT_DIR}/phase3/ip_port_pairs.txt"
    local nmap_grep="${OUTPUT_DIR}/phase3/port_scan_results.txt"
    local cloud_global="${OUTPUT_DIR}/phase2/final_cloud_assets.txt"

    log_info "═══ Per-Root-Domain Results ═══"

    local root
    while IFS= read -r root; do
        [[ -z "$root" ]] && continue
        root=$(normalize_hostname "$root")
        [[ -z "$root" ]] && continue

        local rdir="${results_dir}/${root}"
        mkdir -p "${rdir}/nmap_results"

        log_info "Slicing results for root domain: $root"

        # Resolve the phase1 directory for this root (its name may differ in
        # case/normalization from ROOT_DOMAINS_FILE). Fall back to a glob match.
        local p1_dir=""
        local d
        for d in "${OUTPUT_DIR}"/phase1/*/; do
            [[ -d "$d" ]] || continue
            if [[ "$(normalize_hostname "$(basename "$d")")" == "$root" ]]; then
                p1_dir="$d"
                break
            fi
        done

        _write_subdomains        "$rdir" "$dns_tsv" "$root"
        _write_dns_records       "$rdir" "$dns_tsv" "$root"
        _write_live_hosts        "$rdir" "$dns_tsv" "$meta_tsv" "$root"
        _write_ips               "$rdir" "$dns_tsv" "$root"
        _write_ip_asn            "$rdir" "$class_tsv" "$root"
        _write_nmap_results      "$rdir" "$ip_port_pairs" "$nmap_grep"
        _write_cloud_assets      "$rdir" "$dns_tsv" "$cloud_global" "$root"
        _write_waymore_urls      "$rdir" "$p1_dir"
        _write_discovery_sources "$rdir" "$dns_tsv" "$root"

    done < "$ROOT_DOMAINS_FILE"

    local root_count
    root_count=$(grep -c . "$ROOT_DOMAINS_FILE" 2>/dev/null || echo 0)
    log_success "Per-root results written for $root_count root domain(s) under ${results_dir}/"
}

# ── subdomains.txt: all in-scope hostnames for this root ──────────────────────
_write_subdomains() {
    local rdir="$1" dns_tsv="$2" root="$3"
    awk -F'\t' -v rd="$root" 'FNR>1 && $2==rd {print $1}' "$dns_tsv" \
        | sort -u > "${rdir}/subdomains.txt"
}

# ── dns_records.tsv: canonical DNS info for those hosts ───────────────────────
_write_dns_records() {
    local rdir="$1" dns_tsv="$2" root="$3"
    printf 'hostname\tA\tAAAA\tCNAME\tresolution_status\n' > "${rdir}/dns_records.tsv"
    awk -F'\t' -v rd="$root" -v OFS='\t' 'FNR>1 && $2==rd {print $1,$4,$5,$6,$7}' "$dns_tsv" \
        | sort -u >> "${rdir}/dns_records.tsv"
}

# ── live_hosts.tsv: HTTPX results joined to this root via canonical DNS ───────
# httpx_metadata.tsv columns: hostname cdn technologies webserver content_length status_code title url
# Output columns: url status_code title technologies webserver content_length cdn
_write_live_hosts() {
    local rdir="$1" dns_tsv="$2" meta_tsv="$3" root="$4"
    printf 'url\tstatus_code\ttitle\ttechnologies\twebserver\tcontent_length\tcdn\n' > "${rdir}/live_hosts.tsv"
    if [[ ! -s "$meta_tsv" ]]; then
        return
    fi
    # Join: build hostname→root map from canonical DNS, then filter httpx rows
    # whose host belongs to this root. FNR==1 skips both file headers.
    awk -F'\t' -v rd="$root" -v OFS='\t' '
        FNR==1 { next }
        NR==FNR { rd_map[$1]=$2; next }
        ($1 in rd_map) && rd_map[$1]==rd { print $8,$6,$7,$3,$4,$5,$2 }
    ' "$dns_tsv" "$meta_tsv" | sort -u >> "${rdir}/live_hosts.tsv"
}

# ── ips.txt: unique IPs from A records of this root's hosts ───────────────────
_write_ips() {
    local rdir="$1" dns_tsv="$2" root="$3"
    : > "${rdir}/ips.txt"
    awk -F'\t' -v rd="$root" '
        FNR>1 && $2==rd && $4!="" {
            n = split($4, ips, ";")
            for (i=1; i<=n; i++) {
                gsub(/^[ \t]+|[ \t]+$/, "", ips[i])
                if (ips[i] != "") print ips[i]
            }
        }
    ' "$dns_tsv" | sort -u -V > "${rdir}/ips.txt"
}

# ── ip_asn.tsv: IP/ASN/org/classification for IPs of this root ────────────────
# ip_classification.tsv columns: IP classification associated_hostnames root_domains ASN ASN_org
# An IP belongs to this root if root (column 4) contains <root> as an element.
_write_ip_asn() {
    local rdir="$1" class_tsv="$2" root="$3"
    printf 'IP\tASN\tASN_org\tclassification\n' > "${rdir}/ip_asn.tsv"
    if [[ ! -s "$class_tsv" ]]; then
        return
    fi
    awk -F'\t' -v rd="$root" -v OFS='\t' '
        FNR>1 && index(";"$4";", ";"rd";")>0 { print $1,$5,$6,$2 }
    ' "$class_tsv" | sort -u >> "${rdir}/ip_asn.tsv"
}

# ── nmap_results/: nmap output for this root's IPs ────────────────────────────
# Filters ip_port_pairs.txt (IP:port) and the greppable port_scan_results.txt
# to only IPs present in this root's ips.txt (many-to-many preserved).
_write_nmap_results() {
    local rdir="$1" ip_port_pairs="$2" nmap_grep="$3"
    local ips_file="${rdir}/ips.txt"

    # ip_port_pairs.txt: "IP:port" — keep pairs whose IP is in ips.txt.
    if [[ -s "$ip_port_pairs" && -s "$ips_file" ]]; then
        awk -F':' '
            NR==FNR { ips[$1]=1; next }
            ($1 in ips) { print }
        ' "$ips_file" "$ip_port_pairs" | sort -u > "${rdir}/nmap_results/ip_port_pairs.txt"
    else
        : > "${rdir}/nmap_results/ip_port_pairs.txt"
    fi

    # port_scan_results.txt: nmap -oG greppable. Keep Host: lines whose IP
    # (field 2) is in ips.txt; preserve nmap comment/metadata lines.
    if [[ -s "$nmap_grep" && -s "$ips_file" ]]; then
        awk -v ips_file="$ips_file" '
            BEGIN {
                while ((getline line < ips_file) > 0) ips[line]=1
                close(ips_file)
            }
            /^#/ { print; next }
            /^Host:/ {
                ip = $2
                if (ip in ips) print
            }
        ' "$nmap_grep" > "${rdir}/nmap_results/port_scan_results.txt"
    else
        : > "${rdir}/nmap_results/port_scan_results.txt"
    fi
}

# ── cloud_assets.txt: cloud assets attributed to this root ────────────────────
# Two attribution signals, both from existing data (no tools re-run):
#   1. CNAME targets of this root's hosts that point at cloud infra
#      (extracted from canonical_dns.tsv, filtered via filter_cloud_domains).
#   2. Global cloud assets (phase2/final_cloud_assets.txt) that are themselves
#      subdomains of this root.
_write_cloud_assets() {
    local rdir="$1" dns_tsv="$2" cloud_global="$3" root="$4"
    : > "${rdir}/cloud_assets.txt"

    # Source 1: CNAME targets for this root's hosts, filtered to cloud patterns.
    local cname_tmp="${rdir}/.cnames.tmp"
    if [[ -s "$dns_tsv" ]]; then
        awk -F'\t' -v rd="$root" '
            FNR>1 && $2==rd && $6!="" {
                n = split($6, cnames, ";")
                for (i=1; i<=n; i++) {
                    gsub(/^[ \t]+|[ \t]+$/, "", cnames[i])
                    if (cnames[i] != "") print cnames[i]
                }
            }
        ' "$dns_tsv" > "$cname_tmp"
        if [[ -s "$cname_tmp" ]]; then
            filter_cloud_domains "$cname_tmp" "${cname_tmp}.cloud" || true
            [[ -s "${cname_tmp}.cloud" ]] && cat "${cname_tmp}.cloud" >> "${rdir}/cloud_assets.txt"
        fi
    fi
    rm -f "$cname_tmp" "${cname_tmp}.cloud"

    # Source 2: global cloud assets that are subdomains of this root.
    if [[ -s "$cloud_global" ]]; then
        local escaped_root="${root//./\\.}"
        grep -E "(^|\.)(${escaped_root})$" "$cloud_global" >> "${rdir}/cloud_assets.txt" 2>/dev/null || true
    fi

    sort -u "${rdir}/cloud_assets.txt" -o "${rdir}/cloud_assets.txt" 2>/dev/null || : > "${rdir}/cloud_assets.txt"
}

# ── waymore_urls.txt: historical URLs for this root ───────────────────────────
# Waymore runs per-root in Phase 1, so phase1/<root>/waymore_urls.txt already
# holds this root's URLs — dedupe and present, no re-crawl.
_write_waymore_urls() {
    local rdir="$1" p1_dir="$2"
    if [[ -n "$p1_dir" && -s "${p1_dir}waymore_urls.txt" ]]; then
        sort -u "${p1_dir}waymore_urls.txt" > "${rdir}/waymore_urls.txt"
    else
        : > "${rdir}/waymore_urls.txt"
    fi
}

# ── discovery_sources.tsv: hostname → discovery provenance ────────────────────
_write_discovery_sources() {
    local rdir="$1" dns_tsv="$2" root="$3"
    printf 'hostname\tdiscovery_sources\n' > "${rdir}/discovery_sources.tsv"
    awk -F'\t' -v rd="$root" -v OFS='\t' 'FNR>1 && $2==rd {print $1,$3}' "$dns_tsv" \
        | sort -u >> "${rdir}/discovery_sources.tsv"
}
