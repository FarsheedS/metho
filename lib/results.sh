#!/usr/bin/env bash
# ── Per-Root-Domain Final Results ─────────────────────────────────────────────
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
# Design rules:
#   * Pure filtering/consolidation of EXISTING global datasets — no tools are
#     re-run, no raw artifacts are copied/duplicated.
#   * hostname→root_domain comes ONLY from the canonical DNS dataset's
#     root_domain column (never derived from the hostname's labels).
#   * Many-to-many IP↔root relationships are preserved: an IP shared by hosts
#     in different roots appears in every applicable root's results.
#   * All outputs are deduplicated.
#   * Existing phase1/phase2/phase3 + canonical files are untouched — this is
#     an additional, additive layer run after all phases complete.
#
# ── Why this is bucketed rather than a per-root loop ──────────────────────────
# The obvious implementation reads ROOT_DOMAINS_FILE and, for each root, scans
# the whole canonical TSV once per output file. That is O(roots × datasets)
# full scans: at 70 roots it is ~350 passes over a multi-million-row TSV plus
# 70 two-file joins, i.e. ten-plus minutes of pure re-reading, and the cost
# grows with both the root count and the corpus.
#
# Instead every global dataset is read exactly ONCE, and each row is tagged
# with the root it belongs to. Sorting the tagged stream groups a root's rows
# together, so the per-root files are then written by a single pass that keeps
# one file open at a time. Total work is a fixed handful of passes regardless
# of how many roots the run covers.

# ── Generate per-root-domain result directories ───────────────────────────────
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

    local root_list="${OUTPUT_DIR}/.results_roots.txt"
    _scaffold_root_dirs "$root_list" "$results_dir"

    local root_count=0
    [[ -s "$root_list" ]] && root_count=$(wc -l < "$root_list")
    if (( root_count == 0 )); then
        log_warn "generate_per_root_results: no root domains to slice"
        return 0
    fi

    local work="${OUTPUT_DIR}/.results_work"
    rm -rf "$work"
    mkdir -p "$work"

    _tag_root_slices "$work" "$root_list" "$dns_tsv" "$meta_tsv" "$class_tsv" \
                     "$ip_port_pairs" "$nmap_grep" "$cloud_global"

    _place_root_slices "$work" "$results_dir"

    _write_waymore_urls_per_root "$results_dir" "$root_list"

    rm -rf "$work"
    log_success "Per-root results written for ${root_count} root domain(s) under ${results_dir}/"
}

# ── Build the normalized root list and pre-create every output file ───────────
# Headers go in first: the placement pass appends, and a slice with no rows
# must still be a valid, self-describing file.
_scaffold_root_dirs() {
    local root_list="$1" results_dir="$2"
    : > "$root_list"

    # nmap's greppable header comments are identical for every root. Read them
    # ONCE rather than re-grepping the scan output per root.
    local nmap_comments=""
    if [[ -s "${OUTPUT_DIR}/phase3/port_scan_results.txt" ]]; then
        nmap_comments=$(grep '^#' "${OUTPUT_DIR}/phase3/port_scan_results.txt" 2>/dev/null || true)
    fi

    local root rdir
    while IFS= read -r root; do
        [[ -z "$root" ]] && continue
        root=$(normalize_hostname "$root")
        [[ -z "$root" ]] && continue
        printf '%s\n' "$root" >> "$root_list"

        rdir="${results_dir}/${root}"
        mkdir -p "${rdir}/nmap_results"

        : > "${rdir}/subdomains.txt"
        : > "${rdir}/ips.txt"
        : > "${rdir}/cloud_assets.txt"
        : > "${rdir}/nmap_results/ip_port_pairs.txt"
        printf 'hostname\tA\tAAAA\tCNAME\tresolution_status\n' > "${rdir}/dns_records.tsv"
        printf 'hostname\tdiscovery_sources\n'              > "${rdir}/discovery_sources.tsv"
        printf 'url\tstatus_code\ttitle\ttechnologies\twebserver\tcontent_length\tcdn\n' > "${rdir}/live_hosts.tsv"
        printf 'IP\tASN\tASN_org\tclassification\n'         > "${rdir}/ip_asn.tsv"

        if [[ -n "$nmap_comments" ]]; then
            printf '%s\n' "$nmap_comments" > "${rdir}/nmap_results/port_scan_results.txt"
        else
            : > "${rdir}/nmap_results/port_scan_results.txt"
        fi
    done < "$ROOT_DOMAINS_FILE"

    sort -u "$root_list" -o "$root_list"
}

# ── Read every global dataset ONCE, tagging each row with its root ───────────
_tag_root_slices() {
    local work="$1" root_list="$2" dns_tsv="$3" meta_tsv="$4" class_tsv="$5" \
          pairs="$6" nmapg="$7" cloud="$8"

    awk -F'\t' -v OFS='\t' \
        -v roots_file="$root_list" \
        -v dns_tsv="$dns_tsv" -v meta_tsv="$meta_tsv" -v class_tsv="$class_tsv" \
        -v pairs="$pairs" -v nmapg="$nmapg" -v cloud="$cloud" \
        -v work="$work" '
        function in_scope_of(host, r,   i, suf) {
            # Mirrors match_root_domain: exact root or ".root" suffix.
            if (host == r) return 1
            suf = "." r
            return substr(host, length(host) - length(suf) + 1) == suf
        }
        BEGIN {
            while ((getline r < roots_file) > 0) if (r != "") want[r] = 1
            close(roots_file)

            # ── canonical dataset: subdomains, records, sources, IPs, CNAMEs ──
            while ((getline line < dns_tsv) > 0) {
                n = split(line, f, "\t")
                if (n < 7) continue
                h = f[1]; r = f[2]
                # Header skipped by content, never by line number.
                if (h == "hostname" && r == "root_domain") continue
                if (r == "" || !(r in want)) continue
                # hostname -> root, reused by the metadata join below so the
                # canonical file is read exactly once.
                h2r[h] = r
                print r, h > (work "/subs.tsv")
                print r, h, f[4], f[5], f[6], f[7] > (work "/dns.tsv")
                print r, h, f[3] > (work "/src.tsv")
                if (f[4] != "") {
                    m = split(f[4], ips, ";")
                    for (i = 1; i <= m; i++) {
                        ip = ips[i]; gsub(/^[ \t]+|[ \t]+$/, "", ip)
                        if (ip == "") continue
                        print r, ip > (work "/ips.tsv")
                        # ip -> roots, for the port-scan attribution below.
                        if (index(";" ipr[ip] ";", ";" r ";") == 0)
                            ipr[ip] = (ipr[ip] == "" ? r : ipr[ip] ";" r)
                    }
                }
                if (f[6] != "") {
                    m = split(f[6], cns, ";")
                    for (i = 1; i <= m; i++) {
                        c = cns[i]; gsub(/^[ \t]+|[ \t]+$/, "", c)
                        if (c != "") print r, c > (work "/cname.tsv")
                    }
                }
            }
            close(dns_tsv)

            # ── httpx metadata -> live_hosts (join on hostname) ──
            if (meta_tsv != "") {
                while ((getline line < meta_tsv) > 0) {
                    n = split(line, f, "\t")
                    if (n < 2) continue
                    h = f[1]
                    if (h == "hostname") continue
                    r = h2r[h]
                    if (r == "" || !(r in want)) continue
                    print r, f[8], f[6], f[7], f[3], f[4], f[5], f[2] > (work "/live.tsv")
                }
                close(meta_tsv)
            }

            # ── IP classification -> ip_asn (root_domains may list several) ──
            if (class_tsv != "") {
                while ((getline line < class_tsv) > 0) {
                    n = split(line, f, "\t")
                    if (n < 6) continue
                    if (f[1] == "IP") continue
                    m = split(f[4], rds, ";")
                    for (i = 1; i <= m; i++) {
                        r = rds[i]
                        if (r != "" && (r in want)) print r, f[1], f[5], f[6], f[2] > (work "/asn.tsv")
                    }
                }
                close(class_tsv)
            }

            # ── port scan results -> per-root nmap (many-to-many via ipr) ──
            if (pairs != "") {
                while ((getline line < pairs) > 0) {
                    if (line == "") continue
                    ip = line; sub(/:.*/, "", ip)
                    if (!(ip in ipr)) continue
                    m = split(ipr[ip], rds, ";")
                    for (i = 1; i <= m; i++) if (rds[i] != "") print rds[i], line > (work "/ports.tsv")
                }
                close(pairs)
            }
            if (nmapg != "") {
                while ((getline line < nmapg) > 0) {
                    if (substr(line, 1, 1) == "#") continue   # written per root by the scaffold
                    if (substr(line, 1, 5) != "Host:") continue
                    split(line, g, " ")
                    ip = g[2]
                    if (!(ip in ipr)) continue
                    m = split(ipr[ip], rds, ";")
                    for (i = 1; i <= m; i++) if (rds[i] != "") print rds[i], line > (work "/nmapg.tsv")
                }
                close(nmapg)
            }

            # ── global cloud assets that ARE in scope for a root ──
            if (cloud != "") {
                while ((getline line < cloud) > 0) {
                    if (line == "") continue
                    v = tolower(line)
                    gsub(/^[ \t]*"|"[ \t]*$/, "", v)              # strip JSON quotes
                    sub(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, "", v)   # strip scheme
                    sub(/[\/:;?].*$/, "", v)                       # strip port/path
                    sub(/^\.+/, "", v)
                    if (v == "") continue
                    for (r in want) if (in_scope_of(v, r)) print r, v > (work "/cloud.tsv")
                }
                close(cloud)
            }
        }
    ' /dev/null
}
# ── Place the tagged streams into per-root files ─────────────────────────────
_place_root_slices() {
    local work="$1" results_dir="$2"

    # CNAME targets that point at cloud infrastructure are cloud assets too.
    # Filter them once, globally, then tag — the provider regex is the same for
    # every root, so there is no reason to run it per root.
    #
    # The target is NORMALIZED on the way through, which it was not. The CNAME
    # column is raw resolver output, so it preserves whatever case each record was
    # published in, and the same target commonly appears twice in one cell under
    # two cases (`af-stage-elb-….amazonaws.com;AF-STAGE-ELB-….amazonaws.com`).
    # Unnormalized, one asset became several rows here while the global aggregate
    # held a single lowercased copy — 33 entries existed in results/<root>/ and
    # not in final/, which is precisely the two-deliverables-disagree symptom this
    # change set is closing. Normalizing both sides makes the per-root file a
    # genuine subset of the aggregate and kills the case-duplicate rows.
    if [[ -s "${work}/cname.tsv" ]]; then
        cut -f2 "${work}/cname.tsv" | sort -u | _cloud_asset_normalize \
            | sort -u > "${work}/.cname_uniq"
        filter_cloud_domains "${work}/.cname_uniq" "${work}/.cname_cloud" || true
        if [[ -s "${work}/.cname_cloud" ]]; then
            # Re-tag: emit (root, normalized-target) for every CNAME whose
            # normalized form is a cloud endpoint.
            awk -F'\t' -v OFS='\t' '
                NR == FNR { keep[$1] = 1; next }
                {
                    v = tolower($2)
                    sub(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, "", v)
                    sub(/[\/:;?].*$/, "", v)
                    sub(/^\.+/, "", v)
                    if (v in keep) print $1, v
                }
            ' "${work}/.cname_cloud" "${work}/cname.tsv" | sort -u -t$'\t' -k1,1 \
                > "${work}/cnamecloud.tsv"
        fi
        rm -f "${work}/.cname_uniq" "${work}/.cname_cloud"
    fi

    _split_tagged "$work" "$results_dir" subs.tsv   subdomains.txt
    _split_tagged "$work" "$results_dir" dns.tsv    dns_records.tsv
    _split_tagged "$work" "$results_dir" src.tsv    discovery_sources.tsv
    _split_tagged "$work" "$results_dir" ips.tsv    ips.txt
    _split_tagged "$work" "$results_dir" live.tsv   live_hosts.tsv
    _split_tagged "$work" "$results_dir" asn.tsv    ip_asn.tsv
    _split_tagged "$work" "$results_dir" ports.tsv  nmap_results/ip_port_pairs.txt
    _split_tagged "$work" "$results_dir" nmapg.tsv  nmap_results/port_scan_results.txt
    _split_tagged "$work" "$results_dir" cloud.tsv  cloud_assets.txt
    _split_tagged "$work" "$results_dir" cnamecloud.tsv cloud_assets.txt

    # Restore the sort -u / dedup guarantees the slice files are documented to
    # have. The bucketing pass writes rows in canonical-TSV order, so each
    # output is sorted and de-duplicated here — on the small per-root files,
    # never on a global dataset.
    local root
    while IFS= read -r root; do
        [[ -z "$root" ]] && continue
        _normalize_root_slice "$results_dir" "$root"
    done < "$root_list"
}

# Write one tagged stream out as per-root files. The stream is sorted by its
# root column first, so all rows for a root are contiguous and only one output
# file is ever open — an early version of this opened one handle per root per
# output kind, which hits the process fd limit on a large target list.
_split_tagged() {
    local work="$1" results_dir="$2" tag="$3" dest="$4"
    local src="${work}/${tag}"
    [[ -s "$src" ]] || return 0

    sort -t$'\t' -k1,1 "$src" > "${src}.sorted"
    awk -F'\t' -v OFS='\t' -v base="$results_dir" -v dest="$dest" '
        {
            if ($1 != cur) {
                if (cur != "") close(curpath)
                cur = $1
                curpath = base "/" cur "/" dest
            }
            sub(/^[^\t]*\t/, "")
            print >> curpath
        }
        END { if (cur != "") close(curpath) }
    ' "${src}.sorted"
    rm -f "${src}.sorted"
}

# Restore the sort -u + dedup guarantees of every slice file. This runs on the
# small per-root files only, never on a global dataset.
_normalize_root_slice() {
    local results_dir="$1" root="$2"
    local d="${results_dir}/${root}"
    [[ -d "$d" ]] || return 0

    _sort_unique_in_place "${d}/subdomains.txt"
    _sort_unique_in_place "${d}/ips.txt" -V
    _sort_unique_in_place "${d}/cloud_assets.txt"
    _sort_unique_in_place "${d}/nmap_results/ip_port_pairs.txt"
    _sort_unique_tsv  "${d}/dns_records.tsv"
    _sort_unique_tsv  "${d}/discovery_sources.tsv"
    _sort_unique_tsv  "${d}/live_hosts.tsv"
    _sort_unique_tsv  "${d}/ip_asn.tsv"
}

_sort_unique_in_place() {
    local f="$1"; shift
    [[ -e "$f" ]] || return 0
    if [[ ! -s "$f" ]]; then
        : > "$f"
        return 0
    fi
    # Nothing to order or dedupe in a single line. A large target list has many
    # roots with a handful of rows (or none), and skipping the fork for those
    # is the difference between a couple of seconds and twenty.
    local _n
    _n=$(wc -l < "$f")
    (( _n < 2 )) && return 0
    sort -u "$@" "$f" -o "$f"
}

# Sort a TSV's data rows, keeping its header on line 1.
_sort_unique_tsv() {
    local f="$1"
    [[ -s "$f" ]] || return 0
    local _n
    _n=$(wc -l < "$f")
    (( _n < 3 )) && return 0     # header only, or header + one row
    local tmp="${f}.srt"
    head -1 "$f" > "$tmp"
    tail -n +2 "$f" | sort -u >> "$tmp"
    mv "$tmp" "$f"
}

# ── waymore_urls.txt: historical URLs for this root ──────────────────────────
# Waymore runs per-root in Phase 1, so phase1/<root>/waymore_urls.txt already
# holds this root's URLs — dedupe and present, no re-crawl and no global scan.
_write_waymore_urls_per_root() {
    local results_dir="$1" root_list="$2"
    local p1_dir="${OUTPUT_DIR}/phase1"

    local d1 r
    for d1 in "$p1_dir"/*/; do
        [[ -d "$d1" ]] || continue
        r=$(normalize_hostname "$(basename "$d1")")
        [[ -z "$r" ]] && continue
        grep -qxF -- "$r" "$root_list" 2>/dev/null || continue
        if [[ -s "${d1}waymore_urls.txt" ]]; then
            sort -u "${d1}waymore_urls.txt" > "${results_dir}/${r}/waymore_urls.txt"
        else
            : > "${results_dir}/${r}/waymore_urls.txt"
        fi
    done

    # A root whose Phase 1 directory is missing still gets an (empty) file, so
    # the per-root output layout is uniform.
    local root
    while IFS= read -r root; do
        [[ -z "$root" ]] && continue
        [[ -f "${results_dir}/${root}/waymore_urls.txt" ]] || \
            : > "${results_dir}/${root}/waymore_urls.txt"
    done < "$root_list"
}
