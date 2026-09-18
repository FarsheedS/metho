#!/usr/bin/env bash
# Shared utility functions for the Metho recon pipeline.

# ── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ── Logging ─────────────────────────────────────────────────────────────────
LOG_FILE=""

init_log() {
    LOG_FILE="${OUTPUT_DIR}/recon.log"
    : > "$LOG_FILE"
    log_info "Log file: $LOG_FILE"
}

_log_ts() { date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo '?'; }

# Unix-seconds timestamp. Used by phase stages to log wall-clock
# duration without spawning `date` repeatedly. Falls back to the
# timestamp helper if epoch isn't available (e.g. some BSD variants).
_now() { date +%s 2>/dev/null || date '+%Y%m%d%H%M%S' | sed 's/^/0/'; }

# Pretty-print a duration in seconds as e.g. "2m 14s" or "47s".
_format_duration() {
    local secs="$1"
    if [[ "$secs" -lt 60 ]]; then
        echo "${secs}s"
    elif [[ "$secs" -lt 3600 ]]; then
        echo "$((secs / 60))m $((secs % 60))s"
    else
        echo "$((secs / 3600))h $(((secs % 3600) / 60))m"
    fi
}

# Turn a URL/host string into a filename-safe token (drop :/, etc.).
_safe_name() {
    printf '%s' "$1" | tr -c '[:alnum:].-' '_'
}

# ── Resolver loading ─────────────────────────────────────────────────────────
# RESOLVERS_FILE is what every dnsx call resolves through. Three paths:
#
#   * --dns-mode doh (DEFAULT): a local DoH proxy (lib/doh_proxy.py) listens on
#     127.0.0.1 and forwards every query over DNS-over-HTTPS on TCP/443.
#     RESOLVERS_FILE becomes a one-line file pointing at it, so dnsx keeps
#     doing the resolving and only the transport changes.
#
#     Why a proxy and not dnsx's own `doh:` resolvers: dnsx v1.3.1 cannot
#     complete a DoH query at all. `doh:https://…` fails with
#     `Post "https://…/dns-query": EOF` and `dot:`/`tcp:` return zero results,
#     on networks where curl and Python POST the identical request to the
#     identical endpoint and get HTTP 200. The resolver STRING format is right
#     (retryabledns' parseResolver() documents exactly that form) — the client
#     is what is broken. Putting the transport in a process we control also
#     means the endpoint-failover behaviour is ours to get right: on the
#     network this was developed against, 1.1.1.1 answered promptly while
#     8.8.8.8/9.9.9.9 accepted TCP then went silent, and naive round-robin
#     sent a third of all queries into that hole.
#
#     This is the default because plain UDP/53 against a large public pool is
#     what fails in practice: the shipped 12.7K trickest list resolved 74% of
#     a known-good sample and collapses under a bulk burst.
#   * --dns-mode udp: built-in static list (wordlists/resolvers.txt, ~12.7K
#     trickest entries) used as-is with NO health-check. retryabledns (dnsx's
#     engine) round-robins resolvers and each retry automatically moves to the
#     NEXT resolver in the list (client.go: Do → index%len(resolvers) →
#     continue on error), so a few dead entries cost little. Note the flip
#     side: a MOSTLY dead list is still ruinous, which is why the runtime
#     quality gate below exists.
#   * Custom list via --resolvers FILE or URL (takes precedence over
#     --dns-mode): if the value is an http(s) URL it is downloaded first. A
#     user-supplied list may be mostly dead, so it IS health-checked, at high
#     parallelism so even 13K entries take ~2 min. If nothing survives, fall
#     back to the system resolver (which answers where corporate firewalls
#     block external UDP/53) rather than a dead list.
#
# A failing transport is also detected AT RUNTIME: canonical_dns_resolve_pending
# measures how many queries were ANSWERED (not how many names resolved), and
# escalates the batch to the fallback transport when the answer rate collapses.
# A startup check alone cannot catch a network that breaks mid-run — which is
# exactly what happened in the run that motivated this: DNS worked for the
# first domain, collapsed when the 28K-hostname batch hit, and every remaining
# stage quietly recorded the loss as "timeout".
load_resolvers() {
    local src="${RESOLVERS_SOURCE:-/opt/scripts/wordlists/resolvers.txt}"
    RESOLVERS_FILE="$src"

    # Accept a URL for --resolvers: download once, use the local copy.
    if [[ "$src" =~ ^https?:// ]]; then
        local dl="${OUTPUT_DIR}/resolvers_custom.txt"
        log_info "Downloading resolver list from $src ..."
        if curl -sL --max-time 120 -o "$dl" "$src" && [[ -s "$dl" ]]; then
            src="$dl"
            RESOLVERS_FILE="$src"
            log_success "Resolver list downloaded: $(grep -cvE '^[[:space:]]*(#|$)' "$src") resolvers → $src"
        else
            log_error "Failed to download resolver list from $src — falling back to built-in list"
            src="${RESOLVERS_SOURCE_BUILTIN:-/opt/scripts/wordlists/resolvers.txt}"
            RESOLVERS_FILE="$src"
        fi
    fi

    if [[ ! -s "$src" ]]; then
        log_warn "Resolver list missing/empty: $src — DNS resolution will likely fail"
        return
    fi

    # Built-in static list + doh mode → bring up the local DoH proxy.
    # (An explicit --resolvers file/URL wins over --dns-mode.)
    if [[ "$src" == "${RESOLVERS_SOURCE_BUILTIN:-/opt/scripts/wordlists/resolvers.txt}" ]]; then
        if [[ "${DNS_MODE}" == "doh" ]]; then
            # Never propagate a failure: this function already falls back to
            # the UDP pool on its own, and load_resolvers is called bare from
            # recon.sh, so a non-zero return would abort the whole run under
            # `set -e` — precisely when the fallback has just succeeded.
            _load_doh_resolvers || true
        else
            log_info "Resolvers: using built-in list ($(grep -cvE '^[[:space:]]*(#|$)' "$src") entries, no health-check — dnsx retries across the pool)"
        fi
        return
    fi

    # Custom list → health-check it, then use only the survivors.
    log_info "Custom resolver list: health-checking $(grep -cvE '^[[:space:]]*(#|$)' "$src") resolvers ..."
    _health_check_resolvers "$src"
}

# ── Local DoH proxy lifecycle ────────────────────────────────────────────────
# The proxy is a child of this shell. It is stopped by the EXIT trap so a
# failed or interrupted run does not leave it holding a UDP port.
DOH_PROXY_PID=""
DOH_PROXY_PORT=""

# Directory holding this script, so the proxy can be found whether the tree is
# mounted at /opt/scripts or run straight from a checkout.
_metho_lib_dir() {
    ( cd "$(dirname "${BASH_SOURCE[0]}")" && pwd )
}

# Start lib/doh_proxy.py and point RESOLVERS_FILE at it.
# Returns 0 only when the proxy is listening AND answered a real query.
_load_doh_resolvers() {
    local lib_dir proxy
    lib_dir="$(_metho_lib_dir)"
    proxy="${lib_dir}/doh_proxy.py"

    if [[ ! -f "$proxy" ]]; then
        log_warn "DoH mode requested but ${proxy} is missing — falling back to the UDP pool"
        _fallback_to_udp_pool
        return 1
    fi
    if ! command -v python3 &>/dev/null; then
        log_warn "DoH mode requested but python3 is not available — falling back to the UDP pool"
        _fallback_to_udp_pool
        return 1
    fi

    local port_file="${OUTPUT_DIR}/.doh_proxy.port"
    local proxy_log="${OUTPUT_DIR}/doh_proxy.log"
    local endpoints="${DOH_ENDPOINTS:-https://1.1.1.1/dns-query,https://8.8.8.8/dns-query,https://9.9.9.9/dns-query}"

    rm -f "$port_file"
    log_info "DoH mode: starting local DNS-over-HTTPS proxy (endpoints: ${endpoints//,/, }) ..."

    python3 "$proxy" \
        --host 127.0.0.1 \
        --port 0 \
        --port-file "$port_file" \
        --endpoints "$endpoints" \
        --threads "${DOH_PROXY_THREADS:-128}" \
        --timeout "${DOH_PROXY_TIMEOUT:-4}" \
        >>"$proxy_log" 2>&1 &
    DOH_PROXY_PID=$!

    # Detach from the shell's job table. This process deliberately never
    # exits, and any `wait` with no arguments would block on it forever —
    # which is exactly how a run hung between Phase 1 and the canonical-DNS
    # merge. bounded_parallel now waits only on PIDs it started, and disowning
    # keeps the proxy out of the way of any other whole-shell wait.
    disown "$DOH_PROXY_PID" 2>/dev/null || true

    # The proxy probes its endpoints BEFORE publishing the port, so this wait
    # also covers endpoint discovery.
    local _i _waited=0 _deadline="${DOH_PROXY_READY_SECS:-30}"
    for ((_i = 0; _i < _deadline * 5; _i++)); do
        if [[ -s "$port_file" ]]; then
            break
        fi
        if ! kill -0 "$DOH_PROXY_PID" 2>/dev/null; then
            log_warn "DoH proxy exited before it started listening — see ${proxy_log}"
            tail -5 "$proxy_log" 2>/dev/null | sed 's/^/    /'
            DOH_PROXY_PID=""
            _fallback_to_udp_pool
            return 1
        fi
        sleep 0.2
        _waited=$((_waited + 1))
    done

    if [[ ! -s "$port_file" ]]; then
        log_warn "DoH proxy did not report a port within ${_deadline}s — see ${proxy_log}"
        _doh_proxy_stop
        _fallback_to_udp_pool
        return 1
    fi

    DOH_PROXY_PORT=$(tr -d '[:space:]' < "$port_file")
    if [[ -z "$DOH_PROXY_PORT" ]]; then
        log_warn "DoH proxy reported an empty port — see ${proxy_log}"
        _doh_proxy_stop
        _fallback_to_udp_pool
        return 1
    fi

    printf '127.0.0.1:%s\n' "$DOH_PROXY_PORT" > "${OUTPUT_DIR}/doh_resolvers.txt"
    RESOLVERS_FILE="${OUTPUT_DIR}/doh_resolvers.txt"

    # Functional check: a live socket is not the same as a working transport.
    if _doh_proxy_answers; then
        log_success "DoH mode: proxy listening on 127.0.0.1:${DOH_PROXY_PORT} and answering — resolvers → ${RESOLVERS_FILE}"
        # Report which endpoints the proxy found usable; on a filtered network
        # this is the first place the problem becomes visible.
        grep -o 'endpoint probe:.*' "$proxy_log" 2>/dev/null | tail -1 | sed 's/^/    /' || true
    else
        log_warn "DoH mode: proxy started but could not answer a probe query through any endpoint."
        log_warn "  TCP/443 to a DoH endpoint may be filtered here. Falling back to the UDP pool."
        _doh_proxy_stop
        RESOLVERS_FILE="${RESOLVERS_SOURCE_BUILTIN:-/opt/scripts/wordlists/resolvers.txt}"
        _fallback_to_udp_pool
        return 1
    fi

    # Stop the proxy when this shell exits, whatever the reason.
    trap '_doh_proxy_stop' EXIT
    return 0
}

# Fall back to the shipped UDP pool, logging why. Used when the DoH transport
# cannot be brought up at all.
_fallback_to_udp_pool() {
    local builtin="${RESOLVERS_SOURCE_BUILTIN:-/opt/scripts/wordlists/resolvers.txt}"
    if [[ -s "$builtin" ]]; then
        RESOLVERS_FILE="$builtin"
        log_warn "DNS transport: falling back to the built-in UDP pool ($(grep -cvE '^[[:space:]]*(#|$)' "$builtin" 2>/dev/null || echo 0) entries)"
    else
        log_warn "DNS transport: no usable resolver list — DNS will fail"
    fi
}

_doh_proxy_stop() {
    [[ -n "${DOH_PROXY_PID:-}" ]] || return 0
    kill -TERM "$DOH_PROXY_PID" 2>/dev/null || true
    wait "$DOH_PROXY_PID" 2>/dev/null || true
    DOH_PROXY_PID=""
    DOH_PROXY_PORT=""
}

# Check the active transport is still usable before a batch depends on it.
#
# Only the DoH proxy can die mid-run — a resolver list cannot. Across a
# 70-domain sweep the proxy lives for hours, so a worker-thread crash or an
# OOM kill would otherwise leave every remaining batch resolving against a
# closed port and recording the loss as "timeout" for the rest of the run.
# Restart it once; if that fails, fall back to the UDP pool rather than
# discovering the problem tens of thousands of hostnames later.
_ensure_dns_transport() {
    [[ "${DNS_MODE}" == "doh" ]] || return 0
    [[ -n "${DOH_PROXY_PID:-}" ]] || return 0     # already fell back to UDP
    kill -0 "$DOH_PROXY_PID" 2>/dev/null && return 0

    log_warn "DoH proxy is no longer running — restarting it before the next resolution batch"
    DOH_PROXY_PID=""
    DOH_PROXY_PORT=""
    _load_doh_resolvers || return 1
    return 0
}

# Does the proxy actually resolve? A listening socket is not enough — the
# proxy can be up while every endpoint is blocked.
_doh_proxy_answers() {
    [[ -n "${DOH_PROXY_PORT:-}" ]] || return 1
    command -v dnsx &>/dev/null || return 1

    # Retried: this is a live round trip to a third-party endpoint through a
    # socket that was bound microseconds ago, and a single miss is not proof
    # that the transport is dead. Concluding "unusable" on one miss threw away
    # a perfectly good DoH path and silently moved the whole run to the pool.
    local attempt
    for attempt in 1 2 3; do
        if printf 'whoami.akamai.net\n' \
            | timeout 30 dnsx -silent -a -r "127.0.0.1:${DOH_PROXY_PORT}" \
                -timeout "$(_dnsx_query_timeout)" -retry 2 2>/dev/null | grep -q .; then
            return 0
        fi
        (( attempt < 3 )) && sleep 1
    done
    return 1
}

# A resolver file usable as a FALLBACK when the primary transport is failing.
# Prefers the network's own resolver (fast, permitted where external UDP/53 is
# firewalled), then the shipped pool. Echoes an empty string if neither exists
# or both are the primary.
_fallback_resolver_file() {
    local primary="${1:-}"
    local sys
    sys=$(_probe_system_resolver)
    if [[ -n "$sys" && "$sys" != "$primary" ]]; then
        echo "$sys"
        return 0
    fi
    local builtin="${RESOLVERS_SOURCE_BUILTIN:-/opt/scripts/wordlists/resolvers.txt}"
    if [[ -s "$builtin" && "$builtin" != "$primary" ]]; then
        echo "$builtin"
        return 0
    fi
    echo ""
}

# A resolver file holding real resolver ADDRESSES — never the local DoH proxy.
# Needed by dnsx features that open their own conversation with a server: AXFR
# is a TCP/53 exchange with the zone's authoritative nameserver, and pointing
# it at a UDP-only proxy on 127.0.0.1 silently reduces it to a no-op. Prefers
# the network's own resolver, then the shipped pool.
_direct_resolver_file() {
    local sys
    sys=$(_probe_system_resolver)
    if [[ -n "$sys" ]]; then
        echo "$sys"
        return 0
    fi
    echo "${RESOLVERS_SOURCE_BUILTIN:-/opt/scripts/wordlists/resolvers.txt}"
}

# Probe every resolver in $1 and keep only those that answer from THIS network,
# writing survivors to $OUTPUT_DIR/live_resolvers.txt and pointing
# RESOLVERS_FILE at it. Falls back to the system resolver if nothing survives.
_health_check_resolvers() {
    local src="$1"
    local out="${OUTPUT_DIR}/live_resolvers.txt"
    RESOLVERS_FILE="$src"

    if ! command -v dnsx &>/dev/null; then
        log_warn "Resolver health-check skipped (dnsx not found); using $src as-is"
        return
    fi

    # -P 400, single probe domain, 2s timeout: worst case (13K entries, all
    # dead) finishes in ~2 min (13K / 400 × 2 attempts × 2s), live lists in
    # seconds. Probe domain is deliberately whoami.akamai.net, NOT a common
    # name like one.one.one.one: some DNS-security appliances sinkhole known
    # DoH-endpoint hostnames (one.one.one.one → a local 10.x IP) for ANY
    # destination resolver, which makes every dead resolver look alive.
    # whoami.akamai.net is answered only by genuine recursive resolvers (the
    # answer embeds the resolver's own egress IP), so the result is honest.
    grep -vE '^[[:space:]]*(#|$)' "$src" \
        | xargs -P 400 -I RV sh -c '
            if printf "whoami.akamai.net\n" \
                 | dnsx -silent -a -r "$1" -timeout 2 -retry 1 2>/dev/null | grep -q .; then
                echo "$1"
            fi' _ RV 2>/dev/null \
        | sort -u > "$out" || true

    local live=0 total
    [[ -s "$out" ]] && live=$(wc -l < "$out")
    total=$(grep -cvE '^[[:space:]]*(#|$)' "$src" 2>/dev/null || echo 0)
    if [[ "$live" -gt 0 ]]; then
        RESOLVERS_FILE="$out"
        log_success "Resolver health-check: ${live}/${total} resolvers live — using $out"
    else
        # Nothing survived: prefer the network's own resolver over a dead list.
        # On corporate/home networks that force all DNS through internal
        # resolvers (direct UDP/53 to external IPs firewalled), the system
        # resolver still works — inside Docker at 127.0.0.11, or whatever
        # /etc/resolv.conf names the host configured.
        local sys_dns
        sys_dns=$(_probe_system_resolver)
        if [[ -n "$sys_dns" ]]; then
            echo "$sys_dns" > "$out"
            RESOLVERS_FILE="$out"
            log_warn "Resolver health-check: none of the ${total} custom resolvers responded — falling back to the system resolver (${sys_dns}), which answered the probe."
            log_warn "  Expect lower throughput (one resolver, possibly rate-limited)."
        else
            log_warn "Resolver health-check: none of the ${total} resolvers responded and the system resolver is also dead — keeping full list ($src)."
            RESOLVERS_FILE="$src"
        fi
    fi
}

# Return a resolver file usable by NON-dnsx consumers (cloud_enum's dnspython
# accepts only BARE IP ADDRESSES — it rejects both the `doh:`-style prefixes
# and the `host:port` form the local DoH proxy uses, with
# "nameserver 127.0.0.1:5353 is not a ... IP address, nor a valid https URL").
# Echoes RESOLVERS_FILE when every entry is a plain address; otherwise probes
# the system resolver and returns a one-entry file (empty string if that is
# dead too, in which case the caller skips its DNS checks).
# True when every entry in the file is a bare IP address — no protocol prefix,
# no port. Split out from _plain_ip_resolver_file so it can be tested without
# touching the network.
_resolver_file_is_plain_ips() {
    local f="$1" line
    [[ -s "$f" ]] || return 1
    while IFS= read -r line; do
        line="${line//[[:space:]]/}"
        [[ -z "$line" || "$line" == \#* ]] && continue
        # No colon at all → a bare IPv4 address.
        [[ "$line" != *:* ]] && continue
        # Colons but only hex digits → a bare IPv6 address.
        [[ "$line" =~ ^[0-9a-fA-F:]+$ ]] && continue
        return 1
    done < "$f"
    return 0
}

_plain_ip_resolver_file() {
    local f="${RESOLVERS_FILE:-}"
    if [[ -z "$f" || ! -s "$f" ]]; then
        echo ""
        return
    fi

    if _resolver_file_is_plain_ips "$f"; then
        echo "$f"
        return
    fi

    # NOTE: this function logs NOTHING. Its stdout is captured by the caller
    # (`nsf_file=$(...)`), so a log line written here is captured too — which
    # is how cloud_enum ended up being handed a two-line "-nsf" value
    # containing the warning text, and failed with
    #     Error: File '/output/.sys_resolvers.txt\n[!] ...' not found.
    # The caller does the reporting, from the return value.
    # Build a plain-IP list rather than handing over the raw active file.
    #
    # The network's own resolver goes first (always reachable, and the only
    # option where external UDP/53 is firewalled), then the well-known public
    # resolvers as backups. dnspython tries nameservers in order, so extras
    # cost nothing when the first answers — but a single resolver is fragile
    # for cloud_enum specifically: it does not catch dns.resolver.NoAnswer, so
    # one NOERROR-with-no-A response aborts the whole run and the assets it had
    # not logged yet are lost.
    local out="${OUTPUT_DIR}/.sys_resolvers.txt"
    : > "$out"
    local sys
    sys=$(_probe_system_resolver)
    [[ -n "$sys" ]] && printf '%s\n' "$sys" >> "$out"
    local pub
    for pub in ${CLOUD_ENUM_FALLBACK_RESOLVERS:-1.1.1.1 8.8.8.8 9.9.9.9}; do
        printf '%s\n' "$pub" >> "$out"
    done

    if [[ -s "$out" ]]; then
        echo "$out"
    else
        echo ""
    fi
}

# Find a working system resolver and echo its IP (empty if none answers).
# Tries Docker's embedded DNS (127.0.0.11) first — inside a container it
# forwards to the host's resolv.conf — then the host-facing resolv.conf entries.
# Probe domain: whoami.akamai.net (see _health_check_resolvers) — immune to
# DoH-endpoint sinkholing that would fake-OK a dead path.
_probe_system_resolver() {
    local candidate ip
    for candidate in 127.0.0.11 $(grep -E '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}'); do
        [[ -z "$candidate" ]] && continue
        if [[ -s /etc/resolv.conf ]] || [[ "$candidate" == "127.0.0.11" ]]; then
            if printf 'whoami.akamai.net\n' \
                | dnsx -silent -a -r "$candidate" -timeout 3 -retry 1 2>/dev/null | grep -q .; then
                echo "$candidate"
                return 0
            fi
        fi
    done
    echo ""
}

# ── Normalize a hostname ────────────────────────────────────────────────────
# Strip leading *. wildcard, lowercase, strip trailing dot.
normalize_hostname() {
    echo "$1" | sed 's/^\*\.//; s/\.$//' | tr '[:upper:]' '[:lower:]'
}

# ── Keep only hostnames that belong to a user-supplied root domain ───────────
# filter_in_scope_hostnames <input_file> <output_file>
#
# EVERY path that feeds hostnames into the canonical DNS dataset must go
# through this. Certificate Transparency logs, cloud_enum bucket names and DNS
# record chains (MX/NS/TXT, CNAME targets) all surface third-party hostnames —
# `_spf.google.com`, `d3vfd.s3.amazonaws.com`, `…elb.amazonaws.com`. Those are
# cloud SIGNALS, not attack surface. Once ingested they are resolved,
# classified, and — because classification can fail — handed to naabu and nmap
# as targets, which means port-scanning infrastructure the program does not
# cover. That happened: 10 out-of-scope bucket/ELB hostnames became 70 scanned
# AWS-owned IPs.
#
# Matching mirrors match_root_domain: exact root, or a ".root" suffix. A file
# that is empty, or a run with no root domains, yields an empty output rather
# than an unfiltered one.
filter_in_scope_hostnames() {
    local input="$1" output="$2"
    : > "$output"
    [[ -s "$input" ]] || return 0
    [[ -s "${ROOT_DOMAINS_FILE:-/nonexistent}" ]] || return 0

    local rd escaped
    while IFS= read -r rd; do
        [[ -z "$rd" ]] && continue
        rd=$(normalize_hostname "$rd")
        [[ -z "$rd" ]] && continue
        escaped="${rd//./\\.}"
        grep -E "(^|\.)${escaped}$" "$input" >> "$output" || true
    done < "$ROOT_DOMAINS_FILE"
    sort -u "$output" -o "$output" 2>/dev/null || true
}

# ── crt.name Certificate Transparency query ──────────────────────────────────
# Queries the crt.name API for a root domain and extracts in-scope hostnames.
# Usage: crtname_query <domain> <output_hostnames_file> <raw_json_file>
#
# The crt.name API returns JSON: [{"sub":"hostname.example.com"}, ...]
# We normalize hostnames, filter to in-scope (matching the root domain),
# deduplicate, and preserve the raw API response.
# Registrable apex for a hostname. crt.name's ?apex= param expects a
# REGISTRABLE domain and returns HTTP 400 for a deep subdomain
# (a deeply nested subdomain -> 400, a registrable apex -> 200). A full Public Suffix
# List is unnecessary here — this covers the multi-label ccTLD suffixes the
# target scope actually contains (co.uk, com.tr, co.za, co.tz, co.ke, co.mz,
# co.ls, com.eg, ...) plus common extras. Single-label TLDs fall through to
# last-two-labels. Callers still filter results to the exact in-scope host.
_METHO_MULTI_SUFFIXES=" co.uk org.uk gov.uk ac.uk me.uk com.tr net.tr org.tr gov.tr co.za org.za co.tz co.ke co.mz com.mz co.ls com.eg net.eg co.nz com.au net.au org.au co.in co.id com.br com.mx co.jp com.sg com.my "
registrable_apex() {
    local host="${1%.}"
    local IFS='.'
    local -a parts=()
    read -ra parts <<< "$host"
    local n=${#parts[@]}
    if (( n < 2 )); then printf '%s\n' "$host"; return; fi
    local last2="${parts[n-2]}.${parts[n-1]}"
    if (( n >= 3 )) && [[ "$_METHO_MULTI_SUFFIXES" == *" $last2 "* ]]; then
        printf '%s\n' "${parts[n-3]}.$last2"
    else
        printf '%s\n' "$last2"
    fi
}

crtname_query() {
    local domain="$1" output_file="$2" raw_file="$3"

    : > "$output_file"
    : > "$raw_file"

    if ! command -v curl &>/dev/null; then
        log_warn "crt.name: curl not found, skipping certificate transparency query"
        return
    fi

    local apex
    apex=$(registrable_apex "$domain")
    log_info "Querying crt.name for $domain (apex: $apex)..."
    local api_url="https://crt.name/v1/search?apex=${apex}&format=json"
    local http_code
    # --max-time guards against a proxy/endpoint that accepts the connection
    # then stalls (crt.name has no server-side timeout of its own).
    http_code=$(with_passive_proxy curl -s --max-time 30 -w '%{http_code}' -o "$raw_file" "$api_url" 2>/dev/null || echo "000")

    if [[ "$http_code" != "200" ]]; then
        log_warn "crt.name: API returned HTTP $http_code for $domain"
        return
    fi

    if [[ ! -s "$raw_file" ]]; then
        log_warn "crt.name: empty response for $domain"
        return
    fi

    # Extract "sub" fields from JSON, normalize, filter to in-scope, deduplicate.
    # Normalization is a SINGLE streamed pass (strip *. and trailing dot, then
    # lowercase) — the previous per-line shell loop forked sed+tr per hostname
    # and cost minutes on large-CT apexes (~28k names for a single apex, far
    # worse under amd64 emulation). Mirrors canonical_dns_add_sources' batch idiom.
    local escaped_domain="${domain//./\\.}"
    jq -r '.[].sub // empty' "$raw_file" 2>/dev/null \
        | sed 's/^\*\.//;s/\.$//' \
        | tr '[:upper:]' '[:lower:]' \
        | grep -E "(^|\.)${escaped_domain}$" \
        | sort -u > "$output_file"

    local count=0
    [[ -s "$output_file" ]] && count=$(wc -l < "$output_file")
    log_success "crt.name subdomains for $domain: $count"
}

# ── Bounded parallel execution ──────────────────────────────────────────────
# Run FUNC once per non-empty line of INPUT with bounded concurrency.
# Each FUNC invocation runs in a backgrounded subshell (which inherits all
# sourced functions/vars, so no export needed). FUNC receives the line as $1
# plus any trailing args. Caller is responsible for giving each worker its
# own output file (see _safe_name) and merging results after this returns.
bounded_parallel() {
    local concurrency="$1" input="$2" func="$3"; shift 3
    local running=0 _prev_errexit
    # Guard: a non-positive PARALLEL_HOSTS would mean no workers spawn.
    [[ "$concurrency" -lt 1 ]] && concurrency=1
    # Detect `wait -n` support (bash >= 4.3). Done once; cheap.
    if [[ -z "${_METHO_HAS_WAIT_N+x}" ]]; then
        # Do NOT probe with `(wait -n)`: with no child jobs it returns non-zero
        # on EVERY bash (unknown-option 2 on <4.3, "no more children" 127 on
        # >=4.3), so the probe ALWAYS failed and silently forced slow
        # whole-batch mode (a stuck domain then gates the entire pool). Gate on
        # the interpreter version directly, which is what actually matters.
        if (( BASH_VERSINFO[0] > 4 || ( BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] >= 3 ) )); then
            _METHO_HAS_WAIT_N=1
        else
            _METHO_HAS_WAIT_N=0
        fi
    fi
    # Track the workers THIS function started, and wait only on those.
    #
    # A bare `wait` waits on every child of the shell, and the pipeline owns
    # at least one process that deliberately never exits — the DoH proxy. With
    # a bare `wait`, the first call to bounded_parallel that finished while the
    # proxy was alive blocked forever, hanging the run between Phase 1 and the
    # canonical-DNS merge with no error and no log line.
    local -a _pids=()
    # Temporarily disable errexit AND save/restore it. A worker that returns
    # non-zero must NOT abort the pool (its exit surfaces through `wait`), and
    # we must not leak `set +e` back to the caller.
    case $- in *e*) _prev_errexit=1; set +e;; *) _prev_errexit=0;; esac
    while read -r line; do
        [[ -z "$line" ]] && continue
        # Workers read from /dev/null: a tool that ignores the caller's
        # stdin redirections (katana historically did) must not swallow the
        # remaining input lines this loop is still reading.
        ( "$func" "$line" "$@" || true ) < /dev/null &
        _pids+=("$!")
        running=$((running + 1))
        if (( running >= concurrency )); then
            if [[ "$_METHO_HAS_WAIT_N" == 1 ]]; then
                wait -n || true
                running=$((running - 1))
            else
                # Older bash: wait for the whole batch, then start the next.
                _metho_wait_pids "${_pids[@]}"
                _pids=()
                running=0
            fi
        fi
    done < "$input"
    _metho_wait_pids "${_pids[@]}"
    [[ "$_prev_errexit" == 1 ]] && set -e
}

# Wait for specific PIDs only, never for "all children".
_metho_wait_pids() {
    local _p
    for _p in "$@"; do
        wait "$_p" 2>/dev/null || true
    done
}

# NOTE: each logger must return 0 unconditionally. Before init_log runs,
# LOG_FILE is empty and the `[[ -n "$LOG_FILE" ]] && ...` guard would leave
# the function with status 1 — under `set -e` (recon.sh) that silently kills
# the whole pipeline the first time a logger fires pre-init (e.g. the
# --subfaster-config message in validate_args).
log_info()    { local msg="[*] $*"; echo -e "${CYAN}${msg}${NC}"; { [[ -n "$LOG_FILE" ]] && echo "$(_log_ts) ${msg}" >> "$LOG_FILE"; } || true; }
log_success() { local msg="[+] $*"; echo -e "${GREEN}${msg}${NC}"; { [[ -n "$LOG_FILE" ]] && echo "$(_log_ts) ${msg}" >> "$LOG_FILE"; } || true; }
log_warn()    { local msg="[!] $*"; echo -e "${YELLOW}${msg}${NC}"; { [[ -n "$LOG_FILE" ]] && echo "$(_log_ts) ${msg}" >> "$LOG_FILE"; } || true; }
log_error()   { local msg="[-] $*"; echo -e "${RED}${msg}${NC}"; { [[ -n "$LOG_FILE" ]] && echo "$(_log_ts) ${msg}" >> "$LOG_FILE"; } || true; }
log_skip()    { local msg="[SKIP] $*"; echo -e "${YELLOW}${msg}${NC}"; { [[ -n "$LOG_FILE" ]] && echo "$(_log_ts) ${msg}" >> "$LOG_FILE"; } || true; }

# ── Passive-source proxy ─────────────────────────────────────────────────────
# Run a command with proxy env vars set ONLY when --proxy/PASSIVE_PROXY is
# given. Applied exclusively to passive OSINT sources (crt.name, GitHub,
# subfaster, waymore), while target DNS resolution, HTTPX and Nmap keep using
# the direct network (real IPs).
# curl and Python (requests+PySocks) honor these for SOCKS and HTTP proxies;
# statically-linked Go tools honor an http:// proxy via net/http but may ignore
# a socks5:// one — prefer an HTTP proxy URL for full coverage.
with_passive_proxy() {
    if [[ -n "${PASSIVE_PROXY:-}" ]]; then
        HTTP_PROXY="$PASSIVE_PROXY"  HTTPS_PROXY="$PASSIVE_PROXY"  ALL_PROXY="$PASSIVE_PROXY" \
        http_proxy="$PASSIVE_PROXY"  https_proxy="$PASSIVE_PROXY"  all_proxy="$PASSIVE_PROXY" \
        "$@"
    else
        "$@"
    fi
}

# ── CLI Argument Parsing ────────────────────────────────────────────────────
DOMAINS=""
DOMAINS_FILE=""
# Preserve an env-var-supplied config (e.g. -e SUBFASTER_PROVIDER_CONFIG=...).
# Previously this was hardcoded to "" which silently overwrote the env var;
# users had to pass --subfaster-config on the CLI to get it recognized.
SUBFASTER_PROVIDER_CONFIG="${SUBFASTER_PROVIDER_CONFIG:-}"
# Proxy for passive OSINT sources only (see with_passive_proxy). Env-supplied
# value is preserved so `-e PASSIVE_PROXY=...` works like the CLI flag.
PASSIVE_PROXY="${PASSIVE_PROXY:-}"
# DNS resolvers. RESOLVERS_SOURCE is the candidate list: the built-in static
# file (trickest ~12.7K) is used as-is with no health-check — retryabledns
# round-robins and each retry moves to the next resolver, so dead entries in a
# large list cost nothing. A custom list passed via --resolvers (FILE or URL)
# IS health-checked, since an arbitrary list can be mostly dead and destroy
# throughput. Every dnsx call uses RESOLVERS_FILE. Total runtime failure falls
# back to the system resolver inside canonical_dns_resolve_pending.
RESOLVERS_SOURCE_BUILTIN="/opt/scripts/wordlists/resolvers.txt"
RESOLVERS_SOURCE="${RESOLVERS_SOURCE:-${RESOLVERS_SOURCE_BUILTIN}}"
RESOLVERS_FILE="${RESOLVERS_SOURCE}"
# DNS transport: doh (DEFAULT — every query goes over DNS-over-HTTPS on
# TCP/443 through a local proxy, immune to UDP/53 filtering and to the
# rate-limiting that a bulk UDP burst provokes) or udp (raw UDP/53 against the
# 12.7K static pool).
#
# The default flipped from udp to doh because udp is what fails in the field:
# on a real 29K-hostname run the pool answered ~1% of the corpus, silently
# labelling ~12,000 existing hostnames as "timeout", while the same hostnames
# resolved fine over DoH. UDP remains available (and is still the automatic
# fallback when TCP/443 is filtered). An explicit --resolvers FILE|URL
# overrides either mode.
# Env-overridable like the other transport settings (-e DNS_MODE=udp), and
# validated once in validate_args — which is what makes that check the
# single validation point for both the flag and an inherited value.
DNS_MODE="${DNS_MODE:-doh}"

# dnsx concurrency is transport-aware — see _dnsx_threads() in
# lib/canonical_dns.sh. Setting DNSX_THREADS here pins it for both transports.
DNSX_THREADS="${DNSX_THREADS:-}"

# dnsx retry count and wall-clock cap, defined ONCE. Both used to be
# re-defaulted at every call site, and had already drifted apart — the
# canonical passes used -retry 2 while the Phase 2 record query used -retry 3,
# so "DNSX_RETRY" meant two different things depending on which file you read.
DNSX_RETRY="${DNSX_RETRY:-2}"
DNSX_TIMEOUT="${DNSX_TIMEOUT:-600}"

AUTO=false
SKIP_PHASES=()
THREADS=50
RATE_LIMIT=100
CHECKPOINT_TIMEOUT=30
OUTPUT_DIR="/output"
CLOUD_ENUM_KEYWORDS=""
PORT_SCAN=true
# Hard off-switch for dnsgen permutation brute force (Stage 4b). Independent of
# DNSGEN_SKIP_THRESHOLD: when true, permutation is skipped for every domain
# regardless of size. Recommended for large multi-domain sweeps where the
# permutation multiplier would dominate runtime for little yield.
SKIP_PERMUTATION=false
# How many live hosts to crawl in parallel within a per-host tool (CeWL,
# Katana, SubDomainizer). These stages spend the vast majority of wall-clock
# time crawling hosts one-by-one; a small bounded pool cuts that ~Nx with no
# data loss.
PARALLEL_HOSTS=5
# How many root domains to process in parallel during Phase 1. Each domain
# gets its own canonical_dns.tsv and httpx_metadata.tsv; after all complete,
# merge_per_domain_dns combines them into the global TSV. I/O-bound workloads
# (DNS, HTTP) tolerate higher concurrency than CPU-bound ones.
PARALLEL_DOMAINS=3
# Per-domain wall-clock cap (seconds) for Phase 1. A single pathological domain
# (huge permutation set, or DNS grinding through per-query timeouts) must never
# gate the whole parallel pool. A watchdog TERMs then KILLs that domain's worker
# once it outlives the cap; already-written partial results are kept. 0 =
# unlimited. Default 5400s (90m) is generous — it only catches genuine hangs.
DOMAIN_TIMEOUT=5400
# ASN classification config file (shell-sourceable)
ASN_CONFIG_FILE=""
# Waymore mode: U (URLs only, default), B (URLs + response bodies).
# R (responses only) is rejected in validate_args — the pipeline extracts
# subdomains from the -oU URL list, not response bodies. Mode U keeps full
# subdomain-discovery coverage while skipping the slow response-body
# downloads that the pipeline never reads back (the -oR dir is unused).
WAYMORE_MODE="U"
# Per-domain wall-clock cap for waymore. Mode U (URLs only) is much faster
# than mode B (which downloads archived response bodies), so 600s is a sane
# default; override with WAYMORE_TIMEOUT for very large domains.
WAYMORE_TIMEOUT=600
# Cloud_Enum wall-clock cap. The fuzz list checks most common bucket names
# first (dev, staging, test, prod, …), so the highest-value permutations
# happen early. 900s (15 min) covers the vast majority of useful checks;
# the previous 1800s default spent the second 15 min on low-probability
# mutations that rarely yield findings.
CLOUD_ENUM_TIMEOUT=900

# Cap dnsgen input subdomain count. dnsgen v2 default mode yields
# ~800-1100 permutations per input — 500 inputs → up to ~561K candidates.
# 500 inputs keeps resolution ≈ 6-10 min, and beyond ~500 passive subs the
# permutation yield drops to near zero anyway (passive sources saturate
# coverage — reconftw uses the same 500 threshold). Resolved hostnames
# are prioritized. Set to 0 to disable the cap.
DNSGEN_MAX_INPUT=500

# Skip dnsgen entirely when a domain has more than this many discovered
# subdomains. Default is deliberately AGGRESSIVE (100): permutation multiplies
# every input by ~800-1100 candidates, so even a "small" domain explodes (307
# subs → 273K candidates in E2E), and empirical yield on non-tiny corpora is
# ~0 while the DNS cost is huge — a multiplier that is ruinous across a large
# multi-domain sweep. So by default only genuinely tiny domains (≤100 subs)
# permute; everything else relies on passive + brute coverage. Raise it for a
# focused single-domain deep run, use --skip-permutation to disable entirely,
# or set to 0 to never skip (permute every domain — not recommended at scale).
DNSGEN_SKIP_THRESHOLD=100

# Hard cap on dnsgen output size in bytes (default 25MB ≈ ~350K
# candidates). Safety net against permutation explosion before the
# resolution stage.
DNSGEN_MAX_OUTPUT_BYTES=26214400

# Naabu packets-per-second cap for the top-1000 SYN sweep. 1000 pps is
# reconftw's NAABU_RATE default: fast enough that 1000 hosts × 1000 ports
# finish well within the timeout, throttled enough to avoid saturating
# the uplink or tripping IPS on the target edge.
NAABU_RATE=1000
# Naabu SYN retransmit count. 2 matches reconftw's --max-retries default
# (one initial probe + 2 retries): resilient to single-packet loss
# without multiplying noise on filtered ports.
NAABU_RETRIES=2

# Naabu wall-clock cap. 0 (default) = derive it from the target count as
# NAABU_TIMEOUT_BASE + hosts × NAABU_SECONDS_PER_HOST, capped at 1h. A fixed
# cap silently truncates large sweeps: 423 hosts × 1000 ports at 1000 pps
# needs ~423s of pure sending before any retransmit, which the old 600s
# default did not leave room for. Set NAABU_TIMEOUT to a positive value to
# pin it explicitly.
NAABU_TIMEOUT=0
NAABU_TIMEOUT_BASE="${NAABU_TIMEOUT_BASE:-300}"
NAABU_SECONDS_PER_HOST="${NAABU_SECONDS_PER_HOST:-2}"

# Cap on how many ports nmap -sV service-detects in Stage 4b. naabu already
# records EVERY open port (they are merged into the final ip_port_pairs), so
# this only bounds which ports get version detection. Without a cap, the union
# of open ports across hundreds of hosts approaches the full top-1000 set and
# nmap re-scans every host against all of them — the single biggest time sink
# in Phase 3. The cap keeps the N ports open on the MOST hosts (highest signal).
# 0 = no cap (scan the full union). Override with --nmap-top-ports.
NMAP_TOP_PORTS=100

# Numeric-argument guard: rejects non-integer values up-front so a typo like
# `--threads abc` fails immediately with a clear message instead of deep inside
# dnsx/cloud_enum at runtime.
_require_int() {
    local flag="$1" val="$2"
    if ! [[ "$val" =~ ^[0-9]+$ ]]; then
        log_error "$flag requires a positive integer, got: $val"
        exit 1
    fi
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --domains)        DOMAINS="$2"; shift 2 ;;
            --domains-file)   DOMAINS_FILE="$2"; shift 2 ;;
            --subfaster-config) SUBFASTER_PROVIDER_CONFIG="$2"; shift 2 ;;
            --proxy)          PASSIVE_PROXY="$2"; shift 2 ;;
            --resolvers)      RESOLVERS_SOURCE="$2"; RESOLVERS_FILE="$2"; shift 2 ;;
            --dns-mode)       DNS_MODE="$2"; shift 2 ;;
            --asn-config)     ASN_CONFIG_FILE="$2"; shift 2 ;;
            --waymore-mode)   WAYMORE_MODE="$2"; shift 2 ;;
            --auto)           AUTO=true; shift ;;
            --skip-phase)     case "$2" in
                                  1|2|3) SKIP_PHASES+=("$2") ;;
                                  *) log_error "Invalid --skip-phase value: $2 (must be 1, 2, or 3)"; exit 1 ;;
                              esac; shift 2 ;;
            --skip-cloud)     SKIP_PHASES+=("2"); shift ;;
            --no-port-scan)   PORT_SCAN=false; shift ;;
            --skip-permutation) SKIP_PERMUTATION=true; shift ;;
            --threads)        _require_int "$1" "$2"; THREADS="$2"; shift 2 ;;
            --parallel-hosts) _require_int "$1" "$2"; PARALLEL_HOSTS="$2"; shift 2 ;;
            --parallel-domains) _require_int "$1" "$2"; PARALLEL_DOMAINS="$2"; shift 2 ;;
            --doh-proxy-threads) _require_int "$1" "$2"; DOH_PROXY_THREADS="$2"; shift 2 ;;
            --domain-timeout) _require_int "$1" "$2"; DOMAIN_TIMEOUT="$2"; shift 2 ;;
            --rate-limit)     _require_int "$1" "$2"; RATE_LIMIT="$2"; shift 2 ;;
            --nmap-top-ports) _require_int "$1" "$2"; NMAP_TOP_PORTS="$2"; shift 2 ;;
            --timeout)        _require_int "$1" "$2"; CHECKPOINT_TIMEOUT="$2"; shift 2 ;;
            --output)         OUTPUT_DIR="$2"; shift 2 ;;
            --cloud-enum-keywords) CLOUD_ENUM_KEYWORDS="$2"; shift 2 ;;
            -h|--help)
                echo "Usage: recon.sh [options]"
                echo ""
                echo "Required (one of):"
                echo "  --domains d1,d2,...       Comma-separated root domains"
                echo "  --domains-file FILE       Line-separated root domains file"
                echo ""
                echo "Options:"
                echo "  --subfaster-config FILE   Path to subfaster provider-config.yaml (API keys)"
                echo "  --proxy URL               Proxy for PASSIVE sources only (crt.name, GitHub,"
                echo "                            subfaster, waymore). Scanning/DNS/Nmap stay direct."
                echo "                            e.g. socks5h://host.docker.internal:12334 or http://host.docker.internal:8080"
                echo "  --resolvers FILE|URL      DNS resolver list (file path or http(s) URL, default:"
                echo "                            built-in ~12.7K trickest list, used as-is with no"
                echo "                            health-check — dnsx retries across the pool). A custom"
                echo "                            list IS health-checked; survivors only. Overrides"
                echo "                            --dns-mode."
                echo "  --dns-mode {udp,doh}      doh (default): DNS-over-HTTPS on TCP/443 through a"
                echo "                            local proxy that tries 1.1.1.1, 8.8.8.8 and 9.9.9.9"
                echo "                            and drops the ones this network cannot reach."
                echo "                            udp: raw UDP/53 against the built-in 12.7K pool."
                echo "                            A failing transport is retried through the other one"
                echo "                            automatically before results are recorded."
                echo "  --asn-config FILE         Path to ASN provider classification config (default: built-in)"
                echo "  --waymore-mode MODE       Waymore mode: U (URLs, default) or B (URLs+responses)"
                echo "  --auto                    Skip all checkpoint prompts"
                echo "  --skip-phase {1,2,3}      Skip specific phase(s)"
                echo "  --skip-cloud              Shorthand for --skip-phase 2"
                echo "  --no-port-scan            Skip port scanning phase"
                echo "  --skip-permutation        Disable dnsgen permutation brute force (Stage 4b) for all domains"
                echo "  --threads N               Cloud_Enum thread count (default: 50). dnsx concurrency is"
                echo "                            transport-aware — see DNSX_THREADS_DOH/_UDP"
                echo "  --parallel-hosts N         Hosts crawled in parallel per tool (default: 5)"
                echo "  --parallel-domains N       Root domains processed in parallel in Phase 1 (default: 3)"
                echo "  --doh-proxy-threads N      Concurrent DoH requests the local proxy may have in"
                echo "                            flight (default: 128). Size it to at least"
                echo "                            parallel-domains × DNSX_THREADS_DOH, or queries queue past"
                echo "                            dnsx's own timeout and are recorded as 'timeout'"
                echo "  --domain-timeout N        Per-domain wall-clock cap in seconds (default: 5400; 0=off)"
                echo "  --rate-limit N            Requests/second (default: 100)"
                echo "  --nmap-top-ports N        Cap nmap -sV to the N most-common open ports (default: 100; 0=no cap)"
                echo "  --timeout N               Checkpoint auto-continue seconds (default: 30)"
                echo "  --output DIR              Output directory (default: /output)"
                echo "  --cloud-enum-keywords KW  Keywords for cloud_enum brute force (comma-sep)"
                exit 0 ;;
            *) log_error "Unknown argument: $1"; exit 1 ;;
        esac
    done
}

validate_args() {
    if [[ -z "$DOMAINS" && -z "$DOMAINS_FILE" ]]; then
        log_error "One of --domains or --domains-file must be provided."
        exit 1
    fi
    if [[ -n "$DOMAINS_FILE" && ! -f "$DOMAINS_FILE" ]]; then
        log_error "Domains file not found: $DOMAINS_FILE"
        exit 1
    fi
    if [[ -n "$DOMAINS_FILE" && ! -s "$DOMAINS_FILE" ]]; then
        log_error "Domains file is empty: $DOMAINS_FILE"
        exit 1
    fi
    if [[ -n "$SUBFASTER_PROVIDER_CONFIG" && ! -f "$SUBFASTER_PROVIDER_CONFIG" ]]; then
        log_error "Subfaster config file not found: $SUBFASTER_PROVIDER_CONFIG"
        exit 1
    fi
    if [[ -n "$ASN_CONFIG_FILE" && ! -f "$ASN_CONFIG_FILE" ]]; then
        log_error "ASN config file not found: $ASN_CONFIG_FILE"
        exit 1
    fi
    if [[ -n "$SUBFASTER_PROVIDER_CONFIG" ]]; then
        export SUBFASTER_PROVIDER_CONFIG
        log_info "Subfaster provider config: $SUBFASTER_PROVIDER_CONFIG"
    fi
    # Normalize and sanity-check the passive proxy.
    if [[ -n "$PASSIVE_PROXY" ]]; then
        # A bare socks:// is ambiguous to curl; assume SOCKS5 with remote DNS.
        case "$PASSIVE_PROXY" in
            socks://*)
                PASSIVE_PROXY="socks5h://${PASSIVE_PROXY#socks://}"
                log_warn "Proxy scheme 'socks://' is ambiguous; using ${PASSIVE_PROXY} (SOCKS5, remote DNS)" ;;
        esac
        case "$PASSIVE_PROXY" in
            *://localhost:*|*://127.0.0.1:*)
                log_warn "Proxy host is localhost/127.0.0.1 — inside the container that resolves to the container itself, not the Docker host. If the proxy runs on the host, use host.docker.internal instead (e.g. ${PASSIVE_PROXY%%://*}://host.docker.internal:PORT)." ;;
        esac
        export PASSIVE_PROXY
    fi
    # Validate DNS mode
    case "${DNS_MODE}" in
        udp|doh) ;;
        *) log_error "Invalid --dns-mode: $DNS_MODE (must be 'udp' or 'doh')"; exit 1 ;;
    esac
    if [[ "$DNS_MODE" == "doh" && -n "$RESOLVERS_SOURCE" && "$RESOLVERS_SOURCE" != "$RESOLVERS_SOURCE_BUILTIN" ]]; then
        log_warn "--resolvers is set explicitly — it overrides --dns-mode doh"
    fi
    # Validate waymore mode
    case "$WAYMORE_MODE" in
        # R (responses only) is deliberately NOT accepted: Phase 1 extracts
        # subdomains from waymore's -oU URL output, which responses-only mode
        # does not produce — a mode-R run would silently discover nothing.
        U|B) ;;
        *) log_error "Invalid --waymore-mode: $WAYMORE_MODE (must be U or B; R is not supported because the pipeline consumes URL output)"; exit 1 ;;
    esac
}

# Resolve domain input (--domains or --domains-file) into a file path.
# Returns the path to a file with one domain per line.
resolve_domain_file() {
    local target="$1"

    if [[ -n "$DOMAINS_FILE" ]]; then
        grep -v '^\s*$' "$DOMAINS_FILE" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sort -u > "$target"
        echo "$target"
        return
    fi

    if [[ -n "$DOMAINS" ]]; then
        IFS=',' read -ra domain_arr <<< "$DOMAINS"
        for d in "${domain_arr[@]}"; do
            echo "$d" | xargs
        done | sort -u > "$target"
        echo "$target"
        return
    fi

    echo ""
}

should_skip_phase() {
    local phase="$1"
    for p in "${SKIP_PHASES[@]}"; do
        [[ "$p" == "$phase" ]] && return 0
    done
    return 1
}

# ── Checkpoint System ────────────────────────────────────────────────────────
checkpoint() {
    local message="$1"
    echo ""
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}[CHECKPOINT]${NC} $message"
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo ""

    if [[ "$AUTO" == true ]]; then
        log_info "Auto mode — continuing..."
        return 0
    fi

    if [[ ! -t 0 ]]; then
        log_info "Non-interactive terminal — continuing..."
        return 0
    fi

    echo "  [C]ontinue  [S]kip next phase  [Q]uit  [R]eview results"
    echo -n "  > "

    if [[ "$CHECKPOINT_TIMEOUT" -gt 0 ]]; then
        read -t "$CHECKPOINT_TIMEOUT" -r choice < /dev/tty || choice="c"
    else
        read -r choice < /dev/tty
    fi

    case "${choice,,}" in
        c|""|"continue")   return 0 ;;
        s|skip)
            # "Skip next phase" records the phase that follows the one that just
            # ran (CURRENT_PHASE is still set to it). Next-phase is consulted by
            # should_skip_phase a moment later, so the skip genuinely takes
            # effect. Establish the user's intent as state rather than a return
            # code, because callers invoke checkpoint with `|| true` (the exit
            # status is otherwise swallowed).
            local next_phase=$((CURRENT_PHASE + 1))
            if [[ "$next_phase" -le 3 ]]; then
                SKIP_PHASES+=("$next_phase")
                log_info "Skip registered for Phase $next_phase."
            else
                log_info "No further phase to skip (all phases already ran)."
            fi
            return 0 ;;
        q|quit)            log_info "Exiting."; exit 0 ;;
        r|review)
            echo ""
            echo "  Phase output files:"
            ls -la "${OUTPUT_DIR}/phase${CURRENT_PHASE:-?}/" 2>/dev/null | tail -20
            echo ""
            echo -n "  Press Enter to continue... "
            read -r < /dev/tty
            return 0 ;;
        *) return 0 ;;
    esac
}

# ── Directory Setup ──────────────────────────────────────────────────────────
# 777 (not u+rwX) is intentional: the container runs as root but the host
# user mounting /output is usually a non-root uid. World-writable lets the
# host user read, modify, and delete results without "permission denied".
setup_dirs() {
    mkdir -p "${OUTPUT_DIR}"/{phase1,phase2,phase3,final,config}
    # A port file left by a previous run would let the readiness wait below
    # succeed instantly against a proxy that is not running, which is how you
    # get a whole run resolving against a dead port.
    rm -f "${OUTPUT_DIR}/.doh_proxy.port" \
          "${OUTPUT_DIR}/doh_resolvers.txt" \
          "${OUTPUT_DIR}/.sys_resolvers.txt"
    chmod -R 777 "$OUTPUT_DIR" 2>/dev/null || true
}

# ── Dependency Check ────────────────────────────────────────────────────────
# Only the core plumbing tools are checked up-front. The recon tools
# (dnsx, katana, etc.) are validated lazily, per-stage, with
# `command -v` so any missing tool is skipped cleanly instead of failing
# the whole run.
REQUIRED_TOOLS=(jq curl)

validate_deps() {
    local missing=()
    for tool in "${REQUIRED_TOOLS[@]}"; do
        command -v "$tool" &>/dev/null || missing+=("$tool")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing[*]}"
        exit 1
    fi
}

# ── HTTPx Probe Helper ─────────────────────────────────────────────────────
# Default: httpx probes port 443 (HTTPS) then falls back to 80 (HTTP).
# No -ports flag = much faster, covers the vast majority of web services.
# No -mc flag = show all responses (equivalent to listing every status code).
#
# HTTPX flags for rich metadata:
#   -cdn            detect CDN and include cdn field in JSON output
#   -status-code    include HTTP status code
#   -title          include page title
#   -tech-detect    detect web technologies
#   -web-server     include web server header (alias: -server)
#   -content-length include content length
httpx_probe() {
    local input_file="$1"
    local output_json="$2"

    if [[ ! -s "$input_file" ]]; then
        log_warn "No subdomains to probe in $input_file"
        return
    fi

    local target_count
    target_count=$(wc -l < "$input_file")
    log_info "Probing ${target_count} targets with httpx..."

    # httpx log file for full verbose output (for debugging)
    local httpx_log="${output_json%.json}.httpx.log"

    # Run httpx with CDN detection and full metadata.
    # -cdn: detect CDN (adds "cdn" boolean field to JSON output)
    # -tech-detect: detect web technologies (adds "tech" array)
    # -web-server: detect web server (alias for -server in some versions)
    # -content-length: include content_length field
    # -status-code, -title: include status code and page title
    # Per-process request rate. --rate-limit is documented as the rate against
    # the TARGETS, but in Phase 1 every parallel domain worker runs its own
    # httpx, so N workers offer N× the configured rate. run_phase1 divides the
    # budget by the number of workers it actually starts and passes it down
    # here; a single-domain run (or any Phase 3 probe) uses RATE_LIMIT as-is.
    local _rl="${METHO_HTTPX_RATE:-$RATE_LIMIT}"

    cat "$input_file" | httpx \
        -silent \
        -json \
        -cdn \
        -status-code \
        -title \
        -tech-detect \
        -web-server \
        -content-length \
        -timeout 10 \
        -retries 2 \
        -rate-limit "$_rl" \
        -o "$output_json" > /dev/null 2>"$httpx_log" || true

    local count=0
    if [[ -s "$output_json" ]]; then
        count=$(wc -l < "$output_json")
        log_success "Live web servers found: $count"
    else
        log_warn "No live web servers found in this round."
    fi

    # Append a summary to the httpx log for context
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] httpx run complete: ${count} results from ${target_count} targets" >> "$httpx_log"

    # Merge httpx metadata into the canonical DNS dataset
    if [[ -s "$output_json" ]]; then
        canonical_dns_merge_httpx "$output_json"
    fi
}

# ── Domain Extraction ───────────────────────────────────────────────────────
extract_domains() {
    local input_file="$1"
    local output_file="$2"
    # `|| true`: grep exits 1 when the input contains zero domain-like
    # tokens. Without it, set -e + pipefail would abort the ENTIRE pipeline
    # run at Stage 5 with no error message (verified in testing).
    #
    # Strip percent-encoded fragments first: URLs like
    # https://x.example.com/redirect?to=%2Fapp.example.com would otherwise
    # yield bogus "2Fapp.example.com" tokens (the %2F path separator
    # merges with the following hostname chars).
    sed -E 's/%[0-9A-Fa-f]{2}/ /g' "$input_file" 2>/dev/null \
        | grep -oE '([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}' \
        | sort -u > "$output_file" || true
}

# ── Cloud Domain Filter ────────────────────────────────────────────────────
# Matches any host pointing at a recognized cloud / PaaS provider.
# The regex is a union of provider-specific suffixes plus root-domain
# tokens; we don't try to enumerate every bucket naming convention.
#
# Coverage rationale:
#   AWS:        amazonaws, cloudfront, elasticbeanstalk, apps that
#               front EC2 with the AWS global accelerator
#   Azure:      azurewebsites, azure, blob.core.windows, cloudapp,
#               azure-api (API Management)
#   GCP:        googleapis, appspot, cloudfunctions, storage.googleapis,
#               web.app (Firebase App Hosting)
#   Cloudflare: cloudflarestorage (R2), workers.dev (Workers)
#   DigitalOcean: digitaloceanspaces (Spaces), digitalocean.app /
#               ondigitalocean.app (App Platform)
#   Heroku:     herokuapp.com / heroku.com
#   Vercel:     vercel.app
#   Netlify:    netlify.app
#   Fly.io:     fly.dev
#   Railway:    railway.app
#   Render:     onrender.com
#   Backblaze:  backblazeb2.com
#   Linode:     linodeobjects.com
#   Oracle:     oraclecloud.com / oraclecloudusercontent.com
#   Supabase:   supabase.co / supabase.in
filter_cloud_domains() {
    local input_file="$1"
    local output_file="$2"
    grep -iE '(amazonaws|cloudfront|elasticbeanstalk|azurewebsites|azure-api|blob\.core\.windows|cloudapp|googleapis|appspot|cloudfunctions|storage\.googleapis|web\.app|cloudflarestorage|workers\.dev|digitaloceanspaces|digitalocean\.app|ondigitalocean\.app|herokuapp|vercel\.app|netlify\.app|fly\.dev|railway\.app|onrender\.com|backblazeb2|linodeobjects|oraclecloud|supabase\.co|supabase\.in)' \
        "$input_file" | sort -u > "$output_file" 2>/dev/null || true
}