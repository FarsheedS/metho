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

# Default DoH endpoints. Defined once and shared by the proxy launcher below
# and the banner in recon.sh, so the two can never drift apart — previously
# the same three-endpoint literal was duplicated in both files. IP literals
# only; the verification notes and per-provider probe results live in
# lib/doh_proxy.py's DEFAULT_ENDPOINTS, which is the same list.
DOH_ENDPOINTS_DEFAULT="https://8.8.8.8/dns-query,https://8.8.4.4/dns-query,https://94.140.14.14/dns-query,https://94.140.15.15/dns-query,https://208.67.222.222/dns-query,https://208.67.220.220/dns-query,https://1.1.1.1/dns-query,https://9.9.9.9/dns-query"

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

# The DoH proxy also listens on this bare-IP UDP port, so consumers that cannot
# use an ephemeral HOST:PORT resolver (cloud_enum's dnspython dials UDP/53 with
# a bare IP) stay on the DoH transport instead of silently leaving it for the
# system resolver. 53 needs root, which the container has; the bind is
# best-effort, so outside a container this degrades to the old behaviour.
DOH_PROXY_EXTRA_PORT="${DOH_PROXY_EXTRA_PORT:-53}"

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
    local endpoints="${DOH_ENDPOINTS:-${DOH_ENDPOINTS_DEFAULT}}"

    rm -f "$port_file"
    log_info "DoH mode: starting local DNS-over-HTTPS proxy (endpoints: ${endpoints//,/, }) ..."

    python3 "$proxy" \
        --host 127.0.0.1 \
        --port 0 \
        --port-file "$port_file" \
        --extra-bind "127.0.0.1:${DOH_PROXY_EXTRA_PORT:-53}" \
        --extra-port-file "${OUTPUT_DIR}/.doh_extra_port" \
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
    # The plain-IP listener died with the proxy. Leaving its port file behind
    # would make _doh_plain_resolver_available keep saying "available" and
    # point cloud_enum at a dead 127.0.0.1:53.
    rm -f "${OUTPUT_DIR}/.doh_extra_port" 2>/dev/null || true
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

# ── Which transport are we ACTUALLY on? ──────────────────────────────────────
# DNS_MODE is the REQUESTED mode and is never rewritten when the proxy fails:
# _load_doh_resolvers falls back by pointing RESOLVERS_FILE at the built-in
# ~12.7K UDP pool while DNS_MODE stays "doh". Anything gating on DNS_MODE alone
# therefore trusts a transport that is not running.
#
# That is not hypothetical — it is how httpx would have been handed the
# unvetted static pool, the exact thing the DoH-only gate exists to prevent,
# on precisely the networks where DoH had already failed. Ask this instead of
# reading DNS_MODE.
#
# The PID is cleared on every fallback path (_doh_proxy_stop does it, and the
# early exits do it directly), and the proxy is a child of this shell — so
# liveness plus the resolver-file identity is the honest signal. The path
# check catches the case where a fallback swapped RESOLVERS_FILE while a
# restarted proxy is still coming up.
_using_doh_transport() {
    [[ "${DNS_MODE}" == "doh" ]] || return 1
    [[ -n "${DOH_PROXY_PID:-}" && -n "${DOH_PROXY_PORT:-}" ]] || return 1
    kill -0 "$DOH_PROXY_PID" 2>/dev/null || return 1
    [[ "${RESOLVERS_FILE:-}" == "${OUTPUT_DIR}/doh_resolvers.txt" ]] || return 1
    return 0
}

# Per-request httpx timeout, transport-aware. $1 = "1" when on the DoH transport
# (httpx resolves through the local proxy, which needs the wider DoH window).
# Pure — takes the transport as an argument so it is unit-testable without a
# live proxy. See HTTPX_TIMEOUT / HTTPX_TIMEOUT_DOH.
_httpx_probe_timeout() {
    if [[ "${1:-0}" == "1" ]]; then echo "${HTTPX_TIMEOUT_DOH:-25}"; else echo "${HTTPX_TIMEOUT:-10}"; fi
}

# httpx concurrency, transport-aware. On DoH ($1="1") cap to a share the proxy
# pool can answer, but never raise an explicitly-lowered HTTPX_THREADS. Pure and
# unit-testable. See HTTPX_THREADS / HTTPX_THREADS_DOH.
_httpx_probe_threads() {
    if [[ "${1:-0}" == "1" ]]; then
        local _cap="${HTTPX_THREADS_DOH:-50}"
        if (( HTTPX_THREADS < _cap )); then echo "$HTTPX_THREADS"; else echo "$_cap"; fi
    else
        echo "$HTTPX_THREADS"
    fi
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
# Is the DoH proxy ALSO listening on a bare-IP address (normally 127.0.0.1:53)?
#
# cloud_enum's dnspython accepts bare IPs only and always dials UDP/53, so in
# DoH mode it could not use the active resolver file at all and silently fell
# back to the system resolver — a DIFFERENT DNS view from every other tool in
# the run, which is exactly the split-horizon divergence DoH mode exists to
# remove. The proxy binds the extra socket best-effort, so this can be false;
# the caller falls back as before.
_doh_plain_resolver_available() {
    local f="${OUTPUT_DIR}/.doh_extra_port"
    [[ -s "$f" ]] && grep -qx '53' "$f" 2>/dev/null
}

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
    # The DoH proxy's plain-IP listener goes FIRST when it exists: it is the only
    # resolver here that gives cloud_enum the same view as the rest of the run.
    # The fallbacks stay behind it, because cloud_enum does not catch
    # dns.resolver.NoAnswer and a single unreachable nameserver aborts its run.
    if _doh_plain_resolver_available; then
        printf '%s\n' "127.0.0.1" >> "$out"
    fi
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
    # Optional stage deadline, passed in by the caller as an ABSOLUTE epoch
    # second in METHO_STAGE_DEADLINE (0/empty = unlimited), with
    # METHO_STAGE_LABEL naming the stage in log output.
    #
    # This is the aggregate bound the per-host caps cannot provide. CeWL and
    # Katana each give a host up to 600s, so a stage's worst case is
    # (hosts ÷ concurrency) × 600s — hours on a large target. Without an
    # aggregate deadline the only thing that stops it is the per-domain
    # watchdog, which kills the WHOLE domain worker mid-stage and takes the
    # stages after it down too. That happened on a real run: CeWL was killed at
    # 2,439/4,371 hosts and Katana, SubDomainizer and Stage 7 never ran.
    local deadline="${METHO_STAGE_DEADLINE:-0}"
    [[ "$deadline" =~ ^[0-9]+$ ]] || deadline=0
    local label="${METHO_STAGE_LABEL:-stage}"
    local _total=0
    # `|| true` matters: this sits ABOVE the set +e guard below, and under
    # `set -euo pipefail` an unreadable $input makes the redirect fail, the
    # pipeline return non-zero and the whole run abort. Every input-reading
    # statement used to live inside the guarded region; this one is new.
    _total=$(wc -l < "$input" 2>/dev/null | tr -d '[:space:]' || true)
    [[ "$_total" =~ ^[0-9]+$ ]] || _total=0
    local _launched=0 _truncated=0
    METHO_STAGE_TRUNCATED=0
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
        # Stop launching once the stage budget is spent. Checked before spawn so
        # the stage cannot overshoot by one host's worth of work; the workers
        # already in flight are terminated below.
        if (( deadline > 0 )) && (( $(date +%s) >= deadline )); then
            _truncated=1
            break
        fi
        # Workers read from /dev/null: a tool that ignores the caller's
        # stdin redirections (katana historically did) must not swallow the
        # remaining input lines this loop is still reading.
        ( "$func" "$line" "$@" || true ) < /dev/null &
        _pids+=("$!")
        _launched=$((_launched + 1))
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
    if (( _truncated )); then
        # Terminate the in-flight workers — and their DESCENDANTS. Killing the
        # wrapper subshell alone leaves the tool it launched running: the
        # crawlers invoke their tool through `timeout`, so the real work is a
        # grandchild that survives the wrapper's death and keeps burning CPU,
        # network and the target's rate budget into the following stages, for up
        # to its own per-host cap. The budget has to stop the work, not just the
        # loop that started it.
        #
        # Partial per-host output is kept on purpose: the crawlers write one
        # file per host and the caller concatenates whatever exists, so a killed
        # host yields "no words from that host", never a corrupt wordlist.
        if [[ ${#_pids[@]} -gt 0 ]]; then
            local _p
            for _p in "${_pids[@]}"; do _metho_kill_tree "$_p"; done
            sleep 2
            for _p in "${_pids[@]}"; do _metho_kill_tree "$_p" KILL; done
        fi
        # The `${arr[@]+…}` guard is not decoration: an empty array expansion is
        # FATAL under `set -u` on bash < 4.4, and the deadline-already-spent case
        # (zero hosts launched) is exactly when the array is empty. The shipped
        # image is bash 5.2, but the test suite is documented as runnable from a
        # macOS checkout, where bash is 3.2.
        _metho_wait_pids ${_pids[@]+"${_pids[@]}"}
        METHO_STAGE_TRUNCATED=1
        log_warn "${label}: stage budget reached after ${_launched}/${_total} hosts — remaining hosts skipped (per-host partial results kept)"
        # Record it at RUN level too. A shell variable would not survive: the
        # crawl stages run inside background subshells, so by the time the run
        # summary is printed the flag is gone and an incomplete run looks
        # complete. The run summary reads this file.
        _record_truncation "${domain:-?}" "$label" "${_launched}/${_total} hosts"
    else
        _metho_wait_pids ${_pids[@]+"${_pids[@]}"}
    fi
    [[ "$_prev_errexit" == 1 ]] && set -e
}

# Kill a process and everything it started.
#
# `kill <wrapper>` does not touch what the wrapper forked, and the per-host
# workers all run their tool through `timeout` — so the actual crawl is a
# grandchild that outlives the wrapper. Walk the tree depth-first with
# `pgrep -P` and signal the leaves first, so nothing is reparented mid-walk.
_metho_kill_tree() { # <pid> [TERM|KILL]
    local pid="$1" sig="${2:-TERM}" child
    for child in $(pgrep -P "$pid" 2>/dev/null || true); do
        _metho_kill_tree "$child" "$sig"
    done
    kill -"$sig" "$pid" 2>/dev/null || true
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
# Every knob below is `${VAR:-default}` rather than a plain assignment, so it is
# settable from the environment as well as from its CLI flag. It was not: these
# were plain assignments, so `CEWL_MAX_HOSTS=0 metho` was silently ignored while
# `--cewl-max-hosts 0` worked, which made the documented "set from the
# environment" path unreachable for exactly the knobs an unattended run wants to
# pin. parse_args runs after this file is sourced, so a flag still wins over the
# environment, which is the intended order.
THREADS="${THREADS:-50}"
RATE_LIMIT="${RATE_LIMIT:-100}"
# httpx concurrency PER PROCESS. Never passed before this existed, so httpx ran
# at its built-in default of 50 threads.
#
# That default, not the rate limit, is what bounded the probe. Measured on a
# real run: 12,276 targets took 47m12s (4.34 targets/s) while the configured
# 50/s never engaged, because 50 threads stalled in connect/read timeouts
# divide out to ~4.5 targets/s (threads ÷ mean latency). Raise this and the
# rate limit becomes the binding constraint, which is the intended order.
#
# Kept deliberately modest: this is the knob that decides how hard every target
# is hit at once. HTTPX_THREADS_MAX is a hard ceiling so a fat-fingered or
# scripted value cannot turn a sweep into a flood.
HTTPX_THREADS="${HTTPX_THREADS:-150}"
# httpx wall-clock ceiling, scaled per target like naabu's and nmap's.
#
# Until this existed httpx was the only long stage with NO cap at all. Phase 1
# bounds it indirectly through the per-domain watchdog, but Phase 3's late probe
# runs outside any watchdog — and that probe was measured re-sending ~7,978
# targets — so a hung httpx there hung the entire run with no timeout, no
# watchdog and no log line.
#
# 1s/target is a deliberate over-estimate of a stage that measured 0.23s/target
# at 50 threads (and so ~0.077s at the current 150); the cap exists to bound a
# hang, not to shape normal running, and must not truncate a legitimate round.
HTTPX_TIMEOUT_BASE="${HTTPX_TIMEOUT_BASE:-60}"
HTTPX_SECONDS_PER_TARGET="${HTTPX_SECONDS_PER_TARGET:-1}"
HTTPX_TIMEOUT_MAX="${HTTPX_TIMEOUT_MAX:-3600}"
# Per-request httpx budget (seconds), transport-aware. httpx re-resolves every
# hostname itself; on the DoH transport that resolution is an HTTPS round-trip
# through the local proxy, far slower than a UDP reply. The UDP-tuned 10s all-in
# budget expired DURING DNS on a congested proxy and recorded live hosts as
# dead — a real vodafone.com run confirmed 5 live out of 1,044 resolved. DoH
# gets a wider window; UDP is unchanged. See _httpx_probe_timeout.
HTTPX_TIMEOUT="${HTTPX_TIMEOUT:-10}"
HTTPX_TIMEOUT_DOH="${HTTPX_TIMEOUT_DOH:-25}"
# httpx concurrency on the DoH transport. Every probe's DNS goes through ONE
# local proxy pool (DOH_PROXY_THREADS:-128); the full 150-thread fan-out, each
# opening a cold DoH lookup, overran it and the surplus expired as "dead". Cap
# to a share the proxy can actually answer (an explicit lower HTTPX_THREADS
# still wins). See _httpx_probe_threads.
HTTPX_THREADS_DOH="${HTTPX_THREADS_DOH:-50}"
# The clamp's error message tells the operator to raise this deliberately, so it
# has to be raisable — a plain assignment here silently ignored the environment
# and made that advice impossible to follow without editing this file.
HTTPX_THREADS_MAX="${HTTPX_THREADS_MAX:-200}"
CHECKPOINT_TIMEOUT="${CHECKPOINT_TIMEOUT:-30}"
OUTPUT_DIR="/output"
CLOUD_ENUM_KEYWORDS="${CLOUD_ENUM_KEYWORDS:-}"
PORT_SCAN="${PORT_SCAN:-true}"
# Hard off-switch for dnsgen permutation brute force (Stage 4b). Independent of
# DNSGEN_SKIP_THRESHOLD: when true, permutation is skipped for every domain
# regardless of size. Recommended for large multi-domain sweeps where the
# permutation multiplier would dominate runtime for little yield.
SKIP_PERMUTATION="${SKIP_PERMUTATION:-false}"
# How many live hosts to crawl in parallel within a per-host tool (CeWL,
# Katana, SubDomainizer). These stages spend the vast majority of wall-clock
# time crawling hosts one-by-one; a small bounded pool cuts that ~Nx with no
# data loss.
PARALLEL_HOSTS="${PARALLEL_HOSTS:-5}"
# How many root domains to process in parallel during Phase 1. Each domain
# gets its own canonical_dns.tsv and httpx_metadata.tsv; after all complete,
# merge_per_domain_dns combines them into the global TSV. I/O-bound workloads
# (DNS, HTTP) tolerate higher concurrency than CPU-bound ones.
PARALLEL_DOMAINS="${PARALLEL_DOMAINS:-3}"
# How many hosts the wordlist-building and crawl stages may touch per domain
# (CeWL at Stage 4a; Katana and SubDomainizer at Stage 6).
#
# Those stages crawl host-by-host with no natural bound, so on a large target
# they run for tens of hours and then get cut off mid-stage by DOMAIN_TIMEOUT.
# That is not hypothetical: a run with 4,371 live hosts spent 18 minutes in
# CeWL, was killed by the 5,400s watchdog at 2,439 hosts, and never reached
# Katana, SubDomainizer or Stage 7 at all.
#
# The marginal value falls off a cliff well before the whole live set — the
# wordlist from host #600 is noise — so capping the input keeps these stages
# proportional to what they actually contribute. 0 = unlimited.
#
# Raised from 150 to match CRAWL_MAX_HOSTS, because the cost per host is small
# (a 4,087-host target spent 1m18s in CeWL on 150 hosts) and a wordlist built
# from 300 hosts beats one from 150. What actually limits the yield is not the
# count but WHICH hosts are picked — see _rank_crawl_candidates, which now
# orders the input so these slots are spent on hosts that serve real content.
CEWL_MAX_HOSTS="${CEWL_MAX_HOSTS:-300}"
CRAWL_MAX_HOSTS="${CRAWL_MAX_HOSTS:-300}"
# Wall-clock cap (seconds) for each crawl stage, independent of DOMAIN_TIMEOUT.
# A host-count cap alone is not enough: per-host caps of 600s (CeWL/Katana)
# multiply by the host count and can still outlast the domain budget.
# 0 = unlimited.
#
# Raised from 1200 to 1800 on measured yield. On a 28,993-hostname run this
# budget was reached with Katana at 159/300 hosts and SubDomainizer at only
# 63/300 — and SubDomainizer was the single best hostname source of the whole
# run: 443 net-new names in those 63 hosts, ~22/min, against ~14/min for
# github-subdomains and ~13/min for waymore. Katana is the cheap one to extend
# (~7.5s/host); SubDomainizer costs ~19s/host, so it is the term that sets the
# cost of this change. Both are now also fed a ranked host list, so the extra
# 600s buys hosts that serve content rather than canonical-redirect stubs.
CRAWL_STAGE_TIMEOUT="${CRAWL_STAGE_TIMEOUT:-1800}"
# Wall-clock cap (seconds) for the github-subdomains stage. It has no host input
# — it is one code-search crawl — so it gets a flat cap rather than sharing the
# crawl budget.
#
# Raised to 1200: at 600s it was still being killed mid-yield on vodafone.com
# (531 subdomains and climbing), the same "killed while still finding them"
# pattern that took it from 300 to 600. It stays cheap — one code-search crawl,
# no host fan-out — and GitHub's own API rate limit caps the real cost well
# below the wall-clock budget. Declared here rather than inline at its call site
# so it is visible in --help-adjacent listings and the run banner alongside the
# other budgets.
GITHUB_SUBDOMAINS_TIMEOUT="${GITHUB_SUBDOMAINS_TIMEOUT:-1200}"
# Per-domain wall-clock cap (seconds) for Phase 1. A single pathological domain
# (huge permutation set, or DNS grinding through per-query timeouts) must never
# gate the whole parallel pool. A watchdog TERMs then KILLs that domain's worker
# once it outlives the cap; already-written partial results are kept. 0 =
# unlimited.
#
# Raised to 14400 (4h). Hitting this is the single worst outcome in the pipeline:
# the domain is killed mid-stage and EVERY later stage for it — Katana,
# SubDomainizer, Stage 7 consolidation, and its HTTPX round — never runs at all.
# The 2h value assumed the old fixed-600s DNS caps; once the DNS passes scale to
# the transport's real throughput (see _dnsx_scaled_cap), a 28,993-hostname root
# over DoH spends several multi-hundred-second resolve/rcode passes in Phase 1
# alone — measured at ~16 q/s a single full resolve pass is ~30m, and Phase 1
# runs several. 4h keeps the completing passes inside the cap with headroom;
# raising DNSX_THREADS_DOH (now 128) shortens them, so this is a ceiling, not a
# target. Single-target runs do not share a parallel pool, so the old anti-gating
# argument for a tighter cap does not apply.
DOMAIN_TIMEOUT="${DOMAIN_TIMEOUT:-14400}"
# Probe hosts whose every address is reserved/private (status `bogon`).
#
# Those hosts are unreachable from the internet but NOT necessarily unreachable
# from you: on a network routed into the target's private or CGNAT space they
# answer normally, and on a real run two internal OpenSearch clusters replied
# HTTP 200 from 100.64.x while being held out of the probe set entirely.
#
# HTTP only. `bogon` hosts stay out of the IP dataset, the ASN lookup, the
# classification, naabu and nmap whatever this is set to: httpx re-resolves each
# name itself so it needs no recorded address, whereas pointing a port scanner
# at private space is a different and much less defensible action.
#
# Off by default because the cost is real when the space is NOT routed — each
# such host then costs an httpx timeout, and the address may route to something
# unrelated to the target. 549 hosts were in that bucket on the run above.
METHO_PROBE_RESERVED="${METHO_PROBE_RESERVED:-0}"
# ASN classification config file (shell-sourceable)
ASN_CONFIG_FILE=""
# Waymore mode: U (URLs only, default), B (URLs + response bodies).
# R (responses only) is rejected in validate_args — the pipeline extracts
# subdomains from the -oU URL list, not response bodies. Mode U keeps full
# subdomain-discovery coverage while skipping the slow response-body
# downloads that the pipeline never reads back (the -oR dir is unused).
WAYMORE_MODE="${WAYMORE_MODE:-U}"
# Per-domain wall-clock cap for waymore. Mode U (URLs only) is much faster
# than mode B (which downloads archived response bodies), so 600s is a sane
# default; override with WAYMORE_TIMEOUT for very large domains.
WAYMORE_TIMEOUT="${WAYMORE_TIMEOUT:-600}"
# Cloud_Enum wall-clock cap. The fuzz list checks most common bucket names
# first (dev, staging, test, prod, …), so the highest-value permutations
# happen early. 900s (15 min) covers the vast majority of useful checks;
# the previous 1800s default spent the second 15 min on low-probability
# mutations that rarely yield findings.
CLOUD_ENUM_TIMEOUT="${CLOUD_ENUM_TIMEOUT:-900}"

# Cap dnsgen input subdomain count. dnsgen v2 default mode yields
# ~800-1100 permutations per input — 500 inputs → up to ~561K candidates.
# 500 inputs keeps resolution ≈ 6-10 min, and beyond ~500 passive subs the
# permutation yield drops to near zero anyway (passive sources saturate
# coverage — reconftw uses the same 500 threshold). Resolved hostnames
# are prioritized. Set to 0 to disable the cap.
#
# This does NOT bound a small domain, and the arithmetic is worth stating
# because it reads like it should. The skip test below fires at 100, so at the
# shipped defaults any input set large enough to trip this cap has already been
# skipped outright — the two thresholds are not independent, they are ordered,
# and the lower one wins. The cap can therefore only ever fire when an operator
# raises DNSGEN_SKIP_THRESHOLD above it. Bounding a sub-threshold domain is
# DNSGEN_MAX_OUTPUT_BYTES' job instead, since the explosion happens per input
# (a 52-input domain produced 40,362 candidates) and truncating the seed list
# would not have moved that number.
DNSGEN_MAX_INPUT="${DNSGEN_MAX_INPUT:-500}"

# Skip dnsgen entirely when a domain has more than this many discovered
# subdomains. Default is deliberately AGGRESSIVE (100): permutation multiplies
# every input by ~800-1100 candidates, so even a "small" domain explodes (307
# subs → 273K candidates in E2E), and empirical yield on non-tiny corpora is
# ~0 while the DNS cost is huge — a multiplier that is ruinous across a large
# multi-domain sweep. So by default only genuinely tiny domains (≤100 subs)
# permute; everything else relies on passive + brute coverage. Raise it for a
# focused single-domain deep run, use --skip-permutation to disable entirely,
# or set to 0 to never skip (permute every domain — not recommended at scale).
DNSGEN_SKIP_THRESHOLD="${DNSGEN_SKIP_THRESHOLD:-100}"

# Hard cap on dnsgen output size in bytes. Safety net against permutation
# explosion before the resolution stage.
#
# Lowered from 25MB to 512KB, because 25MB never bound anything and is not what
# protects a sub-threshold domain. Below DNSGEN_SKIP_THRESHOLD the skip cannot
# fire, and DNSGEN_MAX_INPUT cannot either (see its note above), so the byte
# ceiling is the ONLY thing standing between a small target and an unbounded
# candidate set. Measured: 52 inputs produced 40,362 candidates in 1,207,527
# bytes — ~30 bytes each — against a ceiling 20x larger, so nothing trimmed it
# and the stage spent ~6 minutes resolving 40k names for zero hostnames. 512KB
# ≈ 17K candidates: still ~330x the input count, so a genuine permutation hit is
# not lost, but a pathological blow-up is bounded.
DNSGEN_MAX_OUTPUT_BYTES="${DNSGEN_MAX_OUTPUT_BYTES:-524288}"

# Naabu packets-per-second cap for the top-1000 SYN sweep. 1000 pps is
# reconftw's NAABU_RATE default: fast enough that 1000 hosts × 1000 ports
# finish well within the timeout, throttled enough to avoid saturating
# the uplink or tripping IPS on the target edge.
NAABU_RATE="${NAABU_RATE:-1000}"
# Naabu SYN retransmit count. 2 matches reconftw's --max-retries default
# (one initial probe + 2 retries): resilient to single-packet loss
# without multiplying noise on filtered ports.
NAABU_RETRIES="${NAABU_RETRIES:-2}"

# Naabu top-N ports. 100, not 1000.
#
# The port list is the dominant term in the sweep's cost AND in its exposure.
# At 1,000 ports a 6,501-host sweep is ~6.5M SYNs — ~1.8 hours of continuous SYN
# traffic from a single IP against the target's own ranges, which is exactly what
# a mature SOC's IDS is built to notice. At 100 ports it is ~650k SYNs, about
# 11 minutes, and top-100 still covers essentially every service that matters
# for recon. Raise it deliberately for a small, targeted sweep; do not raise it
# while the candidate list is in the thousands.
NAABU_TOP_PORTS="${NAABU_TOP_PORTS:-100}"

# Naabu wall-clock cap. 0 (default) = derive it from the target count as
# NAABU_TIMEOUT_BASE + hosts × NAABU_SECONDS_PER_HOST, capped at
# NAABU_TIMEOUT_MAX. Set NAABU_TIMEOUT to a positive value to pin it explicitly.
NAABU_TIMEOUT="${NAABU_TIMEOUT:-0}"
NAABU_TIMEOUT_BASE="${NAABU_TIMEOUT_BASE:-300}"
# Seconds of sending per host ≈ top_ports ÷ rate × (1 + retries): at 100 ports,
# 1000 pps and 2 retries that is ~0.3s, so 1 is a deliberately conservative
# integer. This constant is not decoration — it sets both the projected sweep
# time and the chunk size, so it must be recalibrated if NAABU_TOP_PORTS or
# NAABU_RATE changes. (It said 2 against a 1000-port default, which is how a
# projection of 13,302s appeared next to a sweep that could never take that
# long either way.)
NAABU_SECONDS_PER_HOST="${NAABU_SECONDS_PER_HOST:-1}"
# Per-chunk ceiling. Together with the constants above it sets the chunk size as
# (cap − base) ÷ per-host, and it is also the worst case for ONE hung chunk: at
# 1200s a stuck chunk costs 20 minutes rather than an hour, and the real need for
# a 900-host/100-port chunk is ~90s, so the headroom is ample.
NAABU_TIMEOUT_MAX="${NAABU_TIMEOUT_MAX:-1200}"
# Ceiling on the WHOLE sweep, across all chunks (0 = 4 × NAABU_TIMEOUT_MAX).
# naabu's cost is linear in the candidate count, so a big enough target cannot
# fit in one NAABU_TIMEOUT_MAX window. Phase 3 chunks the candidate list so the
# whole set is covered, and this is the point at which it stops trying and
# records the sweep as incomplete instead of pretending otherwise.
NAABU_TOTAL_TIMEOUT_MAX="${NAABU_TOTAL_TIMEOUT_MAX:-0}"
# nmap -sV wall-clock ceiling. Until now the nmap call had NO timeout at all,
# which matters most on its fallback path (naabu found nothing, so every
# candidate is handed to -sV): 6,501 hosts × a 33-port version scan can outlast
# the rest of the run. Scaled per host like naabu and capped by NMAP_TIMEOUT_MAX.
NMAP_TIMEOUT_BASE="${NMAP_TIMEOUT_BASE:-60}"
NMAP_SECONDS_PER_HOST="${NMAP_SECONDS_PER_HOST:-30}"
NMAP_TIMEOUT_MAX="${NMAP_TIMEOUT_MAX:-3600}"
# How many hosts a port must have been seen open on before nmap -sV spends time
# on it. The -sV port list is global (one list for every target), so a port seen
# once gets probed across the whole estate; on a real run 226 of 247 discovered
# ports came from GCP front-end artefacts on 2 hosts each. Well-known ports
# (<1024) bypass this floor. 1 = no floor (previous behaviour).
#
# Default lowered from 2 to 1, because the floor was dropping real findings. On
# the run above naabu found 88.134.246.114:8080 open — the only host in the
# estate with 8080 open — and the floor kept 8080 out of the -sV union, so it
# was never fingerprinted; the scan went out with -p 53,80,110,443,2000,5060 and
# the one non-standard service the sweep discovered was the one port it did not
# look at.
#
# The floor was written when NAABU_TOP_PORTS was 1000, where an uncorroborated
# port really could drag the union toward 1000 ports and re-scan every host
# against all of them. At the current top-100 the union is bounded by 100 no
# matter what, and NMAP_TIMEOUT_MAX bounds the wall clock, so the noise argument
# no longer pays for the missed findings. Excluded ports are now logged rather
# than dropped silently, so raising this back is an informed choice.
NMAP_MIN_PORT_HOSTS="${NMAP_MIN_PORT_HOSTS:-1}"

# Cap on how many ports nmap -sV service-detects in Stage 4b. naabu already
# records EVERY open port (they are merged into the final ip_port_pairs), so
# this only bounds which ports get version detection. Without a cap, the union
# of open ports across hundreds of hosts approaches the full top-1000 set and
# nmap re-scans every host against all of them — the single biggest time sink
# in Phase 3. The cap keeps the N ports open on the MOST hosts (highest signal).
# 0 = no cap (scan the full union). Override with --nmap-top-ports.
NMAP_TOP_PORTS="${NMAP_TOP_PORTS:-100}"

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
            --probe-reserved) METHO_PROBE_RESERVED=1; shift ;;
            --threads)        _require_int "$1" "$2"; THREADS="$2"; shift 2 ;;
            --parallel-hosts) _require_int "$1" "$2"; PARALLEL_HOSTS="$2"; shift 2 ;;
            --parallel-domains) _require_int "$1" "$2"; PARALLEL_DOMAINS="$2"; shift 2 ;;
            --doh-proxy-threads) _require_int "$1" "$2"; DOH_PROXY_THREADS="$2"; shift 2 ;;
            --domain-timeout) _require_int "$1" "$2"; DOMAIN_TIMEOUT="$2"; shift 2 ;;
            --rate-limit)     _require_int "$1" "$2"; RATE_LIMIT="$2"; shift 2 ;;
            --httpx-threads)  _require_int "$1" "$2"; HTTPX_THREADS="$2"; shift 2 ;;
            --cewl-max-hosts) _require_int "$1" "$2"; CEWL_MAX_HOSTS="$2"; shift 2 ;;
            --crawl-max-hosts) _require_int "$1" "$2"; CRAWL_MAX_HOSTS="$2"; shift 2 ;;
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
                echo "  --probe-reserved          ALSO probe hosts whose only addresses are reserved/private"
                echo "                            (status 'bogon'). They are unreachable from the internet but"
                echo "                            reachable on a network routed into the target's private/CGNAT"
                echo "                            space. HTTP only — they are still never port-scanned." 
                echo "  --threads N               Cloud_Enum thread count (default: 50). dnsx concurrency is"
                echo "                            transport-aware — see DNSX_THREADS_DOH/_UDP"
                echo "  --parallel-hosts N         Hosts crawled in parallel per tool (default: 5)"
                echo "  --parallel-domains N       Root domains processed in parallel in Phase 1 (default: 3)"
                echo "  --doh-proxy-threads N      Concurrent DoH requests the local proxy may have in"
                echo "                            flight (default: 128). Size it to at least"
                echo "                            parallel-domains × DNSX_THREADS_DOH, or queries queue past"
                echo "                            dnsx's own timeout and are recorded as 'timeout'"
                echo "  --domain-timeout N        Per-domain wall-clock cap in seconds (default: 7200; 0=off)"
                echo "  --rate-limit N            Requests/second (default: 100)"
                echo "  --httpx-threads N         httpx threads per process (default: 150, hard maximum"
                echo "                            ${HTTPX_THREADS_MAX}). This, not --rate-limit, is what bounds"
                echo "                            probe throughput. Values above the maximum are clamped"
                echo "                            and reported, not honoured silently."
                echo "  --cewl-max-hosts N        Max live hosts CeWL may crawl for the brute-force"
                echo "                            wordlist (default: 300; 0=unlimited)"
                echo "  --crawl-max-hosts N       Max live hosts Katana/SubDomainizer may crawl"
                echo "                            (default: 300; 0=unlimited)"
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

    # ── httpx thread ceiling ────────────────────────────────────────────────
    # Clamped rather than rejected: this is a tuning knob, and refusing to
    # start over it would be worse than running at the documented ceiling. The
    # clamp is always reported, because silently ignoring a requested value is
    # how "I set 500 and it still took an hour" becomes unexplainable.
    if (( HTTPX_THREADS > HTTPX_THREADS_MAX )); then
        log_warn "HTTPX_THREADS=${HTTPX_THREADS} exceeds the ${HTTPX_THREADS_MAX}-thread ceiling — clamping to ${HTTPX_THREADS_MAX}."
        log_warn "  Raise the ceiling deliberately via HTTPX_THREADS_MAX if you intend to hit targets harder."
        HTTPX_THREADS="$HTTPX_THREADS_MAX"
    fi
    if (( HTTPX_THREADS < 1 )); then
        log_warn "HTTPX_THREADS=${HTTPX_THREADS} is not usable — using 1."
        HTTPX_THREADS=1
    fi
    export HTTPX_THREADS
    # METHO_PROBE_RESERVED is read inside per-domain subshells and by Phase 3.
    export METHO_PROBE_RESERVED

    # ── DoH proxy sizing ────────────────────────────────────────────────────
    # In DoH mode every tool's DNS goes through ONE local proxy with a fixed
    # worker pool. The in-flight count against it is at least
    #     PARALLEL_DOMAINS × (dnsx threads)
    # and when that exceeds the pool, surplus queries queue past the client's
    # own timeout and are recorded as unresolved hosts — the exact failure the
    # proxy exists to avoid. Shipped defaults were 3 × 64 = 192 against 128
    # workers, i.e. over budget before httpx's own lookups are counted, and
    # nothing validated the invariant the README states. Now something does.
    if [[ "$DNS_MODE" == "doh" ]]; then
        local _doh_pool="${DOH_PROXY_THREADS:-128}"
        local _dnsx_each="${DNSX_THREADS:-${DNSX_THREADS_DOH:-64}}"
        local _workers="${PARALLEL_DOMAINS:-3}"
        local _dns_inflight=$(( _workers * _dnsx_each ))
        if (( _dns_inflight > _doh_pool )); then
            log_warn "DoH proxy undersized: ${_workers} domains × ${_dnsx_each} dnsx threads = ${_dns_inflight} in flight against ${_doh_pool} proxy workers."
            log_warn "  Surplus queries queue past dnsx's own timeout and are recorded as 'timeout'. Raise --doh-proxy-threads to >= ${_dns_inflight}, or lower DNSX_THREADS_DOH."
        fi
    fi
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
          "${OUTPUT_DIR}/.doh_extra_port" \
          "${OUTPUT_DIR}/doh_resolvers.txt" \
          "${OUTPUT_DIR}/.sys_resolvers.txt"
    # Run-level state that ACCUMULATES or is MERGED INTO, and therefore must not
    # survive into a new run in a reused output directory. Reuse is expected —
    # the proxy-file reset above exists precisely because it happens.
    #   stage_truncations.txt  appended per truncation; a stale one makes a
    #                          clean run report itself INCOMPLETE, and the
    #                          counts double up across runs.
    #   httpx_probed.txt       append-only ledger of every host handed to httpx.
    #                          Stale entries make Phase 3's late pass skip hosts
    #                          this run never probed — silent coverage loss, the
    #                          exact failure the ledger was added to prevent.
    #   httpx_metadata.tsv     written only when a merge produces rows, so a
    #                          leftover file is merged into rather than replaced
    #                          and keeps hosts that no longer answer.
    #   cloud_enum_results.json  APPENDED to by cloud_enum as it scans, and
    #                          re-parsed in full whenever it is non-empty, so a
    #                          re-run into a reused directory reads the previous
    #                          run's buckets as if this run had found them. It
    #                          also defeats the 900s cap: the stage can be killed
    #                          with nothing found and still report a full result
    #                          set, from a run whose targets may be unrelated.
    rm -f "${OUTPUT_DIR}/stage_truncations.txt" \
          "${OUTPUT_DIR}/httpx_probed.txt" \
          "${OUTPUT_DIR}/httpx_metadata.tsv" \
          "${OUTPUT_DIR}/phase2/cloud_enum_results.json"
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
# ── Probe ledger: every hostname handed to httpx, responders or not ──────────
# Phase 3's late pass exists to probe hosts discovered after the last Phase 1
# round, so it needs the set of hosts ALREADY PROBED. The only record that
# existed was httpx_metadata.tsv, which is built from httpx's -o output and so
# contains RESPONDERS ONLY. A host that was probed and stayed silent therefore
# looked unprobed and was probed a second time — 7,905 targets on a real run,
# about 64% of a 47-minute round, for zero new information.
#
# Scoped exactly like CANONICAL_DNS_TSV: each Phase 1 domain worker writes its
# own ledger via METHO_HTTPX_LEDGER, merge_per_domain_dns folds them into the
# global one, and Phase 3's late probe diffs against that.
# ── Stage budgets for the host-by-host crawling stages ───────────────────────
# Absolute epoch deadline from a duration in seconds. 0/empty/non-numeric means
# unlimited, and is reported as 0 so bounded_parallel skips the check entirely
# (passing a raw 0 would otherwise read as "the deadline was 1970" and truncate
# the stage before its first host).
_stage_deadline() {
    local secs="${1:-0}"
    if [[ "$secs" =~ ^[0-9]+$ ]] && (( secs > 0 )); then
        echo $(( $(date +%s) + secs ))
    else
        echo 0
    fi
}

# Order a live-host list by how much a crawl is likely to get out of each host,
# so a host-count cap spends its slots on the hosts that have something to give.
#
# The cap alone was not enough. `head -n` over the live list picked whatever came
# first, and that list is sorted alphabetically, so a 300-slot budget went to
# adm.*, adminauth.*, adms.* … — the alphabet, not the target. Measured on a
# 4,174-host run: the 300 hosts actually crawled were 208 canonical-redirect
# stubs (301) and 11 real pages (200), while the corpus held 577 hosts answering
# 200. CeWL then built a 168-word wordlist out of redirect stubs and the whole
# crawl budget bought 445 net-new hostnames.
#
# Ranking is free — it reorders the same list rather than lengthening it — and it
# is deliberately crude, because the alternative is crawling a host before
# knowing anything about it:
#
#   tier 0  200               real content: the only status a crawler can read
#   tier 1  401/403           auth surfaces; error pages still leak paths,
#                             framework hints and redirect_uri parameters
#   tier 2  3xx               redirect stubs — a crawl mostly re-follows them
#   tier 3  everything else  5xx, 000, no response
#   tier 4  no metadata       never answered httpx; nothing to rank on
#
# Within a tier: hosts not behind a CDN first (their content is the origin's,
# not an edge error page), then larger content_length, then input order so the
# result is deterministic.
#
# Falls back to the input order — unchanged — when there is no usable metadata,
# and says so, because a silent fallback here is indistinguishable from the
# ranking having run and simply not helped.
_rank_crawl_candidates() { # <input_urls> <metadata_tsv> <output>
    local input="$1" meta="$2" output="$3"
    if [[ ! -s "$meta" ]] || (( $(wc -l < "$meta" 2>/dev/null || echo 0) < 2 )); then
        log_info "  crawl ranking: no httpx metadata at ${meta} — using input order" >&2
        cp "$input" "$output" 2>/dev/null || cat "$input" > "$output" 2>/dev/null || : > "$output"
        return 0
    fi
    awk -F'\t' '
        function tier(s) {
            if (s == "200") return 0
            if (s == "401" || s == "403") return 1
            if (s ~ /^3[0-9][0-9]$/) return 2
            return 3
        }
        NR == FNR {
            if (FNR == 1 && $1 == "hostname") next
            h = tolower($1)
            st[h]  = $6
            cdn[h] = ($2 == "true") ? 1 : 0
            cl[h]  = ($5 + 0)
            known[h] = 1
            next
        }
        {
            h = tolower($0)
            sub(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, "", h)
            sub(/[\/:?].*$/, "", h)
            t = (h in known) ? tier(st[h]) : 4
            c = (h in known) ? cdn[h] : 1
            printf "%d\t%d\t%d\t%d\t%s\n", t, c, (h in known) ? -cl[h] : 0, FNR, $0
        }
    ' "$meta" "$input" 2>/dev/null \
        | sort -t"$(printf '\t')" -k1,1n -k2,2n -k3,3n -k4,4n 2>/dev/null \
        | cut -f5- > "$output" 2>/dev/null || cp "$input" "$output" 2>/dev/null || :
    [[ -s "$output" ]] || cp "$input" "$output" 2>/dev/null || : > "$output"
    return 0
}

# Cap a live-host list for a crawling stage. Echoes "<kept> <total>".
#
# CeWL, Katana and SubDomainizer crawl host-by-host with no natural bound, so on
# a large target they outlast the domain budget and get killed mid-stage — which
# takes every later stage down with them. The cap keeps a stage proportional to
# what it contributes. What was dropped is always reported: a silent cap looks
# exactly like a stage that ran and found nothing, which is the failure mode
# this pipeline keeps rediscovering.
#
# The list is RANKED before it is truncated (see _rank_crawl_candidates), so the
# slots go to hosts with content rather than to whichever hostname sorted first.
# Ranking is skipped when nothing is dropped, so an uncapped run keeps the exact
# input order its tools have always seen.
#
# Optional 5th argument: the httpx metadata TSV to rank against. Defaults to
# httpx_metadata.tsv, which is what the Phase 1 callers have in their cwd.
#
# 0 = unlimited (previous behaviour).
_cap_crawl_hosts() {
    local input="$1" cap="$2" output="$3" label="${4:-stage}"
    local meta="${5:-httpx_metadata.tsv}"
    local total=0 kept=0 ranked=0
    # `wc -l < file` is space-padded on BSD/macOS, and this value is echoed back
    # to the caller as "<kept> <total>", so strip the padding here rather than
    # making every caller parse around it.
    total=$(wc -l < "$input" 2>/dev/null | tr -d '[:space:]')
    [[ "$total" =~ ^[0-9]+$ ]] || total=0
    if (( cap > 0 )) && (( total > cap )); then
        local _ordered="${output}.ranked"
        _rank_crawl_candidates "$input" "$meta" "$_ordered" 2>/dev/null
        if [[ -s "$_ordered" ]]; then
            head -n "$cap" "$_ordered" > "$output" 2>/dev/null || : > "$output"
            ranked=1
        else
            head -n "$cap" "$input" > "$output" 2>/dev/null || : > "$output"
        fi
        rm -f "$_ordered" 2>/dev/null || true
        kept=$(wc -l < "$output" 2>/dev/null | tr -d '[:space:]')
        [[ "$kept" =~ ^[0-9]+$ ]] || kept=0
        # To STDERR: this function's stdout is captured by the caller as
        # "<kept> <total>", and log_warn writes to stdout. A log line here
        # silently becomes part of the returned value — the same defect that
        # once handed cloud_enum a two-line -nsf argument.
        if (( ranked )); then
            log_warn "  ${label}: input capped at ${cap} of ${total} hosts — kept the ${cap} highest-ranked (200 > auth > redirect > other); raise the cap or set it to 0 for unlimited" >&2
        else
            log_warn "  ${label}: input capped at ${cap} of ${total} hosts — the remainder is skipped (raise the cap, or set it to 0 for unlimited)" >&2
        fi
    else
        cp "$input" "$output" 2>/dev/null || cat "$input" > "$output" 2>/dev/null || : > "$output"
        kept=$total
    fi
    echo "${kept:-0} ${total:-0}"
}

# Wall-clock cap for a scan of <n> targets: base overhead plus a per-target
# allowance, bounded by a ceiling.
#
# Shared by every bounded scan — naabu chunks, nmap -sV and the httpx rounds —
# so the same "a small target keeps a tight timeout, a large one keeps a real
# one" rule applies everywhere instead of each stage inventing its own.
_scaled_scan_cap() { # <n_targets> <base_overhead> <seconds_per_target> <cap>
    local actual="${1:-0}" base="${2:-300}" per="${3:-2}" cap="${4:-3600}"
    local t=$(( base + actual * per ))
    (( t > cap )) && t="$cap"
    (( t < 1 )) && t=1
    echo "$t"
}

_httpx_ledger_path() {
    echo "${METHO_HTTPX_LEDGER:-${OUTPUT_DIR:-/output}/httpx_probed.txt}"
}

# ── Record a truncation ──────────────────────────────────────────────────────
# One writer, one format. Four call sites hand-rolled this printf, which is
# precisely how the nmap variant ended up with a different field shape from the
# rest — and the filename is read by two loops that only agree on the format by
# convention.
#
#   _record_truncation <domain|all> <stage> <detail>
_record_truncation() {
    mkdir -p "${OUTPUT_DIR:-/output}" 2>/dev/null || true
    printf '%s\t%s\t%s\n' "${1:-?}" "${2:-stage}" "${3:-}" \
        >> "${OUTPUT_DIR:-/output}/stage_truncations.txt" 2>/dev/null || true
}

# Did timeout(1) kill the command? 124 is its own exit status.
#
# Recording on 124 rather than on "non-zero" matters. A stage that failed for its
# own reason is a different finding from one cut off mid-work, and only the
# latter means everything downstream of it is a lower bound. Treating every
# non-zero exit as truncation would cry wolf on the tool failures that are
# routine (a passive source with no token, an empty grep).
_was_capped() { [[ "${1:-0}" -eq 124 ]]; }

# Append a round's input to the ledger. Called AFTER the round returns: the
# ledger's job is "do not probe this again", and a round that was killed before
# it could run its targets should not claim them — re-probing is the safe
# direction to err in, and it is what happened before this existed.
httpx_ledger_record() {
    local input_file="$1"
    [[ -s "$input_file" ]] || return 0
    local ledger
    ledger=$(_httpx_ledger_path)
    mkdir -p "$(dirname "$ledger")" 2>/dev/null || true
    cat "$input_file" >> "$ledger" 2>/dev/null || true
}

# Already-probed hostnames, sorted and deduped. Missing ledger prints nothing.
httpx_ledger_read() {
    local ledger
    ledger=$(_httpx_ledger_path)
    if [[ -s "$ledger" ]]; then
        sort -u "$ledger"
    fi
}

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

    # Resolve through the SAME resolver the canonical dataset was built with.
    #
    # Without this, httpx falls back to the container's system resolver
    # (Docker's 192.168.65.7, which forwards to the host's own DNS), so in DoH
    # mode the dataset says a host resolves to one address while httpx
    # connects to whatever the local resolver returns. That is two DNS views
    # for one target — the split-horizon / fake-IP case DoH mode exists to
    # avoid — and because dnsx's DoH queries bypass the OS resolver entirely,
    # httpx's ~12,320 cold lookups were landing right back on the local
    # network path that DoH mode had just taken all 29,022 names off.
    #
    # DoH transport only, and "on DoH" means the proxy is RUNNING — not that
    # DoH was asked for. _using_doh_transport() answers that, because DNS_MODE
    # still reads "doh" after a fallback has swapped RESOLVERS_FILE for the
    # built-in UDP pool; gating on DNS_MODE would have handed httpx the
    # unvetted ~12.7K-entry static list on exactly the networks where DoH had
    # already failed, trading a divergence risk for a resolution-failure one.
    #
    # On the DoH transport, RESOLVERS_FILE is a single health-checked local
    # proxy address, so both layers provably agree. Everywhere else httpx keeps
    # the system resolver it has always used — unchanged behaviour, so UDP mode
    # cannot regress. The divergence still exists there, so it is reported
    # rather than left implicit.
    local -a _httpx_resolver_args=()
    local _httpx_on_doh=0
    if _using_doh_transport && [[ -s "${RESOLVERS_FILE:-}" ]]; then
        _httpx_resolver_args=(-r "$RESOLVERS_FILE")
        _httpx_on_doh=1
    else
        log_info "httpx: not on the DoH transport (DNS_MODE=${DNS_MODE}) — probing via the system resolver; IPs may differ from the canonical dataset"
    fi

    # httpx re-resolves every name itself, so on the DoH transport its DNS runs
    # through the local proxy. A UDP-tuned 10s all-in timeout expired during that
    # resolution and marked live hosts dead, and the full thread fan-out overran
    # the shared proxy pool. Widen the timeout and cap concurrency on DoH only.
    local _httpx_timeout _httpx_threads
    _httpx_timeout=$(_httpx_probe_timeout "$_httpx_on_doh")
    _httpx_threads=$(_httpx_probe_threads "$_httpx_on_doh")
    (( _httpx_on_doh == 1 )) && log_info "httpx: DoH transport — ${_httpx_threads} threads, ${_httpx_timeout}s per-request timeout (DNS resolves through the local proxy)"

    # Bound the round. See HTTPX_TIMEOUT_MAX for why this did not exist before:
    # Phase 3's late probe has no watchdog above it, so an unbounded httpx there
    # could hang the whole run.
    local _probe_cap _httpx_rc=0
    _probe_cap=$(_scaled_scan_cap "$target_count" "${HTTPX_TIMEOUT_BASE:-60}" \
        "${HTTPX_SECONDS_PER_TARGET:-1}" "${HTTPX_TIMEOUT_MAX:-3600}")

    cat "$input_file" | timeout "$_probe_cap" httpx \
        ${_httpx_resolver_args[@]+"${_httpx_resolver_args[@]}"} \
        -silent \
        -json \
        -cdn \
        -status-code \
        -title \
        -tech-detect \
        -web-server \
        -content-length \
        -threads "$_httpx_threads" \
        -timeout "$_httpx_timeout" \
        -retries 2 \
        -rate-limit "$_rl" \
        -o "$output_json" > /dev/null 2>"$httpx_log" || _httpx_rc=$?

    if _was_capped "$_httpx_rc"; then
        _record_truncation "${domain:-all}" "httpx" "hit its ${_probe_cap}s cap over ${target_count} targets — results are partial"
        log_warn "httpx was KILLED at its ${_probe_cap}s cap over ${target_count} targets — results are PARTIAL (whatever flushed is kept)"
    fi

    # Ledger the round's input (responders AND non-responders) so Phase 3 can
    # tell "already probed" from "never probed". See httpx_ledger_record.
    httpx_ledger_record "$input_file"

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
    # Strip percent-encoded fragments: URLs like
    # https://x.example.com/redirect?to=%2Fapp.example.com would otherwise
    # yield bogus "2Fapp.example.com" tokens (the %2F path separator
    # merges with the following hostname chars).
    #
    # `%25` must be expanded BEFORE the general `%XX` strip, and the pair run
    # twice, because the input is frequently DOUBLE-encoded. A single pass at
    # `%XX` turns `%252F` into a literal `2F` glued to the next hostname and
    # stops — there is no `%` left to match, so it can never recover the second
    # level. That is exactly what happened: waymore URL lists carry OAuth
    # callbacks with `redirect_uri=https%253A%252F%252Fapi.portal.vodafone.com`,
    # and a run produced 37 hostnames like `2Fapi.portal.vodafone.com` and
    # `2Fciamsso.ciam.vodafone.com` — plausible-looking, charset-valid, entirely
    # fictional. They reached the hostname inventory, the canonical dataset and
    # the dnsgen seed list. Order matters: `%25` → `%` first, then `%XX` → space,
    # twice, resolves three levels of encoding.
    #
    # Note what is deliberately NOT done here: filtering tokens that merely start
    # with two hex digits. Real hostnames do — `2fa.id.aws.cps.vodafone.com` and
    # `6u2fa.k8s.eu-central-1.aws.cps.vodafone.com` were both in the same run's
    # output — so a prefix filter would delete real hosts to hide fake ones.
    # Decoding correctly is the whole fix.
    sed -E 's/%25/%/g; s/%[0-9A-Fa-f]{2}/ /g; s/%25/%/g; s/%[0-9A-Fa-f]{2}/ /g' \
        "$input_file" 2>/dev/null \
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

# ── Normalize a cloud-asset row to a bare hostname ───────────────────────────
# The three cloud-asset sources do not agree on shape and nothing reconciled
# them: dnsx contributes bare hostnames, katana contributes full URLs with
# scheme, and cloud_enum contributed JSON-quoted URLs. `sort -u` over the union
# was the only "normalization", so the aggregate file held three formats at once
# and every consumer had to guess. results.sh guessed with a scheme-stripping
# regex, which produced `"http:` from a quoted row, failed the in-scope test, and
# silently discarded all 40 cloud_enum assets from every per-root file.
#
# Normalizing here means the aggregate and every slice of it are composable, and
# `sort -u` finally dedupes across sources instead of across formats.
#
# Wildcards are DROPPED, not de-starred: `https://*.amazonaws.com` scraped out of
# crawled JavaScript is a pattern reference, not a discovered endpoint, and
# reducing it to `amazonaws.com` would inject a provider root into the asset
# inventory.
_cloud_asset_normalize() {
    sed -E 's/^[[:space:]]*"//; s/"[[:space:]]*$//; s/^[[:space:]]+//; s/[[:space:]]+$//' \
        | grep -vE '^\*\.' \
        | sed -E 's|^[a-zA-Z][a-zA-Z0-9+.-]*://||' \
        | sed -E 's|[/:;?].*$||' \
        | sed -E 's/^\.+//; s/\.+$//' \
        | tr '[:upper:]' '[:lower:]' \
        | grep -E '^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$' || true
}