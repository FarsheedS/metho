#!/usr/bin/env bash
# Unit tests for metho pure functions — run inside the container with lib/ mounted.
#
# The tree under test is /opt/scripts inside the image. When run from a checkout
# (or against any other tree, via METHO_SCRIPTS_DIR) it resolves the repo root
# instead, so the suite is runnable — and so a modified tree can be compared
# against a pristine one:
#     git archive HEAD | tar -x -C /tmp/base
#     METHO_SCRIPTS_DIR=/tmp/base bash tests/run_tests.sh
# Without this the suite silently tested whichever tree happened to be at
# /opt/scripts and failed wholesale anywhere else.
if [[ -z "${METHO_SCRIPTS_DIR:-}" && ! -f /opt/scripts/lib/utils.sh ]]; then
    _repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    [[ -f "${_repo_root}/lib/utils.sh" ]] && METHO_SCRIPTS_DIR="$_repo_root"
fi
SCRIPT_DIR="${METHO_SCRIPTS_DIR:-/opt/scripts}"
if [[ ! -f "${SCRIPT_DIR}/lib/utils.sh" ]]; then
    echo "tests: cannot find lib/utils.sh under SCRIPT_DIR=${SCRIPT_DIR}" >&2
    echo "       set METHO_SCRIPTS_DIR to the tree you want to test" >&2
    exit 1
fi
source "${SCRIPT_DIR}/lib/utils.sh"
source "${SCRIPT_DIR}/lib/canonical_dns.sh"
source "${SCRIPT_DIR}/lib/classify.sh"
# phase3.sh holds the late-probe candidate selection, whose "already probed"
# test is exactly what the ledger changed. Without it sourced here, a test that
# calls into phase3 fails as "command not found" and — because the call is
# redirected — looks like an assertion failure rather than a missing source.
source "${SCRIPT_DIR}/lib/phase3.sh"
# phase2.sh and consolidate.sh hold the cloud-asset normalization path and the
# final/ consolidation globs, both of which had defects that only a test against
# a fixture output directory can pin.
source "${SCRIPT_DIR}/lib/phase2.sh"
source "${SCRIPT_DIR}/lib/consolidate.sh"
source "${SCRIPT_DIR}/lib/results.sh"

PASS=0 FAIL=0
t() { # t <name> <expected> <actual>
    if [[ "$2" == "$3" ]]; then PASS=$((PASS+1)); echo "PASS: $1";
    else FAIL=$((FAIL+1)); echo "FAIL: $1 — expected [$2] got [$3]"; fi
}

# Count matching lines, always as a single unpadded number.
# `grep -c ... || echo 0` prints "0" AND then "0" again (grep -c already writes
# its count before exiting 1 on no match), which turns a passing assertion into
# a multi-line failure. `wc -l < file` is space-padded on BSD/macOS.
_count_in() { # _count_in <file> <grep-pattern>
    if [[ -s "$1" ]]; then grep -c -- "$2" "$1" 2>/dev/null || true; else echo 0; fi
}
_lines() { wc -l < "$1" 2>/dev/null | tr -d '[:space:]'; }

# ── normalize_hostname ──
t "normalize wildcard+case+dot" "foo.com" "$(normalize_hostname '*.Foo.com.')"
t "normalize empty" "" "$(normalize_hostname '')"

# ── _safe_name ──
t "safe_name url" "https___example.com_a" "$(_safe_name 'https://example.com/a')"

# ── _format_duration ──
t "duration 47s" "47s" "$(_format_duration 47)"
t "duration 134s" "2m 14s" "$(_format_duration 134)"
t "duration 7300s" "2h 1m" "$(_format_duration 7300)"

# ── match_root_domain (ccTLD safety) ──
ROOT_DOMAINS_FILE="$(mktemp)"; printf 'example.co.uk\nexample.com\n' > "$ROOT_DOMAINS_FILE"
t "match exact ccTLD root" "example.co.uk" "$(match_root_domain 'example.co.uk')"
t "match ccTLD subdomain" "example.co.uk" "$(match_root_domain 'shop.example.co.uk')"
t "match regular subdomain" "example.com" "$(match_root_domain 'a.b.example.com')"
t "match out-of-scope" "" "$(match_root_domain 'evil.com')"
t "match suffix-lookalike rejected" "" "$(match_root_domain 'notexample.com')"

# ── extract_domains ──
IN="$(mktemp)"; printf 'see https://a.example.com/x and b.test.org\nbare 127.0.0.1 no tld\n' > "$IN"
OUT="$(mktemp)"
extract_domains "$IN" "$OUT"
t "extract_domains finds hosts" "$(printf 'a.example.com\nb.test.org')" "$(cat "$OUT")"

# ── filter_cloud_domains ──
IN2="$(mktemp)"; printf 'bucket.s3.amazonaws.com\nwww.example.com\napp.herokuapp.com\nstorage.blob.core.windows.net\n' > "$IN2"
OUT2="$(mktemp)"
filter_cloud_domains "$IN2" "$OUT2"
t "filter_cloud_domains picks only cloud" "$(printf 'app.herokuapp.com\nbucket.s3.amazonaws.com\nstorage.blob.core.windows.net')" "$(cat "$OUT2")"

# ── classify_ip (priority order + org-name rules) ──
source "${SCRIPT_DIR}/config/asn_providers.sh"
t "classify httpx cdn wins" "cdn" "$(classify_ip 1.1.1.1 AS64496 'Some Hosting' true)"
t "classify asn cdn number" "cdn" "$(classify_ip 1.1.1.1 AS13335 'Cloudflare, Inc.' false)"
t "classify asn cloud number" "cloud" "$(classify_ip 1.1.1.1 AS16509 '' false)"
t "classify asn dedicated number" "dedicated" "$(classify_ip 1.1.1.1 AS53667 '' false)"
t "classify unknown default" "unknown" "$(classify_ip 1.1.1.1 '' '' false)"
t "classify empty asn no crash" "unknown" "$(classify_ip 1.1.1.1 '' '' '')"

# ── canonical_dns add/merge lifecycle ──
WORK="$(mktemp -d)"; OUTPUT_DIR="$WORK"
init_canonical_dns > /dev/null
printf 'www.example.com\n' > "$WORK/h1.txt"
canonical_dns_add_sources "subfaster" "$WORK/h1.txt" "example.com" > /dev/null
t "canonical add creates pending" "www.example.com	example.com	subfaster				pending" "$(tail -1 "$WORK/canonical_dns.tsv")"
printf 'www.example.com\napi.example.com\n' > "$WORK/h2.txt"
canonical_dns_add_sources "waymore" "$WORK/h2.txt" "example.com" > /dev/null
t "canonical merge dedups and appends source" "www.example.com	example.com	subfaster;waymore				pending" "$(awk -F'\t' '$1=="www.example.com"' "$WORK/canonical_dns.tsv")"
t "canonical new host added" "api.example.com" "$(awk -F'\t' '$1=="api.example.com"{print $1}' "$WORK/canonical_dns.tsv")"

# ── filter_in_scope_hostnames ──
# Every ingest path must keep third-party hostnames (cloud bucket names, SPF
# includes, CDN targets) out of the canonical dataset: their IPs would
# otherwise be resolved, classified and handed to naabu/nmap as targets.
SCOPE="$(mktemp)"
printf 'example.com\nexample.co.uk\n' > "$SCOPE"
ROOT_DOMAINS_FILE="$SCOPE"
IN3="$(mktemp)"; OUT3="$(mktemp)"
printf 'a.example.com\nb.example.co.uk\nbucket.s3.amazonaws.com\nnotexample.com\nx.evil.com\n' > "$IN3"
filter_in_scope_hostnames "$IN3" "$OUT3"
t "filter_in_scope keeps only in-scope" "$(printf 'a.example.com\nb.example.co.uk')" "$(cat "$OUT3")"
IN4="$(mktemp)"; OUT4="$(mktemp)"
: > "$IN4"
filter_in_scope_hostnames "$IN4" "$OUT4"
t "filter_in_scope empty input -> empty output" "" "$(cat "$OUT4")"

# ── _resolver_file_is_plain_ips ──
# cloud_enum's dnspython accepts bare addresses only; it rejects both
# "doh:https://..." and the "127.0.0.1:5353" form the DoH proxy uses.
RP1="$(mktemp)"; printf '1.1.1.1\n8.8.8.8\n' > "$RP1"
RP2="$(mktemp)"; printf '127.0.0.1:5353\n' > "$RP2"
RP3="$(mktemp)"; printf 'doh:https://1.1.1.1/dns-query\n' > "$RP3"
RP4="$(mktemp)"; printf '2001:4860:4860::8888\n' > "$RP4"
t "plain IPv4 list accepted"        "0" "$(_resolver_file_is_plain_ips "$RP1"; echo $?)"
t "host:port list rejected"         "1" "$(_resolver_file_is_plain_ips "$RP2"; echo $?)"
t "doh: URL list rejected"          "1" "$(_resolver_file_is_plain_ips "$RP3"; echo $?)"
t "bare IPv6 list accepted"         "0" "$(_resolver_file_is_plain_ips "$RP4"; echo $?)"

# ── bounded_parallel must not wait on unrelated background children ──
# The DoH proxy is a long-lived child of the pipeline shell, and the old
# implementation ended in a bare `wait` — which waits on EVERY child. The
# first bounded_parallel that finished while the proxy was alive blocked
# forever, hanging the run between Phase 1 and the canonical-DNS merge with no
# error and no log line.
# The stand-in for the proxy MUST have its stdout redirected: a background
# process holding the command-substitution pipe open would make the test
# itself hang, which is the very failure it is checking for.
BP_OUT="$(timeout 25 bash -c "
    source '${SCRIPT_DIR}/lib/utils.sh' 2>/dev/null
    sleep 45 >/dev/null 2>&1 &
    printf '%s\n' one two three > /tmp/bp_in.$$
    bounded_parallel 2 /tmp/bp_in.$$ echo
    rm -f /tmp/bp_in.$$
    echo COMPLETED
" 2>/dev/null | tail -1)"
t "bounded_parallel ignores long-lived siblings" "COMPLETED" "${BP_OUT:-TIMED_OUT}"

# ── _dnsx_threads is transport-aware and honours an explicit pin ──
_DNS_MODE_SAVE2="$DNS_MODE"; _DNSX_T_SAVE="${DNSX_THREADS:-}"
DNS_MODE="udp"; DNSX_THREADS=""; t "udp dnsx threads default" "100" "$(_dnsx_threads)"
DNS_MODE="doh"; DNSX_THREADS=""; t "doh dnsx threads default" "128"  "$(_dnsx_threads)"
DNS_MODE="doh"; DNSX_THREADS="7"; t "explicit dnsx threads wins" "7" "$(_dnsx_threads)"
DNS_MODE="$_DNS_MODE_SAVE2"; DNSX_THREADS="$_DNSX_T_SAVE"

# ── _dnsx_scaled_cap: floor for small batches, throughput-scaled for large ──
# Regression for the "DNSx runs over and over" audit finding: a fixed 600s cap
# could not finish ~25K hosts at DoH's ~16 q/s, leaving the pile for the next
# stage to re-grind. The cap now scales with batch size (default /15 q/s),
# bounded below by DNSX_TIMEOUT and above by DNSX_CAP_CEILING.
_DTS_SAVE="${DNSX_TIMEOUT:-}"; _DPS_SAVE="${DNSX_CAP_QUERIES_PER_SEC:-}"; _DCC_SAVE="${DNSX_CAP_CEILING:-}"
DNSX_TIMEOUT=600; DNSX_CAP_QUERIES_PER_SEC=15; DNSX_CAP_CEILING=5400
t "small batch keeps the floor"        "600"  "$(_dnsx_scaled_cap 300)"
t "batch at the floor boundary"        "600"  "$(_dnsx_scaled_cap 9000)"
t "large batch scales past the floor"  "2000" "$(_dnsx_scaled_cap 30000)"
t "pathological batch hits the ceiling" "5400" "$(_dnsx_scaled_cap 200000)"
DNSX_TIMEOUT="$_DTS_SAVE"; DNSX_CAP_QUERIES_PER_SEC="$_DPS_SAVE"; DNSX_CAP_CEILING="$_DCC_SAVE"

# ── httpx probe is transport-aware (widen on DoH, keep UDP unchanged) ──
# Regression for the live-server undercount: httpx resolves through the DoH
# proxy, so a UDP-tuned 10s timeout and the full thread fan-out lost live hosts.
_HXT_SAVE="${HTTPX_THREADS:-}"; _HXTD_SAVE="${HTTPX_TIMEOUT_DOH:-}"; _HXTH_SAVE="${HTTPX_THREADS_DOH:-}"; _HXTO_SAVE="${HTTPX_TIMEOUT:-}"
HTTPX_THREADS=150; HTTPX_TIMEOUT=10; HTTPX_TIMEOUT_DOH=25; HTTPX_THREADS_DOH=50
t "httpx timeout: UDP keeps the tight budget" "10" "$(_httpx_probe_timeout 0)"
t "httpx timeout: DoH gets the wide budget"   "25" "$(_httpx_probe_timeout 1)"
t "httpx threads: UDP keeps the full pool"    "150" "$(_httpx_probe_threads 0)"
t "httpx threads: DoH caps to the proxy share" "50" "$(_httpx_probe_threads 1)"
HTTPX_THREADS=30
t "httpx threads: DoH never raises a lower pin" "30" "$(_httpx_probe_threads 1)"
HTTPX_THREADS="$_HXT_SAVE"; HTTPX_TIMEOUT_DOH="$_HXTD_SAVE"; HTTPX_THREADS_DOH="$_HXTH_SAVE"; HTTPX_TIMEOUT="$_HXTO_SAVE"

# ── _cymru_origin_join: multi-origin ASN must not be glued into a phantom ──
# Regression for AS1516943515 (=15169+43515): Team Cymru's DNS service returns
# space-separated origin ASNs; the parser must keep the first, not concatenate.
COJ="$(mktemp -d)"
printf 'x.origin.asn.cymru.com\t35.214.147.179\n' > "$COJ/map"
printf 'x.origin.asn.cymru.com\t15169 43515 | 35.214.128.0/17 | US | arin | 2012-01-01\n' > "$COJ/answers"
t "multi-origin ASN keeps the first, not glued" "35.214.147.179	15169	35.214.128.0/17	US	arin	2012-01-01" "$(_cymru_origin_join "$COJ/map" "$COJ/answers")"
printf 'y.origin.asn.cymru.com\t8.8.8.8\n' > "$COJ/map"
printf 'y.origin.asn.cymru.com\t15169 | 8.8.8.0/24 | US | arin | 2000-01-01\n' > "$COJ/answers"
t "single-origin ASN is preserved" "8.8.8.8	15169	8.8.8.0/24	US	arin	2000-01-01" "$(_cymru_origin_join "$COJ/map" "$COJ/answers")"
rm -rf "$COJ"

# ── _dnsx_query_timeout is transport-aware ──
_DNS_MODE_SAVE="$DNS_MODE"
DNS_MODE="udp"; t "udp per-query timeout" "5"  "$(_dnsx_query_timeout)"
DNS_MODE="doh"; t "doh per-query timeout covers the proxy" "15" "$(_dnsx_query_timeout)"
DNS_MODE="$_DNS_MODE_SAVE"

# ── DoH proxy unit checks ──
# Parse rather than py_compile: this tree may be mounted read-only, and
# py_compile writes a __pycache__ directory next to the source.
t "doh_proxy parses as valid Python" "0" "$(python3 -c "
import ast, sys
ast.parse(open(sys.argv[1]).read())
" "${SCRIPT_DIR}/lib/doh_proxy.py" 2>/dev/null; echo $?)"
t "doh_proxy builds a well-formed query" "1" "$(python3 -c "
import sys, struct
sys.path.insert(0, '${SCRIPT_DIR}/lib')
import doh_proxy
q = doh_proxy.build_query('example.com')
ok = (len(q) == 29
      and struct.unpack('>H', q[4:6])[0] == 1
      and q[-4:] == b'\x00\x01\x00\x01')
print(1 if ok else 0)")"
# A demoted endpoint must stop being tried first, but must stay in the
# rotation as a last resort — that is what stops one blocked endpoint from
# swallowing a third of all queries.
t "endpoint pool demotes a dead endpoint" "1" "$(python3 -c "
import sys
sys.path.insert(0, '${SCRIPT_DIR}/lib')
import doh_proxy
p = doh_proxy.EndpointPool(['a', 'b', 'c'], fail_threshold=2, cooldown=60)
p.note_fail('a'); p.note_fail('a')
c = p.candidates()
print(1 if c[0] in ('b', 'c') and len(c) == 3 else 0)")"
# A permanently dead endpoint must STAY demoted. The demotion deadline is
# refreshed on every failure; testing with `==` instead of `>=` fires once and
# lets the endpoint rejoin the rotation for good after one cooldown.
t "a dead endpoint stays demoted past its cooldown" "1" "$(python3 -c "
import sys
sys.path.insert(0, '${SCRIPT_DIR}/lib')
import doh_proxy
p = doh_proxy.EndpointPool(['a'], fail_threshold=2, cooldown=60)
for _ in range(10):
    p.note_fail('a')
p._down_until['a'] = __import__('time').monotonic() - 1   # pretend 60s elapsed
p.note_fail('a')                                          # still failing
print(1 if p.healthy() == [] else 0)")"

# ── Canonical DNS lifecycle with a stubbed dnsx ───────────────────────────────
# The header-drop bug, the nxdomain labelling and the health gate all live
# behind dnsx calls. Stubbing the binary runs the real code paths hermetically.
STUB="$(mktemp -d)"
cat > "${STUB}/dnsx" <<'STUBEOF'
#!/usr/bin/env bash
# Minimal dnsx stand-in. Driven by:
#   FAKE_DNSX_A    hostnames that resolve to a public A record
#   FAKE_DNSX_ADDR "host=literal" pairs; the family is inferred from the
#                  literal, so one variable drives both the A and AAAA columns
#   FAKE_DNSX_NX   hostnames reported NXDOMAIN by the -rcode pass
#   FAKE_DNSX_FAIL 1 = every query errors (transport unreachable)
#   FAKE_DNSX_LOG  file to append every queried hostname to, so a test can
#                  assert what a pass did and did not ask for
input="$(cat)"
# dnsx also takes -l FILE; the Cymru ASN fallback uses that form.
for a in "$@"; do :; done
if [[ " $* " == *" -l "* ]]; then
    next=0
    for a in "$@"; do
        if [[ "$next" == "1" ]]; then input="$(cat "$a")"; break; fi
        [[ "$a" == "-l" ]] && next=1
    done
fi
# Record what was actually asked for, so a test can prove a retry pass skipped
# names an earlier pass had already settled.
[[ -n "${FAKE_DNSX_LOG:-}" ]] && printf '%s\n' "$input" >> "$FAKE_DNSX_LOG"
# Team Cymru's DNS service returns EVERY covering prefix; the real service
# does this too, and the code must keep only the most specific one.
if [[ " $* " == *" -txt "* ]]; then
    for h in ${FAKE_DNSX_TXT:-}; do
        grep -qx -- "$h" <<<"$input" || continue
        case "$h" in
            *.origin.asn.cymru.com)
                printf '{"host":"%s","txt":["16509 | 192.0.2.0/24 | US | arin | 2017-12-20","16509 | 192.0.2.0/21 | US | arin | 2017-12-20"]}\n' "$h" ;;
            AS*.asn.cymru.com)
                printf '{"host":"%s","txt":["16509 | US | arin | 2017-12-20 | AMAZON-02 - Amazon.com, Inc., US"]}\n' "$h" ;;
        esac
    done
    exit 0
fi
if [[ " $* " == *" -rcode nxdomain "* ]]; then
    for h in ${FAKE_DNSX_NX:-}; do
        grep -qx -- "$h" <<<"$input" || continue
        printf '{"host":"%s","status_code":"NXDOMAIN"}\n' "$h"
    done
    exit 0
fi
fail=0
[[ "${FAKE_DNSX_FAIL:-0}" == "1" ]] && fail=1
# Fail only for a specific resolver, so a batch can fail on the primary
# transport and succeed on the fallback.
if [[ -n "${FAKE_DNSX_FAIL_RSLVR:-}" ]]; then
    next=0
    for a in "$@"; do
        if [[ "$next" == "1" ]]; then
            [[ "$a" == *"$FAKE_DNSX_FAIL_RSLVR"* ]] && fail=1
            break
        fi
        [[ "$a" == "-r" ]] && next=1
    done
fi
if [[ "$fail" == "1" ]]; then
    echo "[WRN] $(grep -c . <<<"$input") domains failed to resolve (consider increasing -retry or reducing -threads)" >&2
    exit 0
fi
# One JSON record per host, carrying every field found for it. Real dnsx emits
# a single object per host; emitting one line per FIELD made the cname line
# (which carries no address) overwrite the address line's status during the
# parse — an artifact of the stub, not of the code under test, and one that
# disguised a real assertion failure as a code defect.
_emit_host() {
    local h="$1" fields="" a kv ip target
    grep -qx -- "$h" <<<"$input" || return 0
    # A real resolver answers the probe name too — _probe_system_resolver uses
    # it to decide whether a fallback transport is usable at all.
    for a in ${FAKE_DNSX_A:-} whoami.akamai.net; do
        if [[ "$a" == "$h" ]]; then fields="${fields}\"a\":[\"93.184.216.34\"],"; fi
    done
    # An explicit address per host, family chosen by the literal. Needed to
    # exercise the reserved-IP filter on BOTH columns: the bug it guards
    # against left AAAA answers looking like a different record type entirely.
    for kv in ${FAKE_DNSX_ADDR:-}; do
        if [[ "${kv%%=*}" == "$h" ]]; then
            ip="${kv#*=}"
            if [[ "$ip" == *:* ]]; then fields="${fields}\"aaaa\":[\"$ip\"],"
            else fields="${fields}\"a\":[\"$ip\"],"; fi
        fi
    done
    # A bare CNAME answer: the host aliases to another name and has no address
    # of its own. This is the population that used to be recorded as "resolved"
    # with an empty address column and handed to httpx.
    for kv in ${FAKE_DNSX_CNAME:-}; do
        if [[ "${kv%%=*}" == "$h" ]]; then
            target="${kv#*=}"
            fields="${fields}\"cname\":[\"$target\"],"
        fi
    done
    [[ -n "$fields" ]] || return 0
    printf '{"host":"%s",%s}\n' "$h" "${fields%,}"
}

_ALL_HOSTS="$(
    for kv in ${FAKE_DNSX_A:-} ${FAKE_DNSX_ADDR:-} ${FAKE_DNSX_CNAME:-} whoami.akamai.net; do
        echo "${kv%%=*}"
    done | sort -u
)"
for h in $_ALL_HOSTS; do _emit_host "$h"; done
exit 0
STUBEOF
chmod +x "${STUB}/dnsx"

# Minimal httpx stand-in, so httpx_probe's parsing, ledger write and canonical
# merge all run for real. Without it the host's own `httpx` gets called — which
# on a developer machine is the Python HTTP client, a different tool that merely
# shares the name, and would either hit the network or fail in a way that looks
# like a pipeline defect.
cat > "${STUB}/httpx" <<'STUBEOF'
#!/usr/bin/env bash
# Honour -o (httpx_probe writes results to a file, not stdout).
out=""; prev=""
for a in "$@"; do
    [[ "$prev" == "-o" ]] && out="$a"
    prev="$a"
done
[[ -n "$out" ]] && exec > "$out"
while IFS= read -r h; do
    [[ -n "$h" ]] || continue
    printf '{"url":"https://%s","input":"%s","host":"%s","status_code":200}\n' "$h" "$h" "$h"
done
exit 0
STUBEOF
chmod +x "${STUB}/httpx"
export PATH="${STUB}:${PATH}"

W2="$(mktemp -d)"; OUTPUT_DIR="$W2"
CANONICAL_DNS_TSV="${W2}/canonical_dns.tsv"
HTTPX_META_TSV="${W2}/httpx_metadata.tsv"
ROOT_DOMAINS_FILE="$SCOPE"
init_canonical_dns > /dev/null
printf 'a.example.com\nb.example.com\n' > "${W2}/in.txt"
canonical_dns_add_sources "test" "${W2}/in.txt" "example.com" > /dev/null
t "new TSV starts with a header" "hostname" "$(head -1 "$CANONICAL_DNS_TSV" | cut -f1)"
t "new TSV has header + 2 rows" "3" "$(_lines "$CANONICAL_DNS_TSV")"

FAKE_DNSX_A="a.example.com" FAKE_DNSX_NX="" canonical_dns_resolve_pending > /dev/null 2>&1
t "header survives a resolve pass" "hostname" "$(head -1 "$CANONICAL_DNS_TSV" | cut -f1)"
t "resolve pass loses no row" "3" "$(_lines "$CANONICAL_DNS_TSV")"
t "resolved host recorded" "resolved" "$(awk -F'\t' '$1=="a.example.com"{print $7}' "$CANONICAL_DNS_TSV")"
t "unanswered host stays timeout" "timeout" "$(awk -F'\t' '$1=="b.example.com"{print $7}' "$CANONICAL_DNS_TSV")"

FAKE_DNSX_A="" FAKE_DNSX_NX="b.example.com" canonical_dns_label_nxdomain > /dev/null 2>&1
t "nxdomain pass labels a dead name" "nxdomain" "$(awk -F'\t' '$1=="b.example.com"{print $7}' "$CANONICAL_DNS_TSV")"
t "header survives the nxdomain pass" "hostname" "$(head -1 "$CANONICAL_DNS_TSV" | cut -f1)"
t "nxdomain pass loses no row" "3" "$(_lines "$CANONICAL_DNS_TSV")"
t "resolved row untouched by nxdomain pass" "resolved" "$(awk -F'\t' '$1=="a.example.com"{print $7}' "$CANONICAL_DNS_TSV")"

# Health gate: a small batch must NOT flip the flag in either direction. This
# is the regression that let a 10-host batch re-arm a 28,927-host re-grind.
METHO_DNS_WORKING=0
printf 'c.example.com\n' > "${W2}/in2.txt"
canonical_dns_add_sources "test" "${W2}/in2.txt" "example.com" > /dev/null
FAKE_DNSX_A="c.example.com" FAKE_DNSX_NX="" canonical_dns_resolve_pending > /dev/null 2>&1
t "tiny successful batch cannot re-arm retries" "0" "$METHO_DNS_WORKING"

# A large batch that answers keeps the flag set; a large batch where the
# transport answers nothing clears it.
{ for i in $(seq 1 25); do echo "h${i}.example.com"; done; } > "${W2}/in3.txt"
canonical_dns_add_sources "test" "${W2}/in3.txt" "example.com" > /dev/null
FAKE_DNSX_A="$(tr '\n' ' ' < "${W2}/in3.txt")" FAKE_DNSX_NX="" canonical_dns_resolve_pending > /dev/null 2>&1
t "healthy large batch sets the flag" "1" "$METHO_DNS_WORKING"

{ for i in $(seq 1 25); do echo "d${i}.example.com"; done; } > "${W2}/in4.txt"
canonical_dns_add_sources "test" "${W2}/in4.txt" "example.com" > /dev/null
FAKE_DNSX_A="" FAKE_DNSX_NX="" FAKE_DNSX_FAIL=1 canonical_dns_resolve_pending > /dev/null 2>&1
t "unreachable transport clears the flag" "0" "$METHO_DNS_WORKING"

# ── Reserved-IP filter: address families ──
# Regression for the filter running the IPv4 octet parser over the AAAA column.
# `split(ip, a, ".")` returns ONE field for an IPv6 literal, so the `n != 4`
# guard was true for every IPv6 address: the whole AAAA column was destroyed on
# every run, and an IPv6-only host was reclassified "bogon" and dropped from
# HTTPx and nmap even when it was a perfectly public host. Both families must
# be judged on their own terms, and a stripped address must leave a trace.
printf 'v6only.example.com\nv6ula.example.com\nv4priv.example.com\nv4pub.example.com\n' > "${W2}/in5.txt"
canonical_dns_add_sources "test" "${W2}/in5.txt" "example.com" > /dev/null
FAKE_DNSX_ADDR="v6only.example.com=2a05:d014:9ed:7901:47a4:eb57:d2e6:7320 v6ula.example.com=fd12:3456:789a::1 v4priv.example.com=10.64.32.141 v4pub.example.com=93.184.216.34" \
    canonical_dns_resolve_pending > /dev/null 2>&1

t "public IPv6 survives the reserved-IP filter" \
  "2a05:d014:9ed:7901:47a4:eb57:d2e6:7320" \
  "$(awk -F'\t' '$1=="v6only.example.com"{print $5}' "$CANONICAL_DNS_TSV")"
t "IPv6-only host stays resolved, never bogon" "resolved" \
  "$(awk -F'\t' '$1=="v6only.example.com"{print $7}' "$CANONICAL_DNS_TSV")"
t "public IPv4 is still kept" "93.184.216.34" \
  "$(awk -F'\t' '$1=="v4pub.example.com"{print $4}' "$CANONICAL_DNS_TSV")"
t "private IPv4 is stripped" "" \
  "$(awk -F'\t' '$1=="v4priv.example.com"{print $4}' "$CANONICAL_DNS_TSV")"
t "private-only host becomes bogon" "bogon" \
  "$(awk -F'\t' '$1=="v4priv.example.com"{print $7}' "$CANONICAL_DNS_TSV")"
t "ULA IPv6 is stripped" "" \
  "$(awk -F'\t' '$1=="v6ula.example.com"{print $5}' "$CANONICAL_DNS_TSV")"
t "ULA-only host becomes bogon" "bogon" \
  "$(awk -F'\t' '$1=="v6ula.example.com"{print $7}' "$CANONICAL_DNS_TSV")"
t "stripped address is recorded for audit" "1" \
  "$(awk -F'\t' '$1=="v4priv.example.com" && $2=="10.64.32.141"{c++} END{print c+0}' "${CANONICAL_DNS_TSV}.bogon")"
t "audit names the matched IPv4 range" "1" \
  "$(awk -F'\t' '$1=="v4priv.example.com" && $3=="10.0.0.0/8"{c++} END{print c+0}' "${CANONICAL_DNS_TSV}.bogon")"
t "audit names the matched IPv6 range" "1" \
  "$(awk -F'\t' '$1=="v6ula.example.com" && $3=="fc00::/7 ULA"{c++} END{print c+0}' "${CANONICAL_DNS_TSV}.bogon")"

# ── Re-discovery must not re-open a settled row ──
# CT logs are historical, so the same dead names come back on every run.
# Resetting them would re-grind the whole NXDOMAIN pile and undo the
# one-query-per-name settling — the point of that pass on a network where bulk
# DNS is the constrained resource. METHO_NXDOMAIN_RECHECK=1 is the opt-out.
printf 'b.example.com\n' > "${W2}/in6.txt"
canonical_dns_add_sources "test" "${W2}/in6.txt" "example.com" > /dev/null
t "re-discovery leaves nxdomain settled" "nxdomain" \
  "$(awk -F'\t' '$1=="b.example.com"{print $7}' "$CANONICAL_DNS_TSV")"

export METHO_NXDOMAIN_RECHECK=1
canonical_dns_add_sources "test" "${W2}/in6.txt" "example.com" > /dev/null
unset METHO_NXDOMAIN_RECHECK
t "METHO_NXDOMAIN_RECHECK=1 re-opens it" "pending" \
  "$(awk -F'\t' '$1=="b.example.com"{print $7}' "$CANONICAL_DNS_TSV")"

# ── Settling first is what makes each name cost one query ──
# The whole point of hoisting canonical_dns_label_nxdomain into Phase 1 is that
# a name proven dead is never asked again. If the include_timeouts retry still
# touches settled rows, the pile gets re-ground at Stage 7 and again in Phase 3
# and the hoist buys nothing. The control below matters just as much: the retry
# must still fire for genuinely unresolved names, or this would "pass" by
# disabling retries altogether.
printf 's1.example.com\ns2.example.com\ns3.example.com\n' > "${W2}/in7.txt"
canonical_dns_add_sources "test" "${W2}/in7.txt" "example.com" > /dev/null
FAKE_DNSX_A="" canonical_dns_resolve_pending > /dev/null 2>&1
FAKE_DNSX_NX="s1.example.com s2.example.com s3.example.com" \
    canonical_dns_label_nxdomain > /dev/null 2>&1
t "settling labels all three nxdomain" "3" \
  "$(awk -F'\t' '$1 ~ /^s[123]\.example\.com$/ && $7=="nxdomain"{c++} END{print c+0}' "$CANONICAL_DNS_TSV")"

: > "${W2}/queried.log"
export METHO_DNS_WORKING=1
FAKE_DNSX_LOG="${W2}/queried.log" canonical_dns_resolve_pending include_timeouts > /dev/null 2>&1
t "retry pass does not re-query settled names" "0" \
  "$(grep -cE '^s[123]\.example\.com$' "${W2}/queried.log" 2>/dev/null || true)"

printf 't1.example.com\n' > "${W2}/in8.txt"
canonical_dns_add_sources "test" "${W2}/in8.txt" "example.com" > /dev/null
FAKE_DNSX_A="" canonical_dns_resolve_pending > /dev/null 2>&1
: > "${W2}/queried2.log"
FAKE_DNSX_LOG="${W2}/queried2.log" canonical_dns_resolve_pending include_timeouts > /dev/null 2>&1
unset METHO_DNS_WORKING
t "retry pass still reaches genuinely unresolved names" "1" \
  "$(grep -cE '^t1\.example\.com$' "${W2}/queried2.log" 2>/dev/null || true)"

# ── _using_doh_transport: the RUNNING transport, not the requested one ──
# The trap this guards: _load_doh_resolvers falls back to the built-in UDP
# pool by repointing RESOLVERS_FILE while leaving DNS_MODE="doh". A gate that
# reads DNS_MODE reports "DoH" on a network where DoH has just failed, and
# httpx gets handed the unvetted ~12.7K static pool — the exact thing the
# DoH-only gate exists to prevent, on exactly the wrong networks.
_saved_mode="${DNS_MODE:-}"; _saved_res="${RESOLVERS_FILE:-}"
_saved_pid="${DOH_PROXY_PID:-}"; _saved_port="${DOH_PROXY_PORT:-}"

DNS_MODE=udp; DOH_PROXY_PID=""; DOH_PROXY_PORT=""
t "udp mode is not a DoH transport" "1" "$(_using_doh_transport; echo $?)"

DNS_MODE=doh; DOH_PROXY_PID=""; DOH_PROXY_PORT=""
t "doh requested but no proxy running is not DoH" "1" "$(_using_doh_transport; echo $?)"

sleep 30 & _fake_proxy=$!          # a live child stands in for the proxy
DOH_PROXY_PID="$_fake_proxy"; DOH_PROXY_PORT=9999
RESOLVERS_FILE="${OUTPUT_DIR}/doh_resolvers.txt"; : > "$RESOLVERS_FILE"
t "doh with a live proxy IS DoH" "0" "$(_using_doh_transport; echo $?)"

# The fallback: proxy gone, DNS_MODE still "doh", RESOLVERS_FILE swapped.
DOH_PROXY_PID=""; DOH_PROXY_PORT=""
RESOLVERS_FILE="${SCRIPT_DIR}/wordlists/resolvers.txt"
t "doh-mode fallback to the UDP pool is not DoH" "1" "$(_using_doh_transport; echo $?)"

# Proxy up, but its resolver file swapped out from under it.
DOH_PROXY_PID="$_fake_proxy"; DOH_PROXY_PORT=9999
t "a stale resolver file is not DoH" "1" "$(_using_doh_transport; echo $?)"
kill "$_fake_proxy" 2>/dev/null

DNS_MODE="$_saved_mode"; RESOLVERS_FILE="$_saved_res"
DOH_PROXY_PID="$_saved_pid"; DOH_PROXY_PORT="$_saved_port"

# ── Cymru ASN DNS fallback ──
# The fallback exists because the whois transport is a single point of failure
# that took down CDN exclusion entirely in the observed run. It has two traps
# worth pinning: Cymru answers with EVERY covering prefix (must keep one row
# per IP, or the ASN summaries double-count), and print must not add a second
# newline (which doubled the apparent record count).
printf '192.0.2.54\n' > "$W2/asn_ips.txt"
if FAKE_DNSX_TXT="54.2.0.192.origin.asn.cymru.com AS16509.asn.cymru.com" \
   _cymru_dns_lookup "$W2/asn_ips.txt" "$W2/asn_out.txt" 2>/dev/null; then
    t "ASN DNS fallback produces exactly one row per IP" "1" "$(_lines "$W2/asn_out.txt")"
    t "ASN DNS fallback keeps the most specific prefix"  "1" "$(grep -c '192.0.2.0/24' "$W2/asn_out.txt")"
    t "ASN DNS fallback resolves the AS name"            "1" "$(grep -c 'AMAZON-02' "$W2/asn_out.txt")"
else
    t "ASN DNS fallback runs" "ok" "failed"
fi

# ── _plain_ip_resolver_file must emit ONLY the path ──
# Its stdout is captured with $(...) by the caller, so a log line written
# inside it silently becomes part of the value. cloud_enum was handed a
# two-line -nsf argument and died with
#   Error: File '<path>\n[!] ...' not found.
RPL="$(mktemp)"; printf '127.0.0.1:5353\n' > "$RPL"
RESOLVERS_FILE_SAVE="${RESOLVERS_FILE:-}"
OUTPUT_DIR_SAVE="$OUTPUT_DIR"
RESOLVERS_FILE="$RPL"; OUTPUT_DIR="$W2"
PLAIN_OUT="$(_plain_ip_resolver_file)"
t "plain-ip getter emits exactly one line" "1" "$(printf '%s\n' "$PLAIN_OUT" | grep -c .)"
t "plain-ip getter emits a usable path"    "1" "$([[ -s "$PLAIN_OUT" ]] && echo 1 || echo 0)"
RESOLVERS_FILE="$RESOLVERS_FILE_SAVE"; OUTPUT_DIR="$OUTPUT_DIR_SAVE"

# ── Transport escalation ──
# A batch whose primary transport answers NOTHING must be retried through the
# fallback before results are recorded. The old code escalated only on an
# exactly-zero result set, so a partially-degraded transport wrote hosts off.
printf 'f1.example.com\nf2.example.com\nf3.example.com\n' > "$W2/in5.txt"
canonical_dns_add_sources "test" "$W2/in5.txt" "example.com" > /dev/null
FAKE_DNSX_FAIL_RSLVR="/opt/scripts/wordlists/resolvers.txt" \
FAKE_DNSX_A="f1.example.com f2.example.com f3.example.com" \
FAKE_DNSX_NX="" canonical_dns_resolve_pending > /dev/null 2>&1
t "escalation recovers hosts the primary transport lost" "resolved" "$(awk -F'\t' '$1=="f1.example.com"{print $7}' "$CANONICAL_DNS_TSV")"
t "escalation loses no rows" "1" "$(awk -F'\t' '$1=="f3.example.com"{print $7}' "$CANONICAL_DNS_TSV" | grep -c resolved)"

# ── "resolved" means the host has an ADDRESS ─────────────────────────────────
# A bare CNAME used to be recorded as "resolved" with an empty address column:
# 1,678 rows — 13.7% of everything handed to httpx — on a real run, of which a
# 40-name independent sample found ~80% NXDOMAIN elsewhere and ~18% pointing at
# a CNAME target that no longer resolves. Neither is "resolved", and neither
# belongs in the probe set (one cannot answer; the other is a takeover
# candidate that belongs in a report).
_cds() { awk -F'\t' -v h="$1" '$1==h{print $7}' "$CANONICAL_DNS_TSV"; }
printf 'r-addr.example.com\nr-cname.example.com\nr-dead.example.com\n' > "$W2/in-rc.txt"
canonical_dns_add_sources "test" "$W2/in-rc.txt" "example.com" > /dev/null
FAKE_DNSX_ADDR="r-addr.example.com=93.184.216.34" \
FAKE_DNSX_CNAME="r-cname.example.com=gone.eu-central-1.elb.amazonaws.com" \
FAKE_DNSX_NX="r-dead.example.com" \
    canonical_dns_resolve_pending > /dev/null 2>&1

t "host with an address is resolved"          "resolved"    "$(_cds r-addr.example.com)"
t "bare CNAME is cname_only, not resolved"    "cname_only"  "$(_cds r-cname.example.com)"
t "bare CNAME keeps its target recorded"      "gone.eu-central-1.elb.amazonaws.com" \
  "$(awk -F'\t' '$1=="r-cname.example.com"{print $6}' "$CANONICAL_DNS_TSV")"
t "cname_only is excluded from the probe set" "0" \
  "$(canonical_dns_extract_resolved | awk '$0=="r-cname.example.com"{c++} END{print c+0}')"
t "no records at all still means timeout"     "timeout"     "$(_cds r-dead.example.com)"

# A row whose only address was stripped as reserved is a private-address record
# even when it also carries a CNAME. The old guard also required an empty CNAME
# column, so such a host stayed "resolved" with no address and got probed.
printf 'r-privcname.example.com\n' > "$W2/in-rp.txt"
canonical_dns_add_sources "test" "$W2/in-rp.txt" "example.com" > /dev/null
FAKE_DNSX_ADDR="r-privcname.example.com=10.64.32.141" \
FAKE_DNSX_CNAME="r-privcname.example.com=internal-lb.eu-central-1.elb.amazonaws.com" \
    canonical_dns_resolve_pending > /dev/null 2>&1
t "private address + CNAME becomes bogon" "bogon" "$(_cds r-privcname.example.com)"

# The reserved-address audit log is reset once per DATASET, not once per pass.
# It used to be truncated at the start of every resolve pass, so it only held
# the last pass's strips: a real run's global file listed 11 hosts against 514
# bogon rows, i.e. the audit trail did not exist for anything stripped in an
# earlier pass. One pass cannot show that — a SECOND pass must not erase the
# first pass's record.
t "bogon audit log records the strip" "1" \
  "$(awk -F'\t' '$1=="r-privcname.example.com" && $2=="10.64.32.141"{c++} END{print c+0}' "${CANONICAL_DNS_TSV}.bogon")"
printf 'r-priv2.example.com\n' > "$W2/in-rp2.txt"
canonical_dns_add_sources "test" "$W2/in-rp2.txt" "example.com" > /dev/null
FAKE_DNSX_ADDR="r-priv2.example.com=10.1.2.3" \
    canonical_dns_resolve_pending > /dev/null 2>&1
t "a later pass does not erase earlier strips" "1" \
  "$(awk -F'\t' '$1=="r-privcname.example.com" && $2=="10.64.32.141"{c++} END{print c+0}' "${CANONICAL_DNS_TSV}.bogon")"
t "the later pass's own strip is recorded too" "1" \
  "$(awk -F'\t' '$1=="r-priv2.example.com" && $2=="10.1.2.3"{c++} END{print c+0}' "${CANONICAL_DNS_TSV}.bogon")"

# ── status ranking across per-domain datasets ───────────────────────────────
# cname_only must rank below resolved: otherwise a dataset that only ever saw a
# CNAME would overwrite another's real address.
MW="$(mktemp -d)"; mkdir -p "$MW/phase1/a.test" "$MW/phase1/b.test"
printf 'hostname\troot_domain\tdiscovery_sources\tA\tAAAA\tCNAME\tresolution_status\n' > "$MW/phase1/a.test/canonical_dns.tsv"
printf 'm.example.com\ta.test\tsubfaster\t\t\talias.amazonaws.com\tcname_only\n' >> "$MW/phase1/a.test/canonical_dns.tsv"
printf 'hostname\troot_domain\tdiscovery_sources\tA\tAAAA\tCNAME\tresolution_status\n' > "$MW/phase1/b.test/canonical_dns.tsv"
printf 'm.example.com\tb.test\tcrt.name\t93.184.216.34\t\t\tresolved\n' >> "$MW/phase1/b.test/canonical_dns.tsv"
_od_save="$OUTPUT_DIR"
OUTPUT_DIR="$MW"; merge_per_domain_dns > /dev/null 2>&1
t "resolved outranks cname_only across datasets" "resolved" \
  "$(awk -F'\t' '$1=="m.example.com"{print $7}' "$MW/canonical_dns.tsv")"
OUTPUT_DIR="$_od_save"

# ── Stage budgets and crawl caps ─────────────────────────────────────────────
t "zero stage budget means no deadline"   "0" "$(_stage_deadline 0)"
t "empty stage budget means no deadline"  "0" "$(_stage_deadline '')"
t "positive stage budget is in the future" "1" \
  "$([[ "$(_stage_deadline 60)" -gt "$(date +%s)" ]] && echo 1 || echo 0)"

# _cap_crawl_hosts' stdout is captured as "<kept> <total>", so its warning must
# go to stderr — a log line on stdout silently becomes part of the value.
CAPIN="$W2/cap_in.txt"; CAPOUT="$W2/cap_out.txt"
printf 'h1\nh2\nh3\nh4\nh5\n' > "$CAPIN"
CAPC="$(_cap_crawl_hosts "$CAPIN" 3 "$CAPOUT" test 2>/dev/null)"
t "crawl cap keeps the configured number" "3" "$(wc -l < "$CAPOUT" | tr -d ' ')"
t "crawl cap reports kept and total only" "3 5" "$CAPC"
CAPC="$(_cap_crawl_hosts "$CAPIN" 0 "$CAPOUT" test 2>/dev/null)"
t "crawl cap of 0 means unlimited"        "5" "$(wc -l < "$CAPOUT" | tr -d ' ')"
t "unlimited crawl cap reports kept == total" "5 5" "$CAPC"

# A stage budget must stop launching, leave the truncation flag, and record the
# truncation at RUN level — a shell variable does not survive the crawl stages'
# background subshells, so without the file an incomplete run reports success.
_bp_noop() { sleep "${BP_SLEEP:-0}"; }
BPW="$(mktemp -d)"; printf 'a\nb\nc\nd\n' > "$BPW/in.txt"
_od_save2="$OUTPUT_DIR"; OUTPUT_DIR="$BPW"
METHO_STAGE_LABEL="test-stage" METHO_STAGE_DEADLINE="$(( $(date +%s) ))" \
    bounded_parallel 1 "$BPW/in.txt" _bp_noop > /dev/null 2>&1
t "spent stage budget sets the truncation flag" "1" "$METHO_STAGE_TRUNCATED"
t "spent stage budget launches nothing"         "1" "$(_count_in "$BPW/stage_truncations.txt" 'test-stage.*0/4')"
t "truncation is recorded with the run, not a variable" "1" "$(_count_in "$BPW/stage_truncations.txt" '.')"

METHO_STAGE_LABEL="ok-stage" METHO_STAGE_DEADLINE=0 \
    bounded_parallel 2 "$BPW/in.txt" _bp_noop > /dev/null 2>&1
t "an unbudgeted stage reports no truncation" "0" "$METHO_STAGE_TRUNCATED"
t "an unbudgeted stage adds no record"        "0" "$(_count_in "$BPW/stage_truncations.txt" 'ok-stage')"
OUTPUT_DIR="$_od_save2"

# ── Probe ledger ─────────────────────────────────────────────────────────────
# The ledger holds every host handed to httpx, responders AND silent hosts.
# Phase 3's "already probed" test used to be httpx_metadata.tsv, which contains
# responders only — so on a real run 7,905 probed-and-silent hosts looked
# unprobed and were probed again (~64% of a 47-minute round, for nothing).
LW="$(mktemp -d)"
_led_save="${METHO_HTTPX_LEDGER:-}"
METHO_HTTPX_LEDGER="$LW/ledger.txt"
printf 'a.example.com\nb.example.com\n' > "$LW/in.txt"
httpx_ledger_record "$LW/in.txt"
httpx_ledger_record "$LW/in.txt"
t "ledger read is deduped"              "2" "$(httpx_ledger_read | wc -l | tr -d '[:space:]')"
t "ledger keeps the silent host"        "1" "$(httpx_ledger_read | awk '$0=="b.example.com"{c++} END{print c+0}')"
t "missing ledger reads as empty"       "0" "$(METHO_HTTPX_LEDGER="$LW/none.txt" httpx_ledger_read | wc -l | tr -d '[:space:]')"

# The late pass must skip a host that was probed and stayed silent, and must
# still reach one that was never probed.
PW="$(mktemp -d)"; mkdir -p "$PW/phase3"
printf 'hostname\troot_domain\tdiscovery_sources\tA\tAAAA\tCNAME\tresolution_status\n' > "$PW/dns.tsv"
printf 'silent.example.com\texample.com\tsubfaster\t93.184.216.34\t\t\tresolved\n' >> "$PW/dns.tsv"
printf 'fresh.example.com\texample.com\tsubfaster\t93.184.216.35\t\t\tresolved\n' >> "$PW/dns.tsv"
printf 'silent.example.com\n' > "$PW/ledger.txt"
_od_save3="$OUTPUT_DIR"; _cds_save="$CANONICAL_DNS_TSV"; _mts_save="${HTTPX_META_TSV:-}"
OUTPUT_DIR="$PW"; CANONICAL_DNS_TSV="$PW/dns.tsv"; HTTPX_META_TSV="$PW/absent.tsv"
METHO_HTTPX_LEDGER="$PW/ledger.txt"
_probe_late_resolved_hosts > /dev/null 2>&1
# Asserted through the ledger, which is append-only: a host the late pass
# actually probed appears once more. (The .late_probe.txt candidate file is
# removed by the function on the way out, so it cannot be inspected afterwards.)
t "late pass probes a host that was never probed" "1" \
  "$(_count_in "$PW/ledger.txt" '^fresh\.example\.com$')"
t "late pass does not re-probe a probed-and-silent host" "1" \
  "$(_count_in "$PW/ledger.txt" '^silent\.example\.com$')"
OUTPUT_DIR="$_od_save3"; CANONICAL_DNS_TSV="$_cds_save"; HTTPX_META_TSV="$_mts_save"
METHO_HTTPX_LEDGER="$_led_save"

# ── Phase 3 IP extraction keeps BOTH address families ───────────────────────
# The AAAA column was written by the DNS layer and read by nothing at all: an
# IPv6-only host could be `resolved`, be probed by httpx, and still be missing
# from the IP inventory, the ASN lookup and the classification — silently,
# because no stage complained. IPv6 is inventoried, not scanned (naabu has no
# IPv6 support), so the two families must stay in separate files.
IPW="$(mktemp -d)"
printf 'hostname\troot_domain\tdiscovery_sources\tA\tAAAA\tCNAME\tresolution_status\n' > "$IPW/dns.tsv"
printf 'v4only.example.com\texample.com\tsubfaster\t93.184.216.34\t\t\tresolved\n'   >> "$IPW/dns.tsv"
printf 'v6only.example.com\texample.com\tsubfaster\t\t2a05:d014:9ed::1\t\tresolved\n' >> "$IPW/dns.tsv"
printf 'both.example.com\texample.com\tsubfaster\t93.184.216.35\t2a05:d014:9ed::2\t\tresolved\n' >> "$IPW/dns.tsv"
printf 'dead.example.com\texample.com\tsubfaster\t\t\t\tbogon\n'                     >> "$IPW/dns.tsv"
IP_COUNT="$(_build_ip_maps "$IPW/dns.tsv" "$IPW")"
t "ip map counts only rows with an address" "2" "$IP_COUNT"
t "IPv6-only host is inventoried"           "1" "$(_count_in "$IPW/domain_ip_map_v6.txt" '^v6only\.example\.com ')"
t "dual-stack host appears in both maps"    "1" "$(_count_in "$IPW/domain_ip_map_v6.txt" '^both\.example\.com ')"
t "IPv6 map excludes non-resolved hosts"    "0" "$(_count_in "$IPW/domain_ip_map_v6.txt" '^dead\.example\.com ')"
t "IPv4 map carries no IPv6 addresses"      "0" "$(_count_in "$IPW/domain_ip_map.txt" ':')"
t "IPv6-only host is absent from the scan inventory" "0" "$(_count_in "$IPW/all_ips.txt" ':')"

# ── Naabu sweep sizing ──────────────────────────────────────────────────────
# naabu's cost is linear in the candidate count, so a single capped run drops
# whatever does not fit. Real numbers from a live run: 6,501 candidates at the
# defaults need 13,302s against a 3,600s cap, and the old code scanned roughly a
# quarter of them while reporting a finished scan.
t "chunk size fits the cap"            "1650" "$(_naabu_chunk_hosts 3600 300 2)"
t "chunk size is never below one"      "1"    "$(_naabu_chunk_hosts 100 300 2)"
t "chunk size survives a zero per-host" "3300" "$(_naabu_chunk_hosts 3600 300 0)"
t "small target keeps its tight cap"   "700"  "$(_scaled_scan_cap 200 300 2 3600)"
t "full chunk is bounded by the cap"   "3600" "$(_scaled_scan_cap 1650 300 2 3600)"
t "oversized chunk is bounded too"     "3600" "$(_scaled_scan_cap 5000 300 2 3600)"
t "a zero-host chunk still gets a cap" "300"  "$(_scaled_scan_cap 0 300 2 3600)"
# 6,501 candidates must be fully covered by whole chunks within the default
# sweep budget, which is the property the old single run could not satisfy.
_CH="$( _naabu_chunk_hosts 3600 300 2 )"
_CHUNKS=$(( (6501 + _CH - 1) / _CH ))
t "6,501 candidates split into 4 chunks"      "4"     "$_CHUNKS"
t "chunks cover every candidate"              "1"     "$([[ $(( _CHUNKS * _CH )) -ge 6501 ]] && echo 1 || echo 0)"
t "projected sweep exceeds one cap but fits the budget" "1" \
  "$([[ $(( 300 + 6501 * 2 )) -gt 3600 && $(( 300 + 6501 * 2 )) -le $(( 3600 * 4 )) ]] && echo 1 || echo 0)"

# ── Run state must not survive into a reused output directory ───────────────
# Reuse is expected — setup_dirs already removes the DoH port file for exactly
# that reason. These three files are also per-RUN state, and each one is
# dangerous if it lingers:
#   stage_truncations.txt  a stale one makes a clean run report INCOMPLETE
#   httpx_probed.txt       stale entries make Phase 3 skip hosts this run never
#                          probed — silent coverage loss
#   httpx_metadata.tsv     merged into rather than replaced, so hosts that no
#                          longer answer stay in the dataset
SW="$(mktemp -d)"
_od_save4="$OUTPUT_DIR"; OUTPUT_DIR="$SW"
printf 'x\n' > "$SW/stage_truncations.txt"
printf 'host.example.com\n' > "$SW/httpx_probed.txt"
printf 'hostname\nhost.example.com\n' > "$SW/httpx_metadata.tsv"
setup_dirs > /dev/null 2>&1
t "setup_dirs clears a stale truncation record" "0" "$([[ -e "$SW/stage_truncations.txt" ]] && echo 1 || echo 0)"
t "setup_dirs clears a stale probe ledger"      "0" "$([[ -e "$SW/httpx_probed.txt" ]] && echo 1 || echo 0)"
t "setup_dirs clears stale httpx metadata"      "0" "$([[ -e "$SW/httpx_metadata.tsv" ]] && echo 1 || echo 0)"
OUTPUT_DIR="$_od_save4"

# ── The stage budget must stop the WORK, not just the loop ──────────────────
# The per-host workers run their tool through `timeout`, so the actual crawl is
# a GRANDCHILD. Killing only the wrapper subshell leaves it running — burning
# CPU, network and the target's rate budget into the following stages for up to
# its own per-host cap. The first check documents why the second exists.
# The worker shape matters: bounded_parallel forks a subshell that runs a shell
# FUNCTION, and the function then runs its tool. A subshell whose body is a
# single external command is exec'd instead, collapsing the chain and hiding the
# very gap being tested — so use a function here, as the pipeline does.
KT_PLAIN="$(bash -c '
    _kt_wrapper() { timeout 33 sleep 33; }
    _kt_wrapper & w=$!
    sleep 0.5
    g=$(pgrep -P "$w" 2>/dev/null | head -1)
    kill -TERM "$w" 2>/dev/null
    sleep 0.5
    if kill -0 "$g" 2>/dev/null; then echo ALIVE; else echo DEAD; fi
    pkill -f "sleep 33" 2>/dev/null
' 2>/dev/null | head -1)"
t "a plain kill leaves the worker's tool running" "ALIVE" "${KT_PLAIN:-}"

# _metho_kill_tree walks the process tree with pgrep, so it is only meaningful
# where procps exists — and the runtime image now installs it for exactly that
# reason. Guarded rather than assumed: on a minimal host without procps the walk
# degrades to the old "kill the wrapper only" behaviour, and asserting DEAD there
# would report a code defect that is really a missing dependency.
if command -v pgrep &>/dev/null; then
    KT_TREE="$(bash -c '
        source "'"${SCRIPT_DIR}"'/lib/utils.sh" 2>/dev/null
        _kt_wrapper() { timeout 33 sleep 33; }
        _kt_wrapper & w=$!
        sleep 0.5
        g=$(pgrep -P "$w" 2>/dev/null | head -1)
        _metho_kill_tree "$w"
        sleep 0.5
        if kill -0 "$g" 2>/dev/null; then echo ALIVE; else echo DEAD; fi
        pkill -f "sleep 33" 2>/dev/null
    ' 2>/dev/null | head -1)"
    t "_metho_kill_tree also stops the worker's tool" "DEAD" "${KT_TREE:-}"
else
    echo "SKIP: _metho_kill_tree test needs pgrep (procps) — not installed here"
fi

# ── Merges are scoped to THIS run's root domains ────────────────────────────
# phase1/*/ also matches directories left by earlier runs in a reused output
# directory. Merging those imports hostnames nobody asked for this time, and —
# for the probe ledger — lets a host this run resolved but never probed be
# skipped by Phase 3 because a previous run probed it.
RDW="$(mktemp -d)"; mkdir -p "$RDW/phase1/keep.test" "$RDW/phase1/stale.test"
printf 'keep.test\n' > "$RDW/root_domains.txt"
_od_save5="$OUTPUT_DIR"; OUTPUT_DIR="$RDW"
t "run-scoped dirs keep this run's root"  "1" "$(_root_domain_dirs | grep -c 'keep\.test' || true)"
t "run-scoped dirs drop a previous run's" "0" "$(_root_domain_dirs | grep -c 'stale\.test' || true)"
: > "$RDW/root_domains.txt"
t "no root list falls back to every directory" "2" "$(_root_domain_dirs | grep -c . || true)"
OUTPUT_DIR="$_od_save5"

# ── timeout(1)'s exit status is how a cap kill is told apart ────────────────
# Recording on "non-zero" would cry wolf on the routine failures (a passive
# source with no token, an empty grep); recording on 124 records only the case
# where coverage below the stage became a lower bound.
t "124 is a cap kill"          "1" "$(_was_capped 124 && echo 1 || echo 0)"
t "1 is an ordinary failure"   "0" "$(_was_capped 1 && echo 1 || echo 0)"
t "0 is success"               "0" "$(_was_capped 0 && echo 1 || echo 0)"
t "empty is not a cap kill"    "0" "$(_was_capped '' && echo 1 || echo 0)"

# ── nmap -sV default cap: a small target must not starve ────────────────────
# Regression for the 2026-09-29 ravro.ir/arvancloud.ir run: just 7 non-CDN
# hosts in 4 port-set groups (hardly a large target) hit the OLD default
# formula's 270s cap (60 + 7*30) after only 2/4 groups, losing -sV on 5 hosts.
# -sV's per-host cost is not naabu's SYN-only cost, so the floor here pins the
# per-host rate actually has headroom now, not just the ceiling.
t "nmap per-host rate has real headroom for -sV, not naabu's SYN-scan rate" "1" \
    "$([[ "${NMAP_SECONDS_PER_HOST}" -ge 90 ]] && echo 1 || echo 0)"
t "the 7-host run that used to get capped at 270s now gets well over 600s" "1" \
    "$([[ "$(_scaled_scan_cap 7 "$NMAP_TIMEOUT_BASE" "$NMAP_SECONDS_PER_HOST" "$NMAP_TIMEOUT_MAX")" -gt 600 ]] && echo 1 || echo 0)"

# ── nmap -sV port union: support floor ──────────────────────────────────────
# The union is global, so a port seen on one odd host is probed across the whole
# estate. On a live run 226 of 247 ports appeared on exactly 2 hosts — all GCP
# front-end artefacts — and they filled the union end to end.
# ── _nmap_portset_groups: scan each host on ITS OWN naabu ports ──────────────
# Regression for the union that re-scanned every host on all discovered ports,
# making naabu's per-host narrowing pointless. Hosts with the same open-port set
# share one group; ports are numerically sorted; NMAP_TOP_PORTS caps per host.
NPG="$(mktemp)"
{
  echo "10.0.0.1:443"; echo "10.0.0.1:80"     # host 1: {80,443}
  echo "10.0.0.2:80"; echo "10.0.0.2:443"     # host 2: {80,443}  (same set as host 1)
  echo "10.0.0.3:53"                          # host 3: {53}
} > "$NPG"
t "hosts with the same port-set share one group" "80,443	10.0.0.1 10.0.0.2" "$(_nmap_portset_groups "$NPG" 0 | grep '^80,443')"
t "a distinct port-set is its own group"         "53	10.0.0.3"            "$(_nmap_portset_groups "$NPG" 0 | grep '^53')"
t "ports are numerically sorted, not lexical"    "1" "$([[ $(_nmap_portset_groups "$NPG" 0 | grep -c '^80,443') -eq 1 ]] && echo 1 || echo 0)"
t "empty naabu file yields no groups"            ""  "$(_nmap_portset_groups "$NPG.nonexistent" 0)"
# Per-host cap keeps the lowest-numbered ports (well-known first).
NPG2="$(mktemp)"
printf '10.0.0.9:443\n10.0.0.9:22\n10.0.0.9:8080\n' > "$NPG2"
t "per-host cap keeps the lowest-numbered ports" "22,443	10.0.0.9" "$(_nmap_portset_groups "$NPG2" 2)"
t "no cap keeps every port for the host"         "22,443,8080	10.0.0.9" "$(_nmap_portset_groups "$NPG2" 0)"
rm -f "$NPG" "$NPG2"

# ── Every documented knob must be reachable from the environment ────────────
# A plain `VAR=default` assignment ignores the environment, so a knob documented
# as tunable — and in several cases advertised IN A WARNING as the thing to raise
# — can only be changed by editing the file. Eight were in that state:
# CRAWL_STAGE_TIMEOUT and HTTPX_THREADS_MAX both had log messages telling the
# operator to raise them, which was impossible. This guards the class.
for _kv in CRAWL_STAGE_TIMEOUT=999 HTTPX_THREADS_MAX=999 WAYMORE_TIMEOUT=999 \
           CLOUD_ENUM_TIMEOUT=999 DNSGEN_MAX_INPUT=999 DNSGEN_SKIP_THRESHOLD=999 \
           DNSGEN_MAX_OUTPUT_BYTES=999 NAABU_RATE=999 NAABU_RETRIES=999 \
           NAABU_TIMEOUT=999 NAABU_TOP_PORTS=999 NAABU_TIMEOUT_MAX=999 \
           NAABU_SECONDS_PER_HOST=999 NAABU_TOTAL_TIMEOUT_MAX=999 \
           NMAP_TIMEOUT_MAX=999 NMAP_INCLUDE_CLOUD=1 ; do
    _k="${_kv%%=*}"; _v="${_kv#*=}"
    _got="$(env "$_k=$_v" bash -c "source '${SCRIPT_DIR}/lib/utils.sh' >/dev/null 2>&1; printf '%s' \"\${${_k}}\"")"
    t "knob ${_k} is settable from the environment" "$_v" "$_got"
done

# ── DNS transport health: ONE definition ────────────────────────────────────
# The flag answers "did the transport answer at all?", which is a different
# question from "did many names resolve". The merge used to re-derive it from a
# >=2% resolution rate, so the same flag meant one thing during Phase 1 and
# another in Phase 3 — and the Phase 3 retry was governed by the weaker one.
# These two cases are the ones where the two definitions DISAGREE.
HW="$(mktemp -d)"; mkdir -p "$HW/phase1/h.test"
printf 'h.test\n' > "$HW/root_domains.txt"
printf 'hostname\troot_domain\tdiscovery_sources\tA\tAAAA\tCNAME\tresolution_status\n' > "$HW/phase1/h.test/canonical_dns.tsv"
for i in $(seq 1 100); do
    if (( i == 1 )); then
        printf 'r%d.h.test\th.test\tsubfaster\t1.2.3.4\t\t\tresolved\n' "$i"
    else
        printf 'r%d.h.test\th.test\tsubfaster\t\t\t\tnxdomain\n' "$i"
    fi
done >> "$HW/phase1/h.test/canonical_dns.tsv"

_od_save6="$OUTPUT_DIR"; _mdw_save="${METHO_DNS_WORKING:-}"
# 1% resolved (below the old threshold) but the transport was observed healthy.
printf '1\n' > "$HW/phase1/h.test/canonical_dns.tsv.dns_health"
OUTPUT_DIR="$HW"; METHO_DNS_WORKING=0
merge_per_domain_dns > /dev/null 2>&1
t "healthy transport on a 1%-resolved corpus keeps retries ON" "1" "$METHO_DNS_WORKING"

# 100% resolved but the transport was observed blackholed: the old rate
# heuristic said healthy here, and was wrong.
printf '0\n' > "$HW/phase1/h.test/canonical_dns.tsv.dns_health"
awk -F'\t' -v OFS='\t' 'NR>1{ $7="resolved"; $4="1.2.3.4" } { print }' \
    "$HW/phase1/h.test/canonical_dns.tsv" > "$HW/tmp.tsv" && mv "$HW/tmp.tsv" "$HW/phase1/h.test/canonical_dns.tsv"
OUTPUT_DIR="$HW"; METHO_DNS_WORKING=1
merge_per_domain_dns > /dev/null 2>&1
t "blackholed transport on a 100%-resolved corpus disables retries" "0" "$METHO_DNS_WORKING"
OUTPUT_DIR="$_od_save6"; METHO_DNS_WORKING="$_mdw_save"

# The observation is persisted next to the dataset it was made against, because
# a flag set inside a Phase 1 subshell does not survive it.
printf 'h2.example.com\n' > "$W2/in-h2.txt" 2>/dev/null || true
H2W="$(mktemp -d)"; OUTPUT_DIR="$H2W"; CANONICAL_DNS_TSV="$H2W/canonical_dns.tsv"
init_canonical_dns > /dev/null 2>&1
printf 'h2.example.com\n' > "$H2W/h2.txt"
canonical_dns_add_sources "test" "$H2W/h2.txt" "example.com" > /dev/null 2>&1
{ for i in $(seq 1 25); do echo "hb${i}.example.com"; done; } > "$H2W/hb.txt"
canonical_dns_add_sources "test" "$H2W/hb.txt" "example.com" > /dev/null 2>&1
FAKE_DNSX_A="$(tr '\n' ' ' < "$H2W/hb.txt")" FAKE_DNSX_NX="" \
    canonical_dns_resolve_pending > /dev/null 2>&1
t "a healthy batch persists its observation" "1" "$(cat "$H2W/canonical_dns.tsv.dns_health" 2>/dev/null | tr -d '[:space:]')"
{ for i in $(seq 1 25); do echo "hd${i}.example.com"; done; } > "$H2W/hd.txt"
canonical_dns_add_sources "test" "$H2W/hd.txt" "example.com" > /dev/null 2>&1
FAKE_DNSX_A="" FAKE_DNSX_NX="" FAKE_DNSX_FAIL=1 \
    canonical_dns_resolve_pending > /dev/null 2>&1
t "a blackholed batch persists that too" "0" "$(cat "$H2W/canonical_dns.tsv.dns_health" 2>/dev/null | tr -d '[:space:]')"
OUTPUT_DIR="$W2"; CANONICAL_DNS_TSV="${W2}/canonical_dns.tsv"

# ── cloud_enum stays on the DoH transport when the proxy offers a plain IP ──
# cloud_enum's dnspython accepts bare IPs only and always dials UDP/53, so in
# DoH mode it used to silently leave the DoH transport for the system resolver —
# a different DNS view from every other tool in the run, which is precisely the
# split-horizon divergence DoH exists to remove.
DPW="$(mktemp -d)"
_od_save7="$OUTPUT_DIR"; _rf_save="${RESOLVERS_FILE:-}"
OUTPUT_DIR="$DPW"; RESOLVERS_FILE="${DPW}/doh_resolvers.txt"
printf '127.0.0.1:55885\n' > "$RESOLVERS_FILE"
_dohpav() { _doh_plain_resolver_available && echo 1 || echo 0; }
t "no extra listener -> unavailable"        "0" "$(_dohpav)"
: > "${DPW}/.doh_extra_port"
t "an empty port file means none bound"     "0" "$(_dohpav)"
printf '53\n' > "${DPW}/.doh_extra_port"
t "a listener on 53 is usable"              "1" "$(_dohpav)"
PLAIN="$(_plain_ip_resolver_file 2>/dev/null)"
t "plain-IP list leads with the proxy"      "127.0.0.1" "$(head -1 "$PLAIN")"
t "plain-IP list still qualifies as bare IPs" "0" "$(_resolver_file_is_plain_ips "$PLAIN"; echo $?)"
printf '5353\n' > "${DPW}/.doh_extra_port"
t "a non-53 port is no use to cloud_enum"   "0" "$(_dohpav)"
OUTPUT_DIR="$_od_save7"; RESOLVERS_FILE="$_rf_save"

# ── HTTP probing may include bogon hosts; scanning never does ───────────────
# A `bogon` host is unreachable from the INTERNET, which is not the same as
# unreachable from the operator: on a network routed into the target's private
# or CGNAT space it answers normally, and two internal OpenSearch clusters were
# left out of the probe set that way with no way to bring them back.
#
# The split is deliberate. httpx re-resolves each name itself, so it needs no
# recorded address; naabu and nmap DO need it, and aiming a port scanner at
# private space is a far less defensible action than one HTTP request.
PBW="$(mktemp -d)"
printf 'hostname\troot_domain\tdiscovery_sources\tA\tAAAA\tCNAME\tresolution_status\n' > "$PBW/dns.tsv"
printf 'pub.example.com\texample.com\tsubfaster\t93.184.216.34\t\t\tresolved\n' >> "$PBW/dns.tsv"
printf 'priv.example.com\texample.com\tsubfaster\t\t\tinternal.elb.amazonaws.com\tbogon\n' >> "$PBW/dns.tsv"
_cds_save2="${CANONICAL_DNS_TSV:-}"
CANONICAL_DNS_TSV="$PBW/dns.tsv"
_pr_has() { canonical_dns_extract_probeable | grep -c -- "$1" || true; }
METHO_PROBE_RESERVED=0
t "bogon is not probed by default"          "0" "$(_pr_has '^priv\.example\.com$')"
t "resolved is always probed"               "1" "$(_pr_has '^pub\.example\.com$')"
METHO_PROBE_RESERVED=1
t "bogon IS probed with --probe-reserved"   "1" "$(_pr_has '^priv\.example\.com$')"
t "probe set stays complete and clean"      "2" "$(canonical_dns_extract_probeable | wc -l | tr -d '[:space:]')"
METHO_PROBE_RESERVED=0
# …and bogon hosts must stay out of the SCAN side whatever the flag says.
_build_ip_maps "$PBW/dns.tsv" "$PBW" > /dev/null 2>&1
t "bogon never enters the scan inventory"   "0" "$(grep -c 'priv\.example\.com' "$PBW/domain_ip_map.txt" 2>/dev/null || true)"
CANONICAL_DNS_TSV="$_cds_save2"

# ── httpx is bounded, and says so when the bound bites ──────────────────────
# httpx was the only long stage with NO wall-clock cap. Phase 1 bounds it
# indirectly through the per-domain watchdog, but Phase 3's late probe runs
# outside any watchdog — and that probe re-sends thousands of targets — so an
# unbounded round there could hang the entire run with no timeout and no trace.
SLOWSTUB="$(mktemp -d)"
cat > "$SLOWSTUB/httpx" <<'EOF'
#!/usr/bin/env bash
sleep 30
EOF
chmod +x "$SLOWSTUB/httpx"
HTW="$(mktemp -d)"; printf 'a.example.com\nb.example.com\n' > "$HTW/in.txt"
_od_save8="$OUTPUT_DIR"; _path_save="$PATH"
OUTPUT_DIR="$HTW"; PATH="$SLOWSTUB:$PATH"
_ht_start=$(date +%s)
HTTPX_TIMEOUT_BASE=1 HTTPX_SECONDS_PER_TARGET=0 HTTPX_TIMEOUT_MAX=2 \
    httpx_probe "$HTW/in.txt" "$HTW/out.json" > /dev/null 2>&1
_ht_elapsed=$(( $(date +%s) - _ht_start ))
PATH="$_path_save"; OUTPUT_DIR="$_od_save8"
t "an httpx round is cut off at its cap"  "1" "$([[ $_ht_elapsed -lt 15 ]] && echo 1 || echo 0)"
t "an httpx cap kill is recorded"         "1" "$(_count_in "$HTW/stage_truncations.txt" 'httpx')"

# ── nmap results: keep identified services, side-line tcpwrapped ────────────
# `tcpwrapped` = handshake completed, nothing answered any probe: a middlebox,
# not a service. 1,783 of 1,925 findings (93%) on a real run, and it buried the
# real identifications. Kept in its own file, never dropped.
#
# The verdict must be decided PER PORT: nmap puts every open port for a host on
# one line, and 47 real lines carried a genuine service beside wrapped ones.
# Judging the line threw those services away — `80 http//Amazon CloudFront httpd`
# sat on exactly such a line, so the fixture below covers that case.
NMW="$(mktemp -d)"
printf '# Nmap 7.95 scan\nHost: 10.0.0.1 ()\tStatus: Up\nHost: 10.0.0.1 ()\tPorts: 53/open/tcp//domain?///, 993/open/tcp//tcpwrapped///\tIgnored State: filtered (98)\nHost: 10.0.0.2 ()\tPorts: 443/open/tcp//ssl|https///\tIgnored State: filtered (99)\nHost: 10.0.0.3 ()\tPorts: 80/open/tcp//http//Amazon CloudFront httpd/, 993/open/tcp//tcpwrapped///\n' > "$NMW/scan.txt"
_nmap_split_ports "$NMW/scan.txt" "$NMW/ident" "$NMW/wrapped"
t "identified services are kept"          "3" "$(wc -l < "$NMW/ident" | tr -d '[:space:]')"
t "tcpwrapped handshakes are side-lined"  "2" "$(wc -l < "$NMW/wrapped" | tr -d '[:space:]')"
t "pairs carry no stray whitespace"       "0" "$(grep -c ' ' "$NMW/ident" || true)"
t "the real service on a MIXED line survives" "1" "$(_count_in "$NMW/ident" '^10\.0\.0\.3:80$')"
t "the wrapped port beside it does not"       "0" "$(_count_in "$NMW/ident" '^10\.0\.0\.3:993$')"
t "that wrapped port is recorded, not lost"   "1" "$(_count_in "$NMW/wrapped" '^10\.0\.0\.3:993$')"

# ── Tuning knobs validated at startup ────────────────────────────────────────
# Run in a subshell: validate_args calls exit 1 on bad input, which would take
# the whole suite down with it.
CLAMPED="$( ( DOMAINS="example.com"; HTTPX_THREADS=999; HTTPX_THREADS_MAX=200
             validate_args > /dev/null 2>&1; echo "$HTTPX_THREADS" ) )"
t "httpx threads above the ceiling are clamped" "200" "$CLAMPED"
KEPT="$( ( DOMAINS="example.com"; HTTPX_THREADS=120; HTTPX_THREADS_MAX=200
           validate_args > /dev/null 2>&1; echo "$HTTPX_THREADS" ) )"
t "httpx threads below the ceiling are honoured" "120" "$KEPT"
UNDERSIZED="$( ( DOMAINS="example.com"; DNS_MODE=doh; PARALLEL_DOMAINS=3
                  DNSX_THREADS="" DNSX_THREADS_DOH=64 DOH_PROXY_THREADS=128
                  validate_args 2>/dev/null ) | grep -c 'DoH proxy undersized' )"
t "an undersized DoH proxy is reported" "1" "$UNDERSIZED"

# ══════════════════════════════════════════════════════════════════════════════
# Audit-closure regressions
#
# Each of these pins a defect found auditing a real run (mydigipay.com +
# vodafone.com, 2026-09-27). They are grouped so a future reader can see which
# behaviour was wrong and why it is now asserted, rather than treating them as
# arbitrary invariants.
# ══════════════════════════════════════════════════════════════════════════════

# ── extract_domains: double-encoded percent fragments ─────────────────────────
# `%252F` decoded once leaves a literal `2F` glued to the next hostname, so a
# URL list produced 37 fictional hosts named 2Fapi.portal.vodafone.com etc. The
# fix expands %25 before stripping %XX; the trap is that a naive fix is to
# filter tokens starting with two hex digits, which would delete the real
# hosts 2fa.id.aws.cps.vodafone.com and 6u2fa.k8s.… found in the same run.
_pct_in="$(mktemp)"; _pct_out="$(mktemp)"
cat > "$_pct_in" <<'PCTEOF'
https://ciamsso.sit1.ciam.vodafone.com/x?cb=https%253A%252F%252Fapi.portal.vodafone.com%252Fsaml2
https://2fa.id.aws.cps.vodafone.com/a
https://6u2fa.k8s.eu-central-1.aws.cps.vodafone.com/b
https://plain.example.com/ok
PCTEOF
extract_domains "$_pct_in" "$_pct_out"
# The assertion is deliberately about the SPECIFIC fake, not about a `2F` prefix.
# Asserting "no host starts with 2f" would be wrong, and would have to be made
# pass by deleting the real 2fa.id.aws.cps.vodafone.com — which is the mistake
# this regression exists to prevent. `2f` is a legal start to a label.
t "double-encoded %252F does not invent 2Fapi.portal…" "0" \
    "$(_count_in "$_pct_out" '^2[Ff]api.portal.vodafone.com$')"
t "the real host behind %252F is recovered" "1" "$(_count_in "$_pct_out" '^api.portal.vodafone.com$')"
t "a real host beginning 2f survives" "1" "$(_count_in "$_pct_out" '^2fa.id.aws.cps.vodafone.com$')"
t "a real host containing 2fa survives" "1" "$(_count_in "$_pct_out" '^6u2fa.k8s.eu-central-1.aws.cps.vodafone.com$')"
t "an ordinary URL is unaffected" "1" "$(_count_in "$_pct_out" '^plain.example.com$')"

# ── _cloud_asset_normalize: one shape for three sources ───────────────────────
# dnsx emits bare hostnames, katana emits URLs, cloud_enum emitted JSON-quoted
# URLs. Unnormalized, results.sh stripped `"http://…"` down to `"http:`, failed
# the in-scope test, and silently dropped all 40 cloud_enum assets from every
# per-root file while leaving them in the aggregate.
_can_in="$(mktemp)"
cat > "$_can_in" <<'CANEOF'
"http://admin-vodafone.s3.amazonaws.com/"
https://bynder-static.s3.amazonaws.com
https://*.amazonaws.com
https://fonts.googleapis.com/icon?family=Material+Icons
UPPER.Case.Amazonaws.com
CANEOF
_can_out="$(_cloud_asset_normalize < "$_can_in")"
t "cloud: JSON quotes stripped" "1" "$(printf '%s\n' "$_can_out" | grep -cx 'admin-vodafone.s3.amazonaws.com')"
t "cloud: scheme stripped" "1" "$(printf '%s\n' "$_can_out" | grep -cx 'bynder-static.s3.amazonaws.com')"
t "cloud: path and query stripped" "1" "$(printf '%s\n' "$_can_out" | grep -cx 'fonts.googleapis.com')"
t "cloud: wildcard dropped, not de-starred" "0" "$(printf '%s\n' "$_can_out" | grep -cx 'amazonaws.com')"
t "cloud: target lowercased" "1" "$(printf '%s\n' "$_can_out" | grep -cx 'upper.case.amazonaws.com')"

# ── _gcs_bucket_to_vhost: GCP path-style buckets keep their name ─────────────
# cloud_enum reports GCP hits as storage.googleapis.com/<bucket> — the only
# source whose identifying part is a PATH, not the host. Piped straight into
# _cloud_asset_normalize (which strips everything after the first /), every
# GCP finding collapsed to the bare host "storage.googleapis.com": on the
# 2026-09-29 ravro.ir/arvancloud.ir run, 3,674 of 3,678 cloud_enum findings
# reduced to that one anonymous, unattributable line.
_gcs_in="$(mktemp)"
cat > "$_gcs_in" <<'GCSEOF'
http://storage.googleapis.com/ravro
http://storage.googleapis.com/ravro-0
http://storage.googleapis.com/www.example.com
http://storage.googleapis.com/bad_bucket_name
http://storage.googleapis.com/
https://bynder-static.s3.amazonaws.com
GCSEOF
_gcs_out="$(_gcs_bucket_to_vhost < "$_gcs_in" | _cloud_asset_normalize)"
t "gcs: bucket name becomes a vhost-style host" "1" \
    "$(printf '%s\n' "$_gcs_out" | grep -cx 'ravro.storage.googleapis.com')"
t "gcs: a hyphenated bucket name survives" "1" \
    "$(printf '%s\n' "$_gcs_out" | grep -cx 'ravro-0.storage.googleapis.com')"
t "gcs: a dotted (domain-verified) bucket name survives" "1" \
    "$(printf '%s\n' "$_gcs_out" | grep -cx 'www.example.com.storage.googleapis.com')"
# Both the illegal-bucket-name line and the bare-host (no path) line fall
# through unchanged to the same bare host, so it's counted twice here — sort -u
# downstream (as in the real pipeline) is what dedupes it to one.
t "gcs: illegal bucket name and no-path host both fall back to the bare host" "2" \
    "$(printf '%s\n' "$_gcs_out" | grep -cx 'storage.googleapis.com')"
t "gcs: a non-GCS source is passed through unchanged" "1" \
    "$(printf '%s\n' "$_gcs_out" | grep -cx 'bynder-static.s3.amazonaws.com')"

# End-to-end: the vhost-style rewrite must actually reach the per-root file via
# the real keyword-attribution path in results.sh (not just survive its own
# unit test) — this is the same regression shape as the CNAME dedup fix above.
_PRC2_SAVE_OUT="${OUTPUT_DIR:-}"; _PRC2_SAVE_ROOTS="${ROOT_DOMAINS_FILE:-}"
PRC2="$(mktemp -d)"; mkdir -p "$PRC2/phase2"
printf 'hostname\troot_domain\tdiscovery_sources\tA\tAAAA\tCNAME\tresolution_status\n' > "$PRC2/canonical_dns.tsv"
printf 'ravro.storage.googleapis.com\n' | _gcs_bucket_to_vhost > "$PRC2/phase2/final_cloud_assets.txt"
printf 'ravro.ir\n' > "$PRC2/.prc2_roots.txt"
OUTPUT_DIR="$PRC2"; ROOT_DOMAINS_FILE="$PRC2/.prc2_roots.txt"
generate_per_root_results >/dev/null 2>&1
_PRC2_OUT="$(cat "$PRC2/results/ravro.ir/cloud_assets.txt" 2>/dev/null)"
OUTPUT_DIR="$_PRC2_SAVE_OUT"; ROOT_DOMAINS_FILE="$_PRC2_SAVE_ROOTS"
t "gcs: vhost-style bucket reaches its root's cloud_assets.txt via keyword match" "1" \
    "$(printf '%s\n' "$_PRC2_OUT" | grep -cx 'ravro.storage.googleapis.com')"
rm -rf "$PRC2"

# ── per-root cloud_assets: CNAME-derived + cloud_enum keyword attribution ─────
# Regression for results/<root>/cloud_assets.txt = 1 while the aggregate had
# 1,157: (a) the CNAME re-tag deduped by ROOT only (sort -u -k1,1), collapsing a
# root's entire cloud-CNAME set to a single row; (b) cloud_enum keyword buckets
# (0-vodafone.awsapps.com) never attributed to their root. This runs the real
# generate_per_root_results on a tiny synthetic estate and checks both.
_PRC_SAVE_OUT="${OUTPUT_DIR:-}"; _PRC_SAVE_ROOTS="${ROOT_DOMAINS_FILE:-}"
PRC="$(mktemp -d)"; mkdir -p "$PRC/phase2"
printf 'hostname\troot_domain\tdiscovery_sources\tA\tAAAA\tCNAME\tresolution_status\n' > "$PRC/canonical_dns.tsv"
printf 'a.example.com\texample.com\tsubfaster\t\t\tfoo.elb.amazonaws.com\tcname_only\n' >> "$PRC/canonical_dns.tsv"
printf 'b.example.com\texample.com\tsubfaster\t\t\tbar.elb.amazonaws.com\tcname_only\n' >> "$PRC/canonical_dns.tsv"
printf 'example-prod.s3.amazonaws.com\n' > "$PRC/phase2/final_cloud_assets.txt"
printf 'example.com\n' > "$PRC/.prc_roots.txt"
OUTPUT_DIR="$PRC"; ROOT_DOMAINS_FILE="$PRC/.prc_roots.txt"
generate_per_root_results >/dev/null 2>&1
_PRC_OUT="$(sort -u "$PRC/results/example.com/cloud_assets.txt" 2>/dev/null)"
OUTPUT_DIR="$_PRC_SAVE_OUT"; ROOT_DOMAINS_FILE="$_PRC_SAVE_ROOTS"
t "per-root keeps BOTH cname-derived cloud targets (no -k1,1 collapse)" "2" "$(printf '%s\n' "$_PRC_OUT" | grep -cE 'foo\.elb\.amazonaws\.com|bar\.elb\.amazonaws\.com')"
t "per-root folds in a cloud_enum keyword bucket" "1" "$(printf '%s\n' "$_PRC_OUT" | grep -cx 'example-prod.s3.amazonaws.com')"
rm -rf "$PRC"

# ── _cap_crawl_hosts: the cap must rank, not take the alphabet ────────────────
# `head -n` over an alphabetically sorted live list spent a 300-host crawl budget
# on adm.*/adminauth.*: 208 canonical-redirect stubs and 11 real pages, against
# 577 hosts answering 200 in the corpus.
_ck_dir="$(mktemp -d)"
printf 'http://aaa.example.com\nhttp://bbb.example.com\nhttp://ccc.example.com\n' > "${_ck_dir}/in.txt"
{
    printf 'hostname\tcdn\ttechnologies\twebserver\tcontent_length\tstatus_code\ttitle\turl\n'
    printf 'aaa.example.com\t\thtml\tnginx\t100\t301\t-\thttp://aaa.example.com\n'
    printf 'bbb.example.com\t\thtml\tnginx\t900\t200\t-\thttp://bbb.example.com\n'
    printf 'ccc.example.com\t\thtml\tnginx\t500\t403\t-\thttp://ccc.example.com\n'
} > "${_ck_dir}/httpx_metadata.tsv"
_ck_counts="$(cd "$_ck_dir" && _cap_crawl_hosts in.txt 2 out.txt "Test" httpx_metadata.tsv)"
t "crawl cap returns kept and total" "2 3" "$_ck_counts"
t "crawl cap ranks 200 above 403 and 301" "bbb.example.com" \
    "$(head -1 "${_ck_dir}/out.txt" | sed 's|http://||')"
t "crawl cap ranks 403 above 301" "ccc.example.com" \
    "$(tail -1 "${_ck_dir}/out.txt" | sed 's|http://||')"
_ck_nometa="$(cd "$_ck_dir" && _cap_crawl_hosts in.txt 2 out2.txt "Test" nonexistent.tsv)"
t "crawl cap still caps without metadata" "2 3" "$_ck_nometa"
t "crawl cap falls back to input order" "aaa.example.com" \
    "$(head -1 "${_ck_dir}/out2.txt" | sed 's|http://||')"
t "no cap means no reordering" "3 3" \
    "$(cd "$_ck_dir" && _cap_crawl_hosts in.txt 0 out3.txt "Test" httpx_metadata.tsv)"
t "uncapped output preserves input order" "aaa.example.com" \
    "$(head -1 "${_ck_dir}/out3.txt" | sed 's|http://||')"

# ── _bogon_merge_global: the merged audit log must exist ──────────────────────
# The per-domain pass logs the ranges it strips; the merged pass used to have no
# such file, so it grepped a missing path and reported "No 198.18.0.0/15 present"
# over 1,067 hosts whose per-domain log contained 126 matching rows.
_bg_dir="$(mktemp -d)"
printf 'h1\t10.0.0.1\t10.0.0.0/8\n'                > "${_bg_dir}/d1.tsv.bogon"
printf 'h2\t198.18.0.5\t198.18.0.0/15 RFC2544\n'    > "${_bg_dir}/d2.tsv.bogon"
: > "${_bg_dir}/global.tsv"
_bogon_merge_global "${_bg_dir}/global.tsv" "${_bg_dir}/d1.tsv" "${_bg_dir}/d2.tsv"
t "bogon merge unions per-domain logs" "2" "$(_lines "${_bg_dir}/global.tsv.bogon")"
t "bogon merge keeps the 198.18 evidence" "1" "$(_count_in "${_bg_dir}/global.tsv.bogon" '198[.]18[.]')"
# A domain with no reserved records writes no log; that must not fabricate one.
# The file is still created (empty), which is how the verdict tells "no such
# range" apart from "we have no evidence at all".
: > "${_bg_dir}/global2.tsv"
_bogon_merge_global "${_bg_dir}/global2.tsv" "${_bg_dir}/missing.tsv"
t "bogon merge of nothing yields an empty file" "0" "$(_lines "${_bg_dir}/global2.tsv.bogon")"
t "bogon merge always creates the file" "1" "$([[ -e "${_bg_dir}/global2.tsv.bogon" ]] && echo 1 || echo 0)"

# ── _takeover_classify: verdicts ──────────────────────────────────────────────
# Separated from canonical_dns_takeover_check so the verdict logic is testable
# without making the suite resolve real DNS names.
_tk_dir="$(mktemp -d)"
printf 'alive.example.net\n'  > "${_tk_dir}/alive.txt"
printf 'dead.example.net\n'   > "${_tk_dir}/dead.txt"
cat > "${_tk_dir}/pairs.tsv" <<'TKEOF'
a.example.com	example.com	alive.example.net	crt.name
b.example.com	example.com	dead.example.net	waymore
c.example.com	example.com	unknown.example.org	katana
d.example.com	example.com	DEAD.EXAMPLE.NET	subfaster
e.example.com	example.com	https://alive.example.net/path	root
f.example.com	example.com		root
TKEOF
_tk_out="$(_takeover_classify "${_tk_dir}/pairs.tsv" "${_tk_dir}/alive.txt" "${_tk_dir}/dead.txt")"
t "takeover: resolving target is alive" "alive" \
    "$(printf '%s\n' "$_tk_out" | awk -F'\t' '$1 == "a.example.com" { print $4 }')"
t "takeover: NXDOMAIN target is dangling" "dangling" \
    "$(printf '%s\n' "$_tk_out" | awk -F'\t' '$1 == "b.example.com" { print $4 }')"
t "takeover: unanswerable target is unresolved" "unresolved" \
    "$(printf '%s\n' "$_tk_out" | awk -F'\t' '$1 == "c.example.com" { print $4 }')"
t "takeover: target case is normalized" "dangling" \
    "$(printf '%s\n' "$_tk_out" | awk -F'\t' '$1 == "d.example.com" { print $4 }')"
t "takeover: target printed lowercased" "dead.example.net" \
    "$(printf '%s\n' "$_tk_out" | awk -F'\t' '$1 == "d.example.com" { print $3 }')"
t "takeover: URL-shaped target is normalized" "alive" \
    "$(printf '%s\n' "$_tk_out" | awk -F'\t' '$1 == "e.example.com" { print $4 }')"
t "takeover: a pair with no target is dropped" "0" \
    "$(printf '%s\n' "$_tk_out" | grep -c '^f.example.com' || true)"

# ── setup_dirs: clear state that accumulates across runs ──────────────────────
# cloud_enum appends to cloud_enum_results.json and Phase 2 re-parses it in full
# whenever it is non-empty, so a re-run into a reused output directory inherited
# the previous run's buckets — and could report a full result set while this
# run's cloud_enum was killed having found nothing.
_sd_dir="$(mktemp -d)"
mkdir -p "${_sd_dir}/phase2"
printf '{"msg":"Protected S3 Bucket","target":"http://stale.s3.amazonaws.com/"}\n' \
    > "${_sd_dir}/phase2/cloud_enum_results.json"
( OUTPUT_DIR="$_sd_dir"; setup_dirs > /dev/null 2>&1 ) || true
t "setup_dirs clears stale cloud_enum findings" "0" \
    "$([[ -e "${_sd_dir}/phase2/cloud_enum_results.json" ]] && echo 1 || echo 0)"

# ── run_consolidation: final/ is scoped to this run's roots ───────────────────
# Every final/ glob was a bare `phase1/*`, so a stale phase1/<other-root>/ from a
# reused output directory imported a previous run's hosts into four deliverables
# even though the canonical merge had correctly excluded them.
_cs_dir="$(mktemp -d)"
mkdir -p "${_cs_dir}/phase1/this.example" "${_cs_dir}/phase1/stale.example" "${_cs_dir}/phase3" "${_cs_dir}/phase2"
printf 'this.example\n' > "${_cs_dir}/root_domains.txt"
printf 'http://a.this.example\n' > "${_cs_dir}/phase1/this.example/live_subdomains_final.txt"
printf 'http://a.stale.example\n' > "${_cs_dir}/phase1/stale.example/live_subdomains_final.txt"
printf 'http://a.this.example/old\n' > "${_cs_dir}/phase1/this.example/waymore_urls.txt"
printf 'http://a.stale.example/old\n' > "${_cs_dir}/phase1/stale.example/waymore_urls.txt"
mkdir -p "${_cs_dir}/phase1/this.example/katana" "${_cs_dir}/phase1/stale.example/katana"
printf 'http://a.this.example/page\n' > "${_cs_dir}/phase1/this.example/katana/discovered_urls.txt"
printf 'http://a.stale.example/page\n' > "${_cs_dir}/phase1/stale.example/katana/discovered_urls.txt"
printf 'http://a.this.example/app.js\n' > "${_cs_dir}/phase1/this.example/katana/javascript_assets.txt"
printf 'http://a.stale.example/app.js\n' > "${_cs_dir}/phase1/stale.example/katana/javascript_assets.txt"
printf 'hostname\troot_domain\tdiscovery_sources\tA\tAAAA\tCNAME\tresolution_status\n' > "${_cs_dir}/canonical_dns.tsv"
printf 'a.this.example\tthis.example\tptr-reverse\t1.2.3.4\t\t\tresolved\n' >> "${_cs_dir}/canonical_dns.tsv"
printf 'new.this.example\tthis.example\tdnsx-cloud\t\t\t\tcname_only\n'   >> "${_cs_dir}/canonical_dns.tsv"
( OUTPUT_DIR="$_cs_dir" METHO_TAKEOVER_CHECK=0 ROOT_DOMAINS_FILE="$_cs_dir/root_domains.txt" \
      run_consolidation > /dev/null 2>&1 ) || true
t "final/ excludes a stale phase1 root from live servers" "0" \
    "$(_count_in "${_cs_dir}/final/final_live_web_servers.txt" 'stale[.]example')"
t "final/ excludes a stale phase1 root from waymore URLs" "0" \
    "$(_count_in "${_cs_dir}/final/final_waymore_urls.txt" 'stale[.]example')"
t "final/ keeps this run's live servers" "1" \
    "$(_count_in "${_cs_dir}/final/final_live_web_servers.txt" 'this[.]example')"
# final_all_domains comes from canonical now, so a host only Phase 2 or Phase 3
# discovered is present — the raw Phase-1 inventory would have missed it.
t "final_all_domains includes a dnsx-cloud discovery" "1" \
    "$(_count_in "${_cs_dir}/final/final_all_domains.txt" '^new.this.example$')"
t "final_all_domains includes a ptr-reverse discovery" "1" \
    "$(_count_in "${_cs_dir}/final/final_all_domains.txt" '^a.this.example$')"

# ── run_consolidation: katana's crawl output is promoted into final/ ─────────
# phase1/<root>/katana/discovered_urls.txt and javascript_assets.txt were real,
# complete crawl data that nothing copied into final/ — absent from
# RECON_SUMMARY and from every other deliverable's home. Same fixture,
# same stale-root scoping rule as the two checks above.
t "final/ promotes this run's discovered URLs" "1" \
    "$(_count_in "${_cs_dir}/final/final_discovered_urls.txt" 'this[.]example')"
t "final/ promotes this run's JS assets" "1" \
    "$(_count_in "${_cs_dir}/final/final_javascript_assets.txt" 'this[.]example')"
t "final/ excludes a stale phase1 root from discovered URLs" "0" \
    "$(_count_in "${_cs_dir}/final/final_discovered_urls.txt" 'stale[.]example')"
t "final/ excludes a stale phase1 root from JS assets" "0" \
    "$(_count_in "${_cs_dir}/final/final_javascript_assets.txt" 'stale[.]example')"

echo ""
echo "RESULT: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]]
