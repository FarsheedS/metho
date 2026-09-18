#!/usr/bin/env bash
# Unit tests for metho pure functions — run inside the container with lib/ mounted.
SCRIPT_DIR="/opt/scripts"
source "${SCRIPT_DIR}/lib/utils.sh"
source "${SCRIPT_DIR}/lib/canonical_dns.sh"
source "${SCRIPT_DIR}/lib/classify.sh"

PASS=0 FAIL=0
t() { # t <name> <expected> <actual>
    if [[ "$2" == "$3" ]]; then PASS=$((PASS+1)); echo "PASS: $1";
    else FAIL=$((FAIL+1)); echo "FAIL: $1 — expected [$2] got [$3]"; fi
}

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
source /opt/scripts/config/asn_providers.sh
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
DNS_MODE="doh"; DNSX_THREADS=""; t "doh dnsx threads default" "64"  "$(_dnsx_threads)"
DNS_MODE="doh"; DNSX_THREADS="7"; t "explicit dnsx threads wins" "7" "$(_dnsx_threads)"
DNS_MODE="$_DNS_MODE_SAVE2"; DNSX_THREADS="$_DNSX_T_SAVE"

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
#   FAKE_DNSX_NX   hostnames reported NXDOMAIN by the -rcode pass
#   FAKE_DNSX_FAIL 1 = every query errors (transport unreachable)
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
# A real resolver answers the probe name too — _probe_system_resolver uses it
# to decide whether a fallback transport is usable at all.
for h in ${FAKE_DNSX_A:-} whoami.akamai.net; do
    grep -qx -- "$h" <<<"$input" || continue
    printf '{"host":"%s","a":["93.184.216.34"]}\n' "$h"
done
exit 0
STUBEOF
chmod +x "${STUB}/dnsx"
export PATH="${STUB}:${PATH}"

W2="$(mktemp -d)"; OUTPUT_DIR="$W2"
CANONICAL_DNS_TSV="${W2}/canonical_dns.tsv"
HTTPX_META_TSV="${W2}/httpx_metadata.tsv"
ROOT_DOMAINS_FILE="$SCOPE"
init_canonical_dns > /dev/null
printf 'a.example.com\nb.example.com\n' > "${W2}/in.txt"
canonical_dns_add_sources "test" "${W2}/in.txt" "example.com" > /dev/null
t "new TSV starts with a header" "hostname" "$(head -1 "$CANONICAL_DNS_TSV" | cut -f1)"
t "new TSV has header + 2 rows" "3" "$(wc -l < "$CANONICAL_DNS_TSV")"

FAKE_DNSX_A="a.example.com" FAKE_DNSX_NX="" canonical_dns_resolve_pending > /dev/null 2>&1
t "header survives a resolve pass" "hostname" "$(head -1 "$CANONICAL_DNS_TSV" | cut -f1)"
t "resolve pass loses no row" "3" "$(wc -l < "$CANONICAL_DNS_TSV")"
t "resolved host recorded" "resolved" "$(awk -F'\t' '$1=="a.example.com"{print $7}' "$CANONICAL_DNS_TSV")"
t "unanswered host stays timeout" "timeout" "$(awk -F'\t' '$1=="b.example.com"{print $7}' "$CANONICAL_DNS_TSV")"

FAKE_DNSX_A="" FAKE_DNSX_NX="b.example.com" canonical_dns_label_nxdomain > /dev/null 2>&1
t "nxdomain pass labels a dead name" "nxdomain" "$(awk -F'\t' '$1=="b.example.com"{print $7}' "$CANONICAL_DNS_TSV")"
t "header survives the nxdomain pass" "hostname" "$(head -1 "$CANONICAL_DNS_TSV" | cut -f1)"
t "nxdomain pass loses no row" "3" "$(wc -l < "$CANONICAL_DNS_TSV")"
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

# ── Cymru ASN DNS fallback ──
# The fallback exists because the whois transport is a single point of failure
# that took down CDN exclusion entirely in the observed run. It has two traps
# worth pinning: Cymru answers with EVERY covering prefix (must keep one row
# per IP, or the ASN summaries double-count), and print must not add a second
# newline (which doubled the apparent record count).
printf '192.0.2.54\n' > "$W2/asn_ips.txt"
if FAKE_DNSX_TXT="54.2.0.192.origin.asn.cymru.com AS16509.asn.cymru.com" \
   _cymru_dns_lookup "$W2/asn_ips.txt" "$W2/asn_out.txt" 2>/dev/null; then
    t "ASN DNS fallback produces exactly one row per IP" "1" "$(wc -l < "$W2/asn_out.txt")"
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

echo ""
echo "RESULT: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]]
