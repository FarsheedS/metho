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

echo ""
echo "RESULT: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]]
