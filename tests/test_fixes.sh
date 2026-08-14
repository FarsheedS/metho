#!/usr/bin/env bash
# Functional test for the Metho fixes (Fix 1, 2, 5, 3, 4).
# Sources the REAL lib/ and config/ files and exercises the changed logic
# without needing external recon tools (dnsx/httpx/nmap are stubbed/skipped).
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$SCRIPT_DIR/.."

# --- Source the real libraries ----------------------------------------------
source "$ROOT/lib/utils.sh"
source "$ROOT/lib/canonical_dns.sh"
source "$ROOT/lib/classify.sh"

# Stub log functions to keep output clean (override after sourcing).
log_info()    { printf '[*] %s\n' "$*"; }
log_success() { printf '[+] %s\n' "$*"; }
log_warn()    { printf '[!] %s\n' "$*"; }
log_error()   { printf '[-] %s\n' "$*"; }
log_skip()    { printf '[SKIP] %s\n' "$*"; }

PASS=0 FAIL=0
assert_eq() { # <desc> <actual> <expected>
    local desc="$1" actual="$2" expected="$3"
    if [[ "$actual" == "$expected" ]]; then
        printf '  [PASS] %s\n' "$desc"; ((PASS++)) || true
    else
        printf '  [FAIL] %s\n     expected: %q\n     actual:   %q\n' \
            "$desc" "$expected" "$actual"; ((FAIL++)) || true
    fi
}

# --- Shared test workspace ---------------------------------------------------
WORK="$(mktemp -d)"
OUTPUT_DIR="$WORK/output"
mkdir -p "$OUTPUT_DIR"
export OUTPUT_DIR

# Build a known root-domains file (includes a ccTLD case).
ROOT_DOMAINS_FILE="$WORK/root_domains.txt"
printf 'example.com\nexample.co.uk\nexample.com.au\n' | sort -u > "$ROOT_DOMAINS_FILE"
export ROOT_DOMAINS_FILE

init_canonical_dns

echo "=== Fix 1: seed every root domain with source=root ==="
# Simulate the start-of-Phase-1 seeding call.
canonical_dns_add_sources "root" "$ROOT_DOMAINS_FILE"

TSV="$OUTPUT_DIR/canonical_dns.tsv"
for rd in example.com example.co.uk example.com.au; do
    # present as a row
    present=$(awk -F'\t' -v h="$rd" '$1==h{print "yes"; exit}' "$TSV")
    assert_eq "root domain $rd seeded into dataset" "$present" "yes"
    # source is root
    src=$(awk -F'\t' -v h="$rd" '$1==h{print $3; exit}' "$TSV")
    assert_eq "root domain $rd source is root" "$src" "root"
    # pending so it goes through DNSX/HTTPX
    st=$(awk -F'\t' -v h="$rd" '$1==h{print $7; exit}' "$TSV")
    assert_eq "root domain $rd status is pending" "$st" "pending"
done

echo
echo "=== Fix 2: stop deriving root domain from hostname (ccTLDs) ==="
# A subdomain file for the co.uk root, added WITH the explicit root (phase1 path).
printf 'www.example.co.uk\napi.example.co.uk\ndeep.staging.example.co.uk\n' > "$WORK/subs_uk.txt"
canonical_dns_add_sources "subfaster" "$WORK/subs_uk.txt" "example.co.uk"
assert_eq "www.example.co.uk root_domain" \
    "$(awk -F'\t' -v h='www.example.co.uk' '$1==h{print $2; exit}' "$TSV")" "example.co.uk"
assert_eq "deep.staging.example.co.uk root_domain" \
    "$(awk -F'\t' -v h='deep.staging.example.co.uk' '$1==h{print $2; exit}' "$TSV")" "example.co.uk"

# A subdomain file for the com.au root, added WITHOUT explicit root (phase2 path)
# -> must match via suffix against known roots, NOT last-two-labels (com.au).
printf 'www.example.com.au\napi.example.com.au\n' > "$WORK/subs_au.txt"
canonical_dns_add_sources "dnsx-cloud" "$WORK/subs_au.txt"
assert_eq "www.example.com.au root_domain (suffix match)" \
    "$(awk -F'\t' -v h='www.example.com.au' '$1==h{print $2; exit}' "$TSV")" "example.com.au"
assert_eq "api.example.com.au root_domain (suffix match)" \
    "$(awk -F'\t' -v h='api.example.com.au' '$1==h{print $2; exit}' "$TSV")" "example.com.au"

# Out-of-scope cloud host (no known root): added, root_domain empty (not inferred).
printf 's3-bucket.s3.amazonaws.com\n' > "$WORK/cloud.txt"
canonical_dns_add_sources "cloud_enum" "$WORK/cloud.txt"
assert_eq "out-of-scope cloud host present" \
    "$(awk -F'\t' -v h='s3-bucket.s3.amazonaws.com' '$1==h{print "yes"; exit}' "$TSV")" "yes"
assert_eq "out-of-scope cloud host root_domain empty (not inferred)" \
    "$(awk -F'\t' -v h='s3-bucket.s3.amazonaws.com' '$1==h{print $2; exit}' "$TSV")" ""

echo
echo "=== Fix 5: source provenance preserved/merged (not overwritten) ==="
# api.example.com discovered by multiple sources across phases.
printf 'api.example.com\n' > "$WORK/s1.txt"
canonical_dns_add_sources "subfaster" "$WORK/s1.txt" "example.com"
printf 'api.example.com\n' > "$WORK/s2.txt"
canonical_dns_add_sources "crt.name" "$WORK/s2.txt" "example.com"
printf 'api.example.com\n' > "$WORK/s3.txt"
canonical_dns_add_sources "waymore" "$WORK/s3.txt" "example.com"
printf 'api.example.com\n' > "$WORK/s4.txt"
canonical_dns_add_sources "shuffledns" "$WORK/s4.txt" "example.com"
merged=$(awk -F'\t' -v h='api.example.com' '$1==h{print $3; exit}' "$TSV")
assert_eq "api.example.com merged sources" "$merged" "subfaster;crt.name;waymore;shuffledns"

# Root domain retains 'root' even when a tool also finds the apex later.
printf 'example.co.uk\n' > "$WORK/s5.txt"
canonical_dns_add_sources "crt.name" "$WORK/s5.txt" "example.co.uk"
rd_src=$(awk -F'\t' -v h='example.co.uk' '$1==h{print $3; exit}' "$TSV")
assert_eq "apex example.co.uk keeps root+tool source" "$rd_src" "root;crt.name"
# and its root_domain field is still correct (not overwritten to empty)
rd_rd=$(awk -F'\t' -v h='example.co.uk' '$1==h{print $2; exit}' "$TSV")
assert_eq "apex example.co.uk root_domain preserved" "$rd_rd" "example.co.uk"

# Back-fill: an out-of-scope host first added with empty root, then re-added
# in-scope with an explicit root -> root_domain gets filled, source merged.
# Use a genuinely out-of-scope host so the suffix match yields empty first.
printf 'random-edge.somecdn.net\n' > "$WORK/s6.txt"
canonical_dns_add_sources "katana" "$WORK/s6.txt"   # no explicit root, no suffix match
assert_eq "out-of-scope host root_domain empty first pass" \
    "$(awk -F'\t' -v h='random-edge.somecdn.net' '$1==h{print $2; exit}' "$TSV")" ""
printf 'random-edge.somecdn.net\n' > "$WORK/s7.txt"
canonical_dns_add_sources "subdomainizer" "$WORK/s7.txt" "example.com"
assert_eq "out-of-scope host root_domain back-filled" \
    "$(awk -F'\t' -v h='random-edge.somecdn.net' '$1==h{print $2; exit}' "$TSV")" "example.com"
assert_eq "out-of-scope host sources merged after back-fill" \
    "$(awk -F'\t' -v h='random-edge.somecdn.net' '$1==h{print $3; exit}' "$TSV")" "katana;subdomainizer"

echo
echo "=== Fix 3: classification rules per corrected config ==="
ASN_CONFIG_FILE="$ROOT/config/asn_providers.sh"
export ASN_CONFIG_FILE
load_asn_config >/dev/null 2>&1 || { echo "FATAL: could not load asn config"; exit 1; }

# Rule 1: HTTPX CDN=true -> cdn (regardless of ASN)
assert_eq "HTTPX CDN=true -> cdn (Azure ASN)" "$(classify_ip 1.1.1.1 AS8075 "Microsoft Azure" true)" "cdn"
assert_eq "HTTPX CDN=true -> cdn (AWS ASN)"   "$(classify_ip 1.1.1.1 AS16509 "Amazon.com" true)" "cdn"
# Rule 2: CDN ASN match -> cdn
assert_eq "Cloudflare ASN -> cdn"  "$(classify_ip 1.2.3.4 AS13335 "Cloudflare, Inc." false)" "cdn"
assert_eq "Fastly ASN -> cdn"      "$(classify_ip 1.2.3.4 AS54113 "Fastly" false)" "cdn"
# CDN provider-name match -> cdn
assert_eq "akamai org name -> cdn" "$(classify_ip 1.2.3.4 AS12345 "Akamai Technologies" false)" "cdn"

# Hyperscaler ASNs must NOT be CDN via ASN anymore (even though they run CDNs).
assert_eq "Azure ASN AS8075 (no httpx) -> cloud (NOT cdn)" \
    "$(classify_ip 1.2.3.4 AS8075 "Microsoft Azure" false)" "cloud"
assert_eq "Alibaba ASN AS7604 (no httpx) -> cloud (NOT cdn)" \
    "$(classify_ip 1.2.3.4 AS7604 "Alibaba US Technology" false)" "cloud"
assert_eq "Tencent ASN AS53913 (no httpx) -> cloud (NOT cdn)" \
    "$(classify_ip 1.2.3.4 AS53913 "Tencent Cloud" false)" "cloud"

# Rule 3: cloud ASN/provider -> cloud
assert_eq "AWS ASN -> cloud"        "$(classify_ip 1.2.3.4 AS16509 "Amazon.com" false)" "cloud"
assert_eq "GCP ASN -> cloud"        "$(classify_ip 1.2.3.4 AS15169 "Google LLC" false)" "cloud"
assert_eq "DigitalOcean ASN -> cloud" "$(classify_ip 1.2.3.4 AS14061 "DigitalOcean LLC" false)" "cloud"

# Rule 4: dedicated -> dedicated (true hosting, not ISP)
assert_eq "Datacamp ASN -> dedicated" "$(classify_ip 1.2.3.4 AS213230 "Datacamp Python" false)" "dedicated"
assert_eq "FranTech/BuyVM ASN -> dedicated" "$(classify_ip 1.2.3.4 AS53667 "FranTech Solutions" false)" "dedicated"
assert_eq "hostinger org name -> dedicated" "$(classify_ip 1.2.3.4 AS99999 "Hostinger International" false)" "dedicated"

# ISP/carrier ASNs must NOT be dedicated anymore -> unknown
assert_eq "Comcast org name -> unknown (removed from dedicated)" \
    "$(classify_ip 1.2.3.4 AS7922 "Comcast Cable Communications" false)" "unknown"
assert_eq "China Telecom org name -> unknown (removed from dedicated)" \
    "$(classify_ip 1.2.3.4 AS4134 "China Telecom" false)" "unknown"
assert_eq "Charter/Spectrum org name -> unknown (removed from dedicated)" \
    "$(classify_ip 1.2.3.4 AS11427 "Charter Communications" false)" "unknown"

# Rule 5: fallback -> unknown
assert_eq "unknown ASN/org -> unknown" "$(classify_ip 1.2.3.4 AS64500 "Some Random ISP" false)" "unknown"
assert_eq "empty ASN -> unknown"       "$(classify_ip 1.2.3.4 "" "" false)" "unknown"

# Cloud-overlap providers (Hetzner/OVH/Vultr) are cloud, not dedicated.
assert_eq "Hetzner -> cloud (not dedicated)" "$(classify_ip 1.2.3.4 AS24940 "Hetzner Online" false)" "cloud"
assert_eq "OVH -> cloud (not dedicated)"     "$(classify_ip 1.2.3.4 AS16276 "OVH SAS" false)" "cloud"
assert_eq "Vultr -> cloud (not dedicated)"   "$(classify_ip 1.2.3.4 AS20473 "Vultr Holdings LLC" false)" "cloud"

echo
echo "=== Fix 4: Nmap uses -Pn (source inspection) ==="
nmap_cmd=$(grep -A6 'nmap -Pn -iL' "$ROOT/lib/phase3.sh" | head -1)
if [[ "$nmap_cmd" == *"-Pn"* ]]; then
    printf '  [PASS] nmap invocation contains -Pn\n'; ((PASS++)) || true
else
    printf '  [FAIL] nmap invocation missing -Pn\n'; ((FAIL++)) || true
fi
# Port-selection policy unchanged: same -p list still present
if grep -q -- '-p 21,22,23,25,53,80,110' "$ROOT/lib/phase3.sh"; then
    printf '  [PASS] nmap port-selection policy unchanged\n'; ((PASS++)) || true
else
    printf '  [FAIL] nmap port-selection policy changed\n'; ((FAIL++)) || true
fi

echo
echo "========================================"
printf 'RESULTS: %d passed, %d failed\n' "$PASS" "$FAIL"
echo "========================================"
rm -rf "$WORK"
[[ "$FAIL" -eq 0 ]]