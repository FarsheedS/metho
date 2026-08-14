#!/usr/bin/env bash
# ── Metho ASN / Provider Classification Configuration ─────────────────────────
#
# This file is sourced by lib/classify.sh to deterministically classify IPs.
#
# Classification rules are applied in priority order:
#   1. HTTPX explicitly reports CDN = true         → "cdn"
#   2. ASN matches CDN_ASNS or org matches CDN     → "cdn"
#   3. ASN matches CLOUD_ASNS or org matches cloud → "cloud"
#   4. ASN matches DEDICATED_ASNS or org matches   → "dedicated"
#   5. Otherwise                                   → "unknown"
#
# An IP receives exactly ONE primary classification.
# CDN IPs are retained in results but excluded from nmap scanning.
#
# To add a new provider, add its ASN to the appropriate _ASNS array
# and/or its name fragment to the appropriate _PROVIDER_NAMES array.
# Names are matched case-insensitively as substrings of the ASN org field.

# ── CDN ────────────────────────────────────────────────────────────────────────
# Content Delivery Networks, reverse-proxy and WAF/edge providers.
# IPs behind these ASNs are almost always shared-edge nodes, not origin
# servers. Broad hyperscaler ASNs (e.g. Azure AS8075, AWS, Alibaba) are
# intentionally NOT listed here even though those providers also operate CDN
# services — they are classified as "cloud" instead. Actual CDN/WAF/edge
# endpoints are still caught by Rule 1 when HTTPX reports CDN=true, regardless
# of which ASN they live on.
CDN_ASNS=(
    "AS13335"    # Cloudflare
    "AS54113"    # Fastly
    "AS20940"    # Akamai Technologies
    "AS16625"    # Akamai Technologies (Prolexic)
    "AS12222"    # Akamai Technologies
    "AS20446"    # Highwinds / StackPath
    "AS30081"    # CacheNetworks
    "AS19551"    # Incapsula / Imperva
    "AS62597"    # Nexusguard (DDoS protection CDN)
    "AS200023"   # Qrator (DDoS protection CDN)
)

CDN_PROVIDER_NAMES=(
    "cloudflare"
    "cloudfront"
    "fastly"
    "akamai"
    "incapsula"
    "imperva"
    "stackpath"
    "sucuri"
    "verizon digital media"
    "cedexis"
    "chinanetcenter"
    "nexusguard"
    "qrator"
    "arvancloud"
    "bunny"
    "keycdn"
    "belugacdn"
    "rocketcdn"
)

# ── Cloud Providers ───────────────────────────────────────────────────────────
# Major cloud / hyperscaler hosting providers (AWS, GCP, Azure, etc.).
# These ASNs host actual customer infrastructure, not CDN edge nodes. Broad
# hyperscaler ASNs live here even when the provider also offers CDN services —
# CDN classification for those is left to HTTPX's explicit CDN detection
# (Rule 1), not to the ASN.
CLOUD_ASNS=(
    "AS14618"    # Amazon/AWS
    "AS16509"    # Amazon/AWS
    "AS15169"    # Google Cloud
    "AS8075"     # Microsoft/Azure
    "AS14061"    # DigitalOcean
    "AS20473"    # Vultr
    "AS63949"    # Linode (Akamai)
    "AS16276"    # OVH
    "AS24940"    # Hetzner
    "AS60626"    # Leaseweb
    "AS62041"    # Contabo
    "AS12876"    # Online SAS / Scaleway
    "AS16552"    # Oracle Cloud
    "AS21844"    # Oracle Cloud (Dyn)
    "AS31898"    # Oracle Cloud
    "AS8560"     # IONOS (1&1)
    "AS26496"    # Godaddy
    "AS55259"    # Alibaba Cloud
    "AS37963"    # Alibaba Cloud
    "AS45090"    # Alibaba Cloud (CN)
    "AS7552"     # Alibaba Cloud (AP)
    "AS7604"     # Alibaba (US) — hyperscaler, not CDN edge
    "AS53913"    # Tencent Cloud — hyperscaler, not CDN edge
)

CLOUD_PROVIDER_NAMES=(
    "amazon"
    "amazon.com"
    "amazonaws"
    "aws"
    "google"
    "google cloud"
    "gcp"
    "microsoft"
    "azure"
    "digitalocean"
    "digital ocean"
    "vultr"
    "linode"
    "ovh"
    "hetzner"
    "leaseweb"
    "contabo"
    "scaleway"
    "online sas"
    "oracle cloud"
    "oracle"
    "ionos"
    "1and1"
    "godaddy"
    "alibaba cloud"
    "alibaba"
    "tencent cloud"
    "huawei cloud"
    "samsungsds"
)

# ── Dedicated Hosting ──────────────────────────────────────────────────────────
# Providers that typically offer dedicated servers or bare-metal/VPS hosting
# and are NOT already covered by the cloud category. Generic ISP/carrier ASNs
# (Comcast, Charter/Spectrum, China Telecom/Unicom/Mobile, etc.) are
# intentionally excluded — they are transit/access networks, not hosting
# providers. Providers that are already classified as cloud (Hetzner, OVH,
# Vultr, Contabo, Leaseweb, Scaleway, IONOS, …) are omitted here too: cloud is
# checked before dedicated, so those entries were dead weight. "unknown"
# remains the fallback rather than guessing.
DEDICATED_ASNS=(
    "AS53667"    # FranTech / BuyVM (Choopa) — VPS/bare-metal
    "AS51167"    # Contabo (secondary)
    "AS213230"   # Datacamp / PYTHON
    "AS212238"   # Datacamp / PYTHON
)

DEDICATED_PROVIDER_NAMES=(
    "datacamp"
    "choopa"
    "buyvm"
    "fran tech"
    "m247"
    "psychz"
    "hostwinds"
    "hostinger"
    "dreamhost"
    "a2hosting"
    "inmotion"
    "bluehost"
    "siteground"
    "namecheap"
)