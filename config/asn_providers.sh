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
# Content Delivery Networks and reverse-proxy/WAF providers.
# IPs behind these ASNs are almost always shared-edge nodes, not origin servers.
CDN_ASNS=(
    "AS13335"    # Cloudflare
    "AS54113"    # Fastly
    "AS20940"    # Akamai Technologies
    "AS16625"    # Akamai Technologies (Prolexic)
    "AS12222"    # Akamai Technologies
    "AS53913"    # Akamai Technologies (Tencent cloud)
    "AS8075"     # Microsoft/Azure CDN (also Azure cloud; CDN takes priority)
    "AS7604"     # Alibaba CDN
    "AS20446"    # Highwinds/StackPath
    "AS30081"    # CacheNetworks
    "AS8001"     # Netrail/Akamai
    "AS46606"    # Tumblr (Verizon Media CDN)
    "AS19551"    # Incapsula/Imperva CDN
    "AS53667"    # FranTech (VPN/proxy hosting)
    "AS62597"    # Nexusguard (DDoS protection CDN)
    "AS200023"   # Qrator (DDoS protection CDN)
    "AS16265"    # Leaseweb CDN
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
    "qrcode"
    "nexusguard"
    "qrator"
    "arvancloud"
    "bunny"
    "keycdn"
    "belugacdn"
    "rocketcdn"
)

# ── Cloud Providers ───────────────────────────────────────────────────────────
# Major cloud hosting providers (AWS, GCP, Azure, etc.).
# These ASNs host actual customer infrastructure, not CDN edge nodes.
CLOUD_ASNS=(
    "AS14618"    # Amazon/AWS
    "AS16509"    # Amazon/AWS
    "AS15169"    # Google Cloud
    "AS8075"     # Microsoft/Azure (also CDN; CDN takes priority)
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
# Hosting providers that typically offer dedicated servers or VPS.
# These are not CDNs and not hyperscale clouds — they're single-tenant servers.
DEDICATED_ASNS=(
    "AS24940"    # Hetzner (also in cloud; cloud takes priority for overlap)
    "AS16276"    # OVH (also in cloud; cloud takes priority for overlap)
    "AS20473"    # Vultr (also in cloud; cloud takes priority for overlap)
    "AS62041"    # Contabo (also in cloud; cloud takes priority for overlap)
    "AS60626"    # Leaseweb (also in cloud; cloud takes priority for overlap)
    "AS12876"    # Online SAS / Scaleway (also in cloud; cloud takes priority)
    "AS8560"     # IONOS / 1&1 (also in cloud; cloud takes priority for overlap)
    "AS51167"    # Contabo
    "AS213230"   # Datacamp/PYTHON
    "AS212238"   # Datacamp/PYTHON
    "AS7922"     # Comcast
    "AS11427"    # Charter/Spectrum
    "AS20001"    # Charter/Spectrum
    "AS10796"    # Charter/Spectrum
    "AS10318"    # China Telecom
    "AS4134"     # China Telecom
    "AS4837"     # China Unicom
    "AS9808"     # China Mobile
    "AS58466"    # China Mobile
)

DEDICATED_PROVIDER_NAMES=(
    "hetzner"
    "ovh"
    "contabo"
    "leaseweb"
    "scaleway"
    "online sas"
    "ionos"
    "1and1"
    "godaddy"
    "digitalocean"
    "vultr"
    "linode"
    "datacamp"
    "choopa"
    "m247"
    "psychz"
    "buyvm"
    "hostwinds"
    "hostinger"
    "dreamhost"
    "a2hosting"
    "inmotion"
    "bluehost"
    "siteground"
    "namecheap"
    "comcast"
    "charter"
    "spectrum"
    "china telecom"
    "china unicom"
    "china mobile"
)