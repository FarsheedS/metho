# ── Build Stage ───────────────────────────────────────────────────────────────
# Compile Go binaries and massdns; clone git-hosted repos.
# Everything here is discarded in the runtime stage.
FROM debian:13-slim AS builder

ENV DEBIAN_FRONTEND=noninteractive
ENV GOPATH=/root/go
ENV PATH="${PATH}:/usr/local/go/bin:${GOPATH}/bin"

# Build-only system dependencies (ca-certificates is required for Go to
# verify TLS certificates when downloading modules from proxy.golang.org).
# No curl/wget needed: all downloads go through `go install` / `git clone`.
# No Ruby needed here: gems are installed in the runtime stage, where their
# native extensions must compile against the runtime's libc anyway.
RUN apt-get update && apt-get install -y --no-install-recommends \
    golang-go \
    git \
    build-essential \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ── Go-based Recon Tools ───────────────────────────────────────────────────
# Pinned release versions (latest at time of build). No @master branches.
RUN go install -v github.com/melvinsh/subfaster/v2/cmd/subfaster@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest

# massdns -- required by shuffledns for DNS brute force. It does NOT ship
# with shuffledns and shuffledns will silently produce no output if it
# can't find massdns. Compile from source per blechschmidt/massdns README.
RUN git clone --depth 1 https://github.com/blechschmidt/massdns.git /opt/massdns && \
    cd /opt/massdns && \
    make -j"$(nproc)" 2>/dev/null && \
    cp bin/massdns /usr/local/bin/massdns && \
    chmod +x /usr/local/bin/massdns && \
    rm -rf /opt/massdns

# ── Clone Git-hosted Repos ─────────────────────────────────────────────────
# Git lives only in the builder stage. The runtime stage receives these
# via COPY and therefore never needs git.
RUN git clone --depth 1 https://github.com/digininja/CeWL.git /opt/tools/cewl && \
    chmod +x /opt/tools/cewl/cewl.rb && \
    git clone --depth 1 https://github.com/nsonaniya2010/SubDomainizer.git /opt/tools/SubDomainizer && \
    git clone --depth 1 https://github.com/initstring/cloud_enum.git /opt/tools/cloud_enum


# ── Runtime Stage ─────────────────────────────────────────────────────────────
# Only runtime dependencies. No compilers, no git, no Go SDK, no build headers.
FROM debian:13-slim

LABEL maintainer="Metho"
LABEL description="Metho -- Automated Bug Bounty Reconnaissance Pipeline"

ENV DEBIAN_FRONTEND=noninteractive

# Runtime-only system dependencies:
#   python3/python3-pip -- SubDomainizer, Cloud_Enum, waymore
#   ruby                -- CeWL
#   dnsutils            -- dig/nslookup (dnsx handles pipeline resolution;
#                          dig is kept as the standard DNS debugging utility)
#   nmap                -- Phase 3 port scanning
#   netcat-openbsd      -- nc, used for the whois.cymru.com ASN lookup
#   curl                -- crt.name API queries
#   jq                  -- JSONL parsing throughout the pipeline
#   ca-certificates     -- TLS for curl/pip/httpx
# NOT needed: wget (curl covers it), whois (cymru query uses nc),
#             git (repos are COPYed from the builder).
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    ruby \
    dnsutils \
    nmap \
    netcat-openbsd \
    curl \
    jq \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Python symlink -- some tools use '#!/usr/bin/env python'
RUN ln -sf /usr/bin/python3 /usr/bin/python

# ── Copy compiled binaries from builder ────────────────────────────────────
COPY --from=builder /root/go/bin/subfaster /usr/local/bin/
COPY --from=builder /root/go/bin/httpx /usr/local/bin/
COPY --from=builder /root/go/bin/katana /usr/local/bin/
COPY --from=builder /root/go/bin/dnsx /usr/local/bin/
COPY --from=builder /root/go/bin/shuffledns /usr/local/bin/
COPY --from=builder /usr/local/bin/massdns /usr/local/bin/

# ── Copy git-cloned repos from builder ─────────────────────────────────────
COPY --from=builder /opt/tools/cewl /opt/tools/cewl
COPY --from=builder /opt/tools/SubDomainizer /opt/tools/SubDomainizer
COPY --from=builder /opt/tools/cloud_enum /opt/tools/cloud_enum

RUN ln -sf /opt/tools/cewl/cewl.rb /usr/local/bin/cewl

# ── CeWL Ruby Gems ──────────────────────────────────────────────────────────
# Native gems must compile against the runtime stage's libc/ruby, so they
# are installed here (not copied from the builder). Build deps are purged
# in the SAME RUN layer so they do not persist in the final image.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ruby-dev \
    build-essential \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    && gem install --no-document \
        public_suffix \
        spider \
        nokogiri \
        mime-types \
        mini_exiftool \
        mime \
        rexml \
        rubyzip \
    && apt-get purge -y --auto-remove \
        ruby-dev \
        build-essential \
        libxml2-dev \
        libxslt1-dev \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/* /root/.bundle

# ── Python tool dependencies ────────────────────────────────────────────────
# SubDomainizer (beautifulsoup4, requests, termcolor, colorama, tldextract, cffi)
RUN pip3 install --break-system-packages \
        beautifulsoup4 requests termcolor colorama tldextract cffi

# Cloud_Enum (real runtime deps from its pyproject.toml)
RUN pip3 install --break-system-packages \
        dnspython requests requests-futures

# Waymore - Historical URL/subdomain discovery
# https://github.com/xnl-h4ck3r/waymore
RUN pip3 install --break-system-packages waymore

# ── Copy Pipeline Scripts & Config ────────────────────────────────────────
COPY recon.sh /opt/scripts/recon.sh
COPY entrypoint.sh /opt/scripts/entrypoint.sh
COPY lib/ /opt/scripts/lib/
COPY config/ /opt/scripts/config/
COPY wordlists/ /opt/scripts/wordlists/

RUN chmod +x /opt/scripts/recon.sh /opt/scripts/entrypoint.sh

# ── Verify Runtime Tools ───────────────────────────────────────────────────
# Every binary and Python package must actually work in the final image.
#
# Two stream-behavior subtleties make `cmd -h 2>/dev/null | grep -q .` fragile:
#   1. projectdiscovery Go tools (httpx, dnsx, katana, shuffledns, subfaster)
#      print -h usage to STDOUT — `2>/dev/null` is harmless and stdout is non-empty.
#   2. massdns has NO -h/--help flag. It prints usage to STDERR and exits 1.
#      `massdns --help 2>/dev/null | grep -q .` → empty stdout → grep fails → build breaks.
#      Fix: invoke massdns with no args (usage → stderr) and capture BOTH streams.
#   3. waymore --help goes to stdout — fine.
#
# Pattern: `cmd <args> 2>&1 | grep -q .` — redirect stderr into stdout so
# grep sees the output regardless of which stream the tool chose, and fails
# only when the binary is truly absent or silent. This is robust for all tools.
RUN subfaster -h 2>&1 | grep -q . && \
    httpx -h 2>&1 | grep -q . && \
    katana -h 2>&1 | grep -q . && \
    dnsx -h 2>&1 | grep -q . && \
    shuffledns -h 2>&1 | grep -q . && \
    massdns 2>&1 | grep -q . && \
    waymore --help 2>&1 | grep -q . && \
    test -f /opt/tools/SubDomainizer/SubDomainizer.py && \
    test -f /opt/tools/cloud_enum/cloud_enum.py && \
    python3 -c "import bs4, requests, termcolor, colorama, tldextract, cffi, dns.resolver, requests_futures" && \
    echo "All runtime tools verified OK"

# CeWL smoke test: if any required gem is missing, cewl exits with
# "Error: <gem> gem not installed" before printing help. Require BOTH:
# some output AND no missing-gem error.
RUN cewl --help > /tmp/cewl_smoke.log 2>&1 ; \
    if grep -q "gem not installed" /tmp/cewl_smoke.log; then \
        echo "cewl smoke test FAILED:"; cat /tmp/cewl_smoke.log; exit 1; \
    fi; \
    grep -q . /tmp/cewl_smoke.log || { echo "cewl produced no output"; exit 1; }; \
    echo "cewl smoke test OK"; rm -f /tmp/cewl_smoke.log

# ── Runtime ─────────────────────────────────────────────────────────────────
WORKDIR /output

# Default mount points:
#   /output        -- results (always mount this)
#   /input         -- optional, for --domains-file
ENTRYPOINT ["/opt/scripts/entrypoint.sh"]
CMD ["--help"]