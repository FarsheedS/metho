# ── Build Stage ───────────────────────────────────────────────────────────────
# Compile Go binaries and massdns; install Ruby gems for CeWL.
# Everything here is discarded in the runtime stage.
FROM debian:13-slim AS builder

ENV DEBIAN_FRONTEND=noninteractive
ENV GOPATH=/root/go
ENV PATH="${PATH}:/usr/local/go/bin:${GOPATH}/bin"

# Build-only system dependencies (ca-certificates is required for Go to
# verify TLS certificates when downloading modules from proxy.golang.org).
RUN apt-get update && apt-get install -y --no-install-recommends \
    golang-go \
    git \
    build-essential \
    wget \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ── Go-based Recon Tools ───────────────────────────────────────────────────
# Pinned release versions (latest at time of build). No @master branches.
RUN go install -v github.com/melvinsh/subfaster/v2/cmd/subfaster@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest

# massdns — required by shuffledns for DNS brute force. It does NOT ship
# with shuffledns and shuffledns will silently produce no output if it
# can't find massdns. Compile from source per blechschmidt/massdns README.
RUN git clone --depth 1 https://github.com/blechschmidt/massdns.git /opt/massdns && \
    cd /opt/massdns && \
    make -j"$(nproc)" 2>/dev/null && \
    cp bin/massdns /usr/local/bin/massdns && \
    chmod +x /usr/local/bin/massdns && \
    massdns --help 2>/dev/null | head -3 && \
    rm -rf /opt/massdns

# ── CeWL Ruby Dependencies ────────────────────────────────────────────────
# Install build deps, gems, then purge build deps — all in one RUN layer
# so the deletions persist in the final builder image.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ruby \
    ruby-dev \
    ruby-bundler \
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
    && rm -rf /var/lib/apt/lists/* /root/.bundle


# ── Runtime Stage ─────────────────────────────────────────────────────────────
# Only runtime dependencies. No compilers, no Go SDK, no build headers.
FROM debian:13-slim

LABEL maintainer="Metho"
LABEL description="Metho — Automated Bug Bounty Reconnaissance Pipeline"

ENV DEBIAN_FRONTEND=noninteractive

# Runtime-only system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    ruby \
    dnsutils \
    nmap \
    whois \
    netcat-openbsd \
    curl \
    jq \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Python symlink — some tools use '#!/usr/bin/env python'
RUN ln -sf /usr/bin/python3 /usr/bin/python

# ── Copy Go binaries from builder ─────────────────────────────────────────
COPY --from=builder /root/go/bin/subfaster /usr/local/bin/
COPY --from=builder /root/go/bin/httpx /usr/local/bin/
COPY --from=builder /root/go/bin/katana /usr/local/bin/
COPY --from=builder /root/go/bin/dnsx /usr/local/bin/
COPY --from=builder /root/go/bin/shuffledns /usr/local/bin/
COPY --from=builder /usr/local/bin/massdns /usr/local/bin/

# ── CeWL ────────────────────────────────────────────────────────────────────
# Clone and link. Ruby gems need recompilation for the runtime stage's libc/ruby.
RUN git clone --depth 1 https://github.com/digininja/CeWL.git /opt/tools/cewl && \
    ln -sf /opt/tools/cewl/cewl.rb /usr/local/bin/cewl && \
    chmod +x /opt/tools/cewl/cewl.rb

# Reinstall Ruby native gems against the runtime stage's Ruby/libc.
# Build deps are installed temporarily and purged in the same RUN layer.
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
    && apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/* /root/.bundle

# Smoke test: if any required gem is missing, cewl exits with
# "Error: <gem> gem not installed" before printing help.
RUN cewl --help 2>&1 | grep -q "gem not installed" && \
    (echo "cewl smoke test FAILED"; exit 1) || echo "cewl smoke test OK"

# ── Python Tools ────────────────────────────────────────────────────────────

# SubDomainizer - JavaScript subdomain/secret discovery
RUN git clone --depth 1 https://github.com/nsonaniya2010/SubDomainizer.git /opt/tools/SubDomainizer && \
    pip3 install --break-system-packages \
        beautifulsoup4 requests termcolor colorama tldextract cffi 2>/dev/null || true

# Cloud_Enum - Cloud bucket/service brute force
# Install the three real runtime deps (from pyproject.toml) explicitly.
RUN git clone --depth 1 https://github.com/initstring/cloud_enum.git /opt/tools/cloud_enum && \
    pip3 install --break-system-packages \
        dnspython requests requests-futures 2>/dev/null || true

# Waymore - Historical URL/subdomain discovery
# https://github.com/xnl-h4ck3r/waymore
RUN pip3 install --break-system-packages waymore 2>/dev/null || true

# ── Copy Pipeline Scripts & Config ────────────────────────────────────────
COPY recon.sh /opt/scripts/recon.sh
COPY entrypoint.sh /opt/scripts/entrypoint.sh
COPY lib/ /opt/scripts/lib/
COPY config/ /opt/scripts/config/
COPY wordlists/ /opt/scripts/wordlists/

RUN chmod +x /opt/scripts/recon.sh /opt/scripts/entrypoint.sh

# ── Verify Runtime Binaries ────────────────────────────────────────────────
# Each binary must respond to -h/--help/--version. If any fails, the build
# fails immediately — no silent missing tools in production.
RUN subfaster -h 2>/dev/null | head -1 && \
    httpx -h 2>/dev/null | head -1 && \
    katana -h 2>/dev/null | head -1 && \
    dnsx -h 2>/dev/null | head -1 && \
    shuffledns -h 2>/dev/null | head -1 && \
    massdns --help 2>/dev/null | head -1 && \
    waymore --help 2>/dev/null | head -1 && \
    echo "All runtime binaries verified OK"

# ── Runtime ─────────────────────────────────────────────────────────────────
WORKDIR /output

# Default mount points:
#   /output        — results (always mount this)
#   /input         — optional, for --domains-file
ENTRYPOINT ["/opt/scripts/entrypoint.sh"]
CMD ["--help"]