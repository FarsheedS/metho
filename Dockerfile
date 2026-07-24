FROM kalilinux/kali-rolling:latest

LABEL maintainer="Metho"
LABEL description="Metho — Automated Bug Bounty Reconnaissance Pipeline"

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# ── System Dependencies ─────────────────────────────────────────────────────
# `build-essential`, `ruby-dev`, `libxml2-dev`, `libxslt1-dev`, `zlib1g-dev`,
# and `python3-dev` are required at build time only (CeWL native gem
# extensions, massdns from source, Python wheels). They are purged after the
# CeWL+massdns install below so the final image doesn't carry them.
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-dev \
    ruby \
    ruby-dev \
    ruby-bundler \
    golang-go \
    git \
    wget \
    curl \
    jq \
    dnsutils \
    nmap \
    whois \
    host \
    netcat-openbsd \
    unzip \
    build-essential \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# massdns — required by shuffledns for DNS brute force. It does NOT ship
# with shuffledns and shuffledns will silently produce no output if it
# can't find massdns (which is what was happening in our runs before this
# was added). Compile from source per blechschmidt/massdns README:
#   git clone + make  →  build/bin/massdns (static binary).
# We strip it and place it under /usr/local/bin so shuffledns auto-detects
# it (per the projectdiscovery/shuffledns README, massdns is auto-detected
# from /usr/bin or /usr/local/bin).
RUN git clone --depth 1 https://github.com/blechschmidt/massdns.git /opt/massdns && \
    cd /opt/massdns && \
    make -j"$(nproc)" 2>/dev/null && \
    cp bin/massdns /usr/local/bin/massdns && \
    chmod +x /usr/local/bin/massdns && \
    massdns --help 2>/dev/null | head -3 && \
    rm -rf /opt/massdns

# Python symlink — many tools (e.g. Sublist3r) use '#!/usr/bin/env python'
# but modern Kali only ships python3.
RUN ln -sf /usr/bin/python3 /usr/bin/python

# ── Go Environment ──────────────────────────────────────────────────────────
ENV GOPATH=/root/go
ENV PATH="${PATH}:${GOPATH}/bin:/usr/local/go/bin"

# ── Go-based Recon Tools ───────────────────────────────────────────────────
# Only the tools actually invoked by lib/*.sh are installed. waybackurls
# and unfurl are intentionally omitted — they're not called anywhere in the
# pipeline. Add them back here if/when they're wired into a later stage.
RUN go install -v github.com/owasp-amass/amass/v4/...@master 2>/dev/null || true && \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest && \
    go install -v github.com/lc/gau/v2/cmd/gau@latest && \
    go install -v github.com/tomnomnom/assetfinder@latest && \
    go install -v github.com/jaeles-project/gospider@latest && \
    go install -v github.com/glebarez/cero@latest && \
    go install -v github.com/gwen001/github-subdomains@latest

# ── Git-cloned Tools ───────────────────────────────────────────────────────
RUN mkdir -p /opt/tools

# CeWL - Custom Word List Generator (Ruby)
# CeWL requires the gems listed in its Gemfile:
#   mime, mime-types (>=3.3.1), mini_exiftool, nokogiri, rexml,
#   rubyzip, spider, public_suffix, getoptlong
# At runtime, cewl.rb `require`s these in order:
#   getoptlong, public_suffix, spider, nokogiri, net/http, cgi
# and cewl_lib.rb requires: mini_exiftool, zip, rexml/document, mime,
# mime-types.
#
# We try `bundle install --system` first; the fallback `gem install`
# list MUST include every gem the runtime requires — previously this
# list was missing public_suffix, spider, and mini_exiftool, which made
# CeWL exit immediately with "Error: <gem> gem not installed" and
# silently produce zero output.
#
# After install, purge the build-only dev packages in the SAME RUN
# layer so the deletions persist in the final image. The smoke test
# runs `cewl --help` and checks its output for the "gem not installed"
# failure mode — missing gems fail BEFORE option parsing in cewl.rb
# (the require block runs first), so a missing-gem exit prints the
# error and never reaches the usage banner.
RUN git clone --depth 1 https://github.com/digininja/CeWL.git /opt/tools/cewl && \
    cd /opt/tools/cewl && \
    (bundle config set --local path 'system' >/dev/null 2>&1 || true) && \
    # Try `bundle install --system` first (resolves against CeWL's
    # Gemfile). The fallback `gem install` ALWAYS runs after, but is
    # idempotent — `gem install` skips gems that are already at the
    # latest version. This means we get the best of both worlds:
    #   - If bundle works, gems are installed at the right versions
    #     from the Gemfile, and the gem install is a no-op.
    #   - If bundle fails (network/version mismatch), the explicit
    #     gem list below guarantees the runtime requires
    #     (public_suffix, spider, mini_exiftool, etc.) are present.
    bundle install --system 2>/dev/null || true ; \
    gem install --no-document \
        public_suffix \
        spider \
        nokogiri \
        mime-types \
        mini_exiftool \
        mime \
        rexml \
        rubyzip \
    2>/dev/null || true ; \
    ln -sf /opt/tools/cewl/cewl.rb /usr/local/bin/cewl && \
    chmod +x /opt/tools/cewl/cewl.rb && \
    # Smoke test: if any required gem is missing, cewl exits with
    # "Error: <gem> gem not installed" before printing help. We grep
    # for that exact failure mode and fail the build if seen.
    cewl --help 2>&1 | tee /tmp/cewl_smoke.log | grep -q "gem not installed" && \
        (echo "cewl smoke test FAILED — see /tmp/cewl_smoke.log"; exit 1) || \
        echo "cewl smoke test OK" && \
    apt-get purge -y --auto-remove \
        build-essential \
        ruby-dev \
        ruby-bundler \
        libxml2-dev \
        libxslt1-dev \
        zlib1g-dev \
        python3-dev \
    && apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/* /root/.bundle /opt/tools/cewl/.bundle

# Sublist3r - Subdomain Enumeration (Python, git version preferred over pip)
RUN git clone --depth 1 https://github.com/aboul3la/Sublist3r.git /opt/tools/sublist3r && \
    pip3 install --break-system-packages -r /opt/tools/sublist3r/requirements.txt 2>/dev/null || true && \
    chmod +x /opt/tools/sublist3r/sublist3r.py && \
    ln -sf /opt/tools/sublist3r/sublist3r.py /usr/local/bin/sublist3r

# SubDomainizer - JavaScript subdomain/secret discovery
RUN git clone --depth 1 https://github.com/nsonaniya2010/SubDomainizer.git /opt/tools/SubDomainizer && \
    pip3 install --break-system-packages \
        beautifulsoup4 requests termcolor colorama tldextract cffi 2>/dev/null || true

# Cloud_Enum - Cloud bucket/service brute force
# cloud_enum migrated off requirements.txt to uv/pyproject.toml, so the old
# `pip install -r requirements.txt` now 404s on GitHub, the install silently
# fails (swallowed by `2>/dev/null || true`), and at runtime enum_tools/utils.py
# prints "[!] Please pip install requirements.txt." and sys.exit()s before
# doing any work -- Stage 3 produced zero output for exactly this reason.
# Install the three real runtime deps (from pyproject.toml) explicitly,
# mirroring the CeWL/Sublist3r explicit-deps pattern.
RUN git clone --depth 1 https://github.com/initstring/cloud_enum.git /opt/tools/cloud_enum && \
    pip3 install --break-system-packages \
        dnspython requests requests-futures 2>/dev/null || true

# ── Copy Scripts ────────────────────────────────────────────────────────────
COPY recon.sh /opt/scripts/recon.sh
COPY entrypoint.sh /opt/scripts/entrypoint.sh
COPY lib/ /opt/scripts/lib/
COPY wordlists/ /opt/scripts/wordlists/

RUN chmod +x /opt/scripts/recon.sh /opt/scripts/entrypoint.sh

# ── Runtime ─────────────────────────────────────────────────────────────────
WORKDIR /output

# Default mount points:
#   /output        — results (always mount this)
#   /input         — optional, for --domains-file
ENTRYPOINT ["/opt/scripts/entrypoint.sh"]
CMD ["--help"]
