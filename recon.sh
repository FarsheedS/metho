#!/usr/bin/env bash
#
# Metho — Automated Recon Pipeline
#
# Usage:
#   docker run --rm -it -v $(pwd)/results:/output metho [options]
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source all library scripts
source "${SCRIPT_DIR}/lib/utils.sh"
source "${SCRIPT_DIR}/lib/canonical_dns.sh"
source "${SCRIPT_DIR}/lib/classify.sh"
source "${SCRIPT_DIR}/lib/phase1.sh"
source "${SCRIPT_DIR}/lib/phase2.sh"
source "${SCRIPT_DIR}/lib/phase3.sh"
source "${SCRIPT_DIR}/lib/consolidate.sh"

# Parse CLI arguments
parse_args "$@"
validate_args

# Setup
validate_deps
setup_dirs
init_log

# Initialize the canonical DNS dataset
init_canonical_dns

# Load the ASN provider configuration for deterministic IP classification
load_asn_config

# Banner
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║        Metho — Recon Pipeline                    ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""
log_info "Domains:    ${DOMAINS:-<not set>}"
log_info "Domains file: ${DOMAINS_FILE:-<not set>}"
log_info "Auto mode:  ${AUTO}"
log_info "Output:     ${OUTPUT_DIR}"
log_info "Threads:    ${THREADS}"
log_info "Rate limit: ${RATE_LIMIT}/s"
log_info "Parallel hosts (per-tool): ${PARALLEL_HOSTS}"
log_info "Port scan:  ${PORT_SCAN}"
[[ -n "$SUBFASTER_PROVIDER_CONFIG" ]] && log_info "Subfaster config: ${SUBFASTER_PROVIDER_CONFIG}"
[[ -n "$ASN_CONFIG_FILE" ]] && log_info "ASN config: ${ASN_CONFIG_FILE}"
log_info "Waymore mode: ${WAYMORE_MODE}"
[[ -n "$CLOUD_ENUM_KEYWORDS" ]] && log_info "Cloud enum keywords: ${CLOUD_ENUM_KEYWORDS}"
echo ""

# ── Resolve root domains ────────────────────────────────────────────────────
ROOT_DOMAINS_FILE=$(resolve_domain_file "${OUTPUT_DIR}/root_domains.txt")

if [[ -z "$ROOT_DOMAINS_FILE" || ! -s "$ROOT_DOMAINS_FILE" ]]; then
    log_error "No root domains provided. Use --domains or --domains-file."
    exit 1
fi

log_success "Loaded $(wc -l < "$ROOT_DOMAINS_FILE") root domains"

# ── Phase 1: Subdomain Discovery ────────────────────────────────────────────
if ! should_skip_phase 1; then
    run_phase1 "$ROOT_DOMAINS_FILE"

    checkpoint "Phase 1 complete. Subdomains discovered for $(wc -l < "$ROOT_DOMAINS_FILE") domain(s)." || true
else
    log_info "Skipping Phase 1 (--skip-phase)"
fi

# ── Phase 2: Cloud Asset Discovery ─────────────────────────────────────────
if ! should_skip_phase 2; then
    ALL_SUBDOMAINS_FILE="${OUTPUT_DIR}/final/final_all_domains.txt"
    LIVE_WEB_FILE="${OUTPUT_DIR}/final/final_live_web_servers.txt"

    # Build intermediate files if Phase 1 ran
    if ! should_skip_phase 1; then
        cat "${OUTPUT_DIR}"/phase1/*/all_subdomains_final.txt 2>/dev/null | sort -u > "$ALL_SUBDOMAINS_FILE" || true
        cat "${OUTPUT_DIR}"/phase1/*/live_subdomains_final.txt 2>/dev/null | sort -u > "$LIVE_WEB_FILE" || true
    fi

    run_phase2 "$ROOT_DOMAINS_FILE" "$ALL_SUBDOMAINS_FILE" "$LIVE_WEB_FILE"

    checkpoint "Phase 2 complete. Cloud assets: $(wc -l < "${OUTPUT_DIR}/phase2/final_cloud_assets.txt" 2>/dev/null || echo '?')" || true
else
    log_info "Skipping Phase 2 (--skip-phase / --skip-cloud)"
fi

# ── Phase 3: IP → Classification → Port Scan ────────────────────────────────
if ! should_skip_phase 3; then
    run_phase3

    checkpoint "Phase 3 complete. IPs: $(wc -l < "${OUTPUT_DIR}/phase3/all_resolved_ips.txt" 2>/dev/null || echo '?') | ASNs: $(wc -l < "${OUTPUT_DIR}/phase3/asn_list.txt" 2>/dev/null || echo '?')" || true
else
    log_info "Skipping Phase 3 (--skip-phase)"
fi

# ── Final Consolidation ────────────────────────────────────────────────────
run_consolidation

log_success "Recon pipeline complete!"
log_info "Full log saved to ${OUTPUT_DIR}/recon.log"