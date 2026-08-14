#!/usr/bin/env bash
set -euo pipefail

# Export PATH for Go binaries
export PATH="${PATH}:/root/go/bin:/usr/local/go/bin"

# Export environment variables for tool configuration
export SUBFASTER_PROVIDER_CONFIG="${SUBFASTER_PROVIDER_CONFIG:-}"
export ASN_CONFIG_FILE="${ASN_CONFIG_FILE:-}"
export WAYMORE_MODE="${WAYMORE_MODE:-B}"

# Ensure output directory exists and is writable
if [[ ! -d "/output" ]]; then
    mkdir -p /output
fi
chmod -R 777 /output 2>/dev/null || true

# Execute the recon script with all passed arguments
exec /opt/scripts/recon.sh "$@"