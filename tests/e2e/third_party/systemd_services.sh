#!/usr/bin/env bash
# E2E validates that systemd can supervise the center and expose `/list`.
#
# Trigger: deployment relies on systemd unit lifecycle and curl HTTP behavior.
# Direct execution cannot prove systemd supervision or unit cleanup semantics.
# This prevents shipping a valid binary with an unusable service definition.
#
# The binary must be in a system executable path so SELinux can authorize it.
#
# Example: `systemd_services.sh /usr/local/bin/tmp-proxy 19090` -> prints `[]`.
set -euo pipefail

binary=${1:?"usage: systemd_services.sh <binary> <unused_port>"}
port=${2:?"usage: systemd_services.sh <binary> <unused_port>"}
unit="tmp-proxy-systemd-e2e-${RANDOM}.service"

trap 'sudo systemctl stop "$unit" >/dev/null 2>&1 || true' EXIT

sudo systemd-run \
    --collect \
    --unit "$unit" \
    --property Type=exec \
    "$binary" -center -ip 127.0.0.1 -port "$port" >/dev/null

response=""
for _ in {1..20}; do
    if response=$(curl --fail --silent --show-error --max-time 1 \
        "http://127.0.0.1:${port}/list" 2>/dev/null); then
        break
    fi
    sleep 0.25
done

if [[ "$response" != "[]" ]]; then
    echo "unexpected center response: $response" >&2
    exit 1
fi

printf '%s\n' "$response"
