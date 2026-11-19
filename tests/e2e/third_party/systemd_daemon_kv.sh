#!/usr/bin/env bash
# E2E verifies that the installed systemd daemon runs in const mode and publishes to KV.
#
# Trigger: the deployed unit supplies environment and config through systemd sandboxing.
# Direct binary execution cannot prove those files are visible to the real service.
# This prevents a healthy-looking unit from silently omitting its discovery report.
#
# Example: `CF_TOKEN=... systemd_daemon_kv.sh` -> prints `systemd daemon KV ok`.
set -euo pipefail

: "${CF_TOKEN:?CF_TOKEN must be exported}"
: "${CF_ACCOUNT_ID:?CF_ACCOUNT_ID must be exported}"
: "${CF_KV_NAMESPACE_ID:?CF_KV_NAMESPACE_ID must be exported}"
: "${CF_KV_KEY:?CF_KV_KEY must be exported}"
unit=tmp-proxy-daemon.service
kv_url=https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/storage/kv/namespaces/${CF_KV_NAMESPACE_ID}/values/${CF_KV_KEY}

for _ in {1..60}; do
    if ! systemctl is-active --quiet "$unit"; then
        sleep 2
        continue
    fi
    service_pid=$(systemctl show "$unit" -p MainPID --value)
    if [[ "$service_pid" == 0 || ! -r "/proc/${service_pid}/cmdline" ]]; then
        sleep 2
        continue
    fi
    command_line=$(tr '\0' ' ' <"/proc/${service_pid}/cmdline")
    if [[ "$command_line" != *" -const"* || "$command_line" == *" -discover-host "* ]]; then
        echo "installed daemon arguments do not select const KV mode" >&2
        exit 1
    fi
    current_code=$(journalctl _PID="$service_pid" -b --no-pager -o cat \
        | awk '/^code: / {code=$2} END {print code}')
    if [[ -n "$current_code" ]] && curl --fail --silent --max-time 5 \
        -H "Authorization: Bearer ${CF_TOKEN}" "$kv_url" \
        | jq -e --arg code "$current_code" --arg key "${CF_KV_KEY##*/}" \
            '.key == $key and .code == $code and .cf != ""' >/dev/null 2>&1; then
        echo "systemd daemon KV ok"
        exit 0
    fi
    sleep 2
done

echo "installed daemon did not publish its current code to Cloudflare KV" >&2
exit 1
