#!/usr/bin/env bash
# E2E checks both daemon reporter backends and KV cleanup with real Cloudflare APIs.
#
# Trigger: Cloudflare KV URL routing, namespace lookup, and tunnel events are external behavior.
# Local-only checks cannot prove the actual write, read-back, and deletion contract.
# This prevents leaving a test key or shipping an integration that never reports.
#
# Example: `CF_TOKEN=... cloudflare_kv.sh target/debug/tmp-proxy` -> three success lines.
set -euo pipefail

binary=${1:?"usage: cloudflare_kv.sh <binary>"}
: "${CF_TOKEN:?CF_TOKEN must be exported}"

work_dir=$(mktemp -d)
target_port=$(shuf -i 20000-45000 -n 1)
center_port=$(shuf -i 45001-60000 -n 1)
key="e2e-$(date +%s)-${RANDOM}"
prefix="cfp-e2e"
kv_url="https://api.cloudflare.com/client/v4/accounts/00000000000000000000000000000000/storage/kv/namespaces/11111111111111111111111111111111/values/${prefix}/${key}"
target_pid=
center_pid=
daemon_pid=
kv_deleted=false

# Stops every child and removes the unique KV key even after an early failure.
# Example: a failed read-back -> no daemon process or KV record remains.
cleanup() {
    set +e
    if [[ -n "$daemon_pid" ]]; then kill "$daemon_pid" 2>/dev/null; wait "$daemon_pid" 2>/dev/null; fi
    if [[ -n "$center_pid" ]]; then kill "$center_pid" 2>/dev/null; wait "$center_pid" 2>/dev/null; fi
    if [[ -n "$target_pid" ]]; then kill "$target_pid" 2>/dev/null; wait "$target_pid" 2>/dev/null; fi
    if [[ "$kv_deleted" == false ]]; then
        curl --silent --show-error --max-time 15 -X DELETE \
            -H "Authorization: Bearer ${CF_TOKEN}" "$kv_url" >/dev/null 2>&1
    fi
    rm -rf -- "$work_dir"
}
trap cleanup EXIT

socat -u "TCP-LISTEN:${target_port},bind=127.0.0.1,reuseaddr,fork" OPEN:/dev/null,wronly \
    >"$work_dir/target.log" 2>&1 &
target_pid=$!
for _ in {1..40}; do
    if (echo >/dev/tcp/127.0.0.1/"$target_port") 2>/dev/null; then
        break
    fi
    sleep 0.25
done

"$binary" -center -ip 127.0.0.1 -port "$center_port" \
    >"$work_dir/center.log" 2>&1 &
center_pid=$!

for _ in {1..40}; do
    if curl --fail --silent --max-time 1 "http://127.0.0.1:${center_port}/list" >/dev/null; then
        break
    fi
    sleep 0.25
done

cat >"$work_dir/center.yaml" <<EOF
reporter:
  type: custom_center
  host: 127.0.0.1:${center_port}
EOF

CFP_CONFIG="$work_dir/center.yaml" "$binary" -daemon -key "$key" \
    -ip 127.0.0.1 -port "$target_port" >"$work_dir/daemon-center.log" 2>&1 &
daemon_pid=$!

center_ok=false
for _ in {1..240}; do
    if curl --fail --silent --max-time 2 "http://127.0.0.1:${center_port}/list" \
        | jq -e --arg key "$key" '.[] | select(.key == $key and .cf != "" and .code != "")' \
        >/dev/null 2>&1; then
        center_ok=true
        break
    fi
    if ! kill -0 "$daemon_pid" 2>/dev/null; then break; fi
    sleep 0.5
done
if [[ "$center_ok" != true ]]; then
    cat "$work_dir/daemon-center.log" >&2
    echo "custom_center did not receive a report" >&2
    exit 1
fi
echo "custom_center report ok"

kill "$daemon_pid"
wait "$daemon_pid" 2>/dev/null || true
daemon_pid=

cat >"$work_dir/kv.yaml" <<EOF
reporter:
  type: cf_kv
  token_env: CF_TOKEN
  namespace: proxy
  prefix: ${prefix}
EOF

CFP_CONFIG="$work_dir/kv.yaml" "$binary" -daemon -key "$key" \
    -ip 127.0.0.1 -port "$target_port" >"$work_dir/daemon-kv.log" 2>&1 &
daemon_pid=$!

kv_ok=false
for _ in {1..240}; do
    if curl --fail --silent --max-time 5 \
        -H "Authorization: Bearer ${CF_TOKEN}" "$kv_url" \
        | jq -e --arg key "$key" '.key == $key and .cf != "" and .code != ""' \
        >/dev/null 2>&1; then
        kv_ok=true
        break
    fi
    if ! kill -0 "$daemon_pid" 2>/dev/null; then break; fi
    sleep 0.5
done
if [[ "$kv_ok" != true ]]; then
    cat "$work_dir/daemon-kv.log" >&2
    echo "Cloudflare KV did not return the daemon report" >&2
    exit 1
fi
echo "Cloudflare KV read-back ok"

expiration_ok=false
for _ in {1..30}; do
    if curl --fail --silent --max-time 5 --get \
        --data-urlencode "prefix=${prefix}/${key}" \
        -H "Authorization: Bearer ${CF_TOKEN}" \
        "https://api.cloudflare.com/client/v4/accounts/00000000000000000000000000000000/storage/kv/namespaces/11111111111111111111111111111111/keys" \
        | jq -e --arg name "${prefix}/${key}" --argjson now "$(date +%s)" \
            '.result[]? | select(.name == $name and .expiration >= ($now + 10740) and .expiration <= ($now + 10860))' \
        >/dev/null 2>&1; then
        expiration_ok=true
        break
    fi
    sleep 1
done
if [[ "$expiration_ok" != true ]]; then
    echo "Cloudflare KV record is missing the three-hour expiration" >&2
    exit 1
fi
echo "Cloudflare KV expiration ok"

kill "$daemon_pid"
wait "$daemon_pid" 2>/dev/null || true
daemon_pid=

delete_result=$(curl --fail --silent --show-error --max-time 15 -X DELETE \
    -H "Authorization: Bearer ${CF_TOKEN}" "$kv_url")
if ! jq -e '.success == true' <<<"$delete_result" >/dev/null; then
    echo "Cloudflare KV delete returned an unsuccessful response" >&2
    exit 1
fi
kv_deleted=true

for _ in {1..60}; do
    status=$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 5 \
        -H "Authorization: Bearer ${CF_TOKEN}" "$kv_url")
    if [[ "$status" == 404 ]]; then
        echo "Cloudflare KV cleanup ok"
        exit 0
    fi
    sleep 1
done
echo "Cloudflare KV key still exists after deletion" >&2
exit 1
