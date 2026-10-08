#!/usr/bin/env bash
# Atomically install the x86_64 daemon binary with readiness rollback.
# Example: install-daemon-root.sh /tmp/tmp-proxy.new -> ready daemon or rollback.
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "install-daemon-root.sh must run as root" >&2
    exit 1
fi

if [[ "$#" -ne 1 || ! -f "$1" ]]; then
    echo "usage: install-daemon-root.sh <staged-binary>" >&2
    exit 1
fi

staged_binary=$1
service=tmp-proxy-daemon.service
live_binary=/usr/local/bin/tmp-proxy
next_binary=/usr/local/bin/.tmp-proxy.next
backup_binary=/usr/local/bin/tmp-proxy.rollback
replaced=false

case "$(uname -m)" in
    x86_64)
        binary_pattern='ELF 64-bit.*x86-64'
        ;;
    aarch64 | arm64)
        binary_pattern='ELF 64-bit.*ARM aarch64'
        ;;
    *)
        echo "unsupported daemon architecture: $(uname -m)" >&2
        exit 1
        ;;
esac
if ! file "$staged_binary" | grep -q "$binary_pattern"; then
    echo "staged daemon architecture does not match $(uname -m)" >&2
    exit 1
fi
if ldd "$staged_binary" | grep -q 'not found'; then
    echo "staged daemon has missing libraries" >&2
    exit 1
fi

# rollback restores the previous daemon after any post-replacement failure.
# Example: readiness timeout -> old binary is restarted before exit.
rollback() {
    trap - ERR
    if [[ "$replaced" == true ]]; then
        install -o root -g root -m 0755 "$backup_binary" "$live_binary"
        if command -v restorecon >/dev/null 2>&1; then
            restorecon -F "$live_binary"
        fi
        systemctl restart "$service" || true
    fi
    echo "daemon deployment failed; previous binary restored" >&2
    exit 1
}

trap rollback ERR
cp --preserve=all "$live_binary" "$backup_binary"
install -o root -g root -m 0755 "$staged_binary" "$next_binary"
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F "$next_binary" "$backup_binary"
fi
mv -f "$next_binary" "$live_binary"
replaced=true
systemctl restart "$service"

for _ in {1..90}; do
    if systemctl is-active --quiet "$service"; then
        service_pid=$(systemctl show "$service" -p MainPID --value)
        if [[ "$service_pid" != 0 ]] &&
            journalctl _PID="$service_pid" -b --no-pager -o cat |
                grep -q '^ready via '; then
            replaced=false
            trap - ERR
            sha256sum "$live_binary"
            systemctl show "$service" \
                -p ActiveState -p SubState -p MainPID -p NRestarts
            exit 0
        fi
    fi
    sleep 1
done

echo "new daemon did not become ready within 90 seconds" >&2
false
