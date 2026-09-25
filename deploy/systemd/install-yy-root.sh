#!/usr/bin/env bash
# Install a staged ARM64 binary and repurpose the existing center unit as yy.
# Example: install-yy-root.sh /tmp/tmp-proxy-deploy.ABC123 -> running yy service.
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "install-yy-root.sh must run as root" >&2
    exit 1
fi

if [[ "$#" -ne 1 || ! -d "$1" ]]; then
    echo "usage: install-yy-root.sh <staging-directory>" >&2
    exit 1
fi

staging_dir=$1
for staged_file in \
    tmp-proxy \
    tmp-proxy-yy-start \
    tmp-proxy-center.service \
    cfp-yy-config.yaml \
    cfp-env; do
    if [[ ! -f "$staging_dir/$staged_file" ]]; then
        echo "staged file is missing: $staged_file" >&2
        exit 1
    fi
done

bash -n "$staging_dir/tmp-proxy-yy-start"
file "$staging_dir/tmp-proxy" | grep -q 'ELF 64-bit.*ARM aarch64'

install -d -o root -g root -m 0755 /etc/cfp
install -o root -g root -m 0600 "$staging_dir/cfp-env" /etc/cfp/env
install -o root -g root -m 0644 "$staging_dir/cfp-yy-config.yaml" /etc/cfp/config.yaml

# Trigger: the running center owns port 9010 and uses the binary being replaced.
# It cannot coexist with yy or safely retain the old executable mapping.
# Prevent regression: stop it only after every staged artifact passes validation.
systemctl stop tmp-proxy-center.service
install -o root -g root -m 0755 "$staging_dir/tmp-proxy" /usr/local/bin/tmp-proxy
install -o root -g root -m 0755 \
    "$staging_dir/tmp-proxy-yy-start" \
    /usr/local/bin/tmp-proxy-yy-start
install -o root -g root -m 0644 \
    "$staging_dir/tmp-proxy-center.service" \
    /etc/systemd/system/tmp-proxy-center.service
systemctl daemon-reload
systemctl start tmp-proxy-center.service
