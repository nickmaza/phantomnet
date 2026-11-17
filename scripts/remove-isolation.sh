#!/usr/bin/env bash
# Remove PhantomNet host isolation chains.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root (sudo)" >&2; exit 1; }
while iptables -D DOCKER-USER -j PHANTOMNET-FWD 2>/dev/null; do :; done
while iptables -D INPUT -j PHANTOMNET-IN 2>/dev/null; do :; done
for c in PHANTOMNET-FWD PHANTOMNET-IN; do
  iptables -F "$c" 2>/dev/null || true
  iptables -X "$c" 2>/dev/null || true
done
echo "PhantomNet isolation rules removed."
