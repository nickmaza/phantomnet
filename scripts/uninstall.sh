#!/usr/bin/env bash
# Stop and remove PhantomNet. Production traffic is unaffected either way.
#   sudo scripts/uninstall.sh           # keep collected evidence in data/
#   sudo scripts/uninstall.sh --purge   # also delete data/ and images
set -euo pipefail
cd "$(dirname "$0")/.."
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }

docker compose down --remove-orphans
if systemctl list-unit-files phantomnet-isolation.service >/dev/null 2>&1; then
  systemctl disable --now phantomnet-isolation.service 2>/dev/null || true
  rm -f /etc/systemd/system/phantomnet-isolation.service
  systemctl daemon-reload
fi
scripts/remove-isolation.sh || true

if [[ "${1:-}" == "--purge" ]]; then
  read -r -p "Delete all collected events, incidents and images? [y/N] " ans
  if [[ "$ans" =~ ^[Yy]$ ]]; then
    rm -rf data/events/* data/state/* data/db/*
    docker image rm phantomnet/app:0.1.0 phantomnet/decoys:0.1.0 2>/dev/null || true
    echo "Purged."
  fi
fi
echo "PhantomNet removed."
