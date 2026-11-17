#!/usr/bin/env bash
# PhantomNet v0.1 installer for Ubuntu Server 24.04 LTS.
# Run from the repository root:  sudo scripts/install.sh
set -euo pipefail
cd "$(dirname "$0")/.."

[[ $EUID -eq 0 ]] || { echo "run as root (sudo scripts/install.sh)" >&2; exit 1; }

say() { printf '\n==> %s\n' "$*"; }

say "Checking host"
. /etc/os-release
[[ "${ID:-}" == "ubuntu" ]] || echo "warning: tested on Ubuntu 24.04; found ${PRETTY_NAME:-unknown}"
command -v docker >/dev/null || { echo "Docker Engine not found. Install it from https://docs.docker.com/engine/install/ubuntu/" >&2; exit 1; }
docker compose version >/dev/null || { echo "Docker Compose plugin not found" >&2; exit 1; }
for bin in iptables ip jq curl; do command -v "$bin" >/dev/null || { echo "missing $bin (apt install -y nftables iptables iproute2 jq curl)" >&2; exit 1; }; done

say "Preparing .env"
if [[ ! -f .env ]]; then
  cp .env.example .env
  pw=$(head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 24)
  sed -i "s|^PN_ADMIN_PASSWORD=.*|PN_ADMIN_PASSWORD=${pw}|" .env
  chmod 600 .env
  echo "Generated dashboard password in .env (PN_ADMIN_PASSWORD)."
fi
set -a; . ./.env; set +a

say "Checking for address conflicts with ${DECOY_SUBNET:-10.77.30.0/24}"
subnet=${DECOY_SUBNET:-10.77.30.0/24}
prefix=${subnet%.*}
if ip -4 route | grep -v "pn-decoy0" | grep -q "^${prefix}\."; then
  echo "conflict: $subnet overlaps an existing route:" >&2
  ip -4 route | grep "^${prefix}\." >&2
  echo "Set DECOY_SUBNET in .env to an unused private range." >&2
  exit 1
fi
if [[ "${DECOY_BIND_IP:-127.0.0.1}" != "127.0.0.1" ]] && ! ip -4 addr | grep -q "inet ${DECOY_BIND_IP}/"; then
  echo "DECOY_BIND_IP=${DECOY_BIND_IP} is not assigned to this host." >&2; exit 1
fi

say "Creating data directories"
mkdir -p data/events data/state data/db
chown -R 10001:10001 data
chmod 750 data/db

say "Building images"
docker compose build

say "Starting PhantomNet"
docker compose up -d
sleep 5
docker compose ps

if [[ "${DECOY_BIND_IP:-127.0.0.1}" != "127.0.0.1" ]]; then
  say "Applying host isolation rules"
  scripts/apply-isolation.sh
  install -m 644 scripts/systemd/phantomnet-isolation.service /etc/systemd/system/
  sed -i "s|@ROOT@|$(pwd)|g" /etc/systemd/system/phantomnet-isolation.service
  systemctl daemon-reload
  systemctl enable phantomnet-isolation.service
else
  echo "Decoys bound to 127.0.0.1 (local testing). Apply isolation before binding to a network address."
fi

cat <<EOF

PhantomNet is running.
  Decoys:    ssh ${DECOY_BIND_IP:-127.0.0.1}:${DECOY_SSH_PORT:-2222}  http :${DECOY_HTTP_PORT:-8080}  mysql :${DECOY_MYSQL_PORT:-33060}
  Dashboard: http://127.0.0.1:${DASHBOARD_PORT:-8800}  (user ${PN_ADMIN_USER:-admin}, password in .env)
             From your workstation:  ssh -L 8800:127.0.0.1:${DASHBOARD_PORT:-8800} <admin>@<this-host>

Next steps: docs/TESTING.md (acceptance tests) and docs/NETWORK.md (firewall rules).
EOF
