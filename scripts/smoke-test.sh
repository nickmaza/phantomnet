#!/usr/bin/env bash
# Authorized test client: touch every decoy so you can confirm events,
# correlation, and alerts. Run ONLY against your own PhantomNet sensor.
#
#   scripts/smoke-test.sh <decoy-ip> [ssh-port] [http-port] [mysql-port]
set -uo pipefail
HOST=${1:?usage: smoke-test.sh <decoy-ip> [ssh-port] [http-port] [mysql-port]}
SSH_PORT=${2:-2222}; HTTP_PORT=${3:-8080}; MYSQL_PORT=${4:-33060}

echo "[http] GET /"
curl -s -o /dev/null -w "  status %{http_code}, server: %header{server}\n" "http://$HOST:$HTTP_PORT/" || true
echo "[http] GET /robots.txt"
curl -s "http://$HOST:$HTTP_PORT/robots.txt" | sed 's/^/  /' || true
echo "[http] POST /login (honeytoken user svc_deploy, dummy password)"
curl -s -o /dev/null -w "  status %{http_code}\n" -d "username=svc_deploy&password=not-a-real-password" \
  "http://$HOST:$HTTP_PORT/login" || true

echo "[ssh] banner + login attempt"
if command -v sshpass >/dev/null; then
  sshpass -p 'not-a-real-password' ssh -p "$SSH_PORT" -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=password \
    -o ConnectTimeout=5 root@"$HOST" true 2>&1 | head -2 | sed 's/^/  /'
else
  timeout 5 bash -c "exec 3<>/dev/tcp/$HOST/$SSH_PORT; head -c 64 <&3" 2>/dev/null | sed 's/^/  /'
  echo "  (install sshpass to also generate an SSH authentication attempt)"
fi

echo "[mysql] login attempt"
if command -v mysql >/dev/null; then
  mysql -h "$HOST" -P "$MYSQL_PORT" -u root -pnot-a-real-password --connect-timeout=5 -e 'select 1' 2>&1 | head -1 | sed 's/^/  /'
else
  timeout 5 bash -c "exec 3<>/dev/tcp/$HOST/$MYSQL_PORT; head -c 32 <&3" 2>/dev/null | tr -cd '[:print:]\n' | sed 's/^/  /'; echo
  echo "  (install mysql-client to also generate a MySQL authentication attempt)"
fi

echo
echo "Done. Within a few seconds the dashboard should show ONE correlated incident for this client."
