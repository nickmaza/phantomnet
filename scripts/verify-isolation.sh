#!/usr/bin/env bash
# Verify decoys cannot initiate connections out of the deception zone.
#
# Probes are launched from INSIDE each decoy container. Every probe must fail
# with a timeout or "unreachable". A refused connection means a packet reached
# the target and got an answer, so it counts as a failure too.
#
#   VERIFY_TARGETS="10.77.10.1:22 192.168.1.20:443" sudo -E scripts/verify-isolation.sh
#
# Writes data/state/isolation_check.json for the dashboard.
set -euo pipefail
cd "$(dirname "$0")/.."

GATEWAY=$(docker network inspect phantomnet_decoy-net -f '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null || echo "")
DEFAULT_TARGETS="1.1.1.1:443 8.8.8.8:53 ${GATEWAY:+$GATEWAY:22} ${GATEWAY:+$GATEWAY:8800}"
TARGETS="${VERIFY_TARGETS:-} $DEFAULT_TARGETS"

PROBE='
import socket, sys
host, port = sys.argv[1].rsplit(":", 1)
s = socket.socket(); s.settimeout(3)
try:
    s.connect((host, int(port))); print("CONNECTED")
except socket.timeout: print("timeout")
except ConnectionRefusedError: print("REFUSED")
except OSError as e: print("unreachable" if e.errno in (101, 113) else f"error:{e.errno}")
'

passed=true
results=()
for svc in phantomnet-web phantomnet-decoys; do
  for t in $TARGETS; do
    r=$(docker compose exec -T "$svc" python -c "$PROBE" "$t" 2>/dev/null | tr -d '\r' || echo "exec-failed")
    case "$r" in
      timeout|unreachable|error:*) verdict=blocked ;;
      *) verdict=REACHABLE; passed=false ;;
    esac
    printf '%-20s -> %-22s %-12s %s\n' "$svc" "$t" "$r" "$verdict"
    results+=("{\"target\":\"$svc -> $t\",\"result\":\"$r ($verdict)\"}")
  done
done

json=$(printf '%s,' "${results[@]}"); json="[${json%,}]"
out=data/state/isolation_check.json
printf '{"checked_at":"%s","passed":%s,"results":%s}\n' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$passed" "$json" > "$out.tmp"
chmod 644 "$out.tmp"; mv "$out.tmp" "$out"

if $passed; then echo "PASS: no outbound path from decoys"; else echo "FAIL: decoys can reach at least one target" >&2; exit 1; fi
