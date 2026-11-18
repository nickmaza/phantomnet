#!/usr/bin/env bash
# Apply console-managed settings that change ports/bindings (run as root on the
# sensor host). Containers can't do this themselves by design: they have no
# Docker socket and no host privileges.
#
#   sudo scripts/apply-managed-config.sh            # apply if changed
#   sudo scripts/apply-managed-config.sh --dry-run  # show what would change
#
# Safe to run from cron/systemd every few minutes; it does nothing when the
# settings already match.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ $EUID -eq 0 || "${1:-}" == "--dry-run" ]] || { echo "run as root (sudo)" >&2; exit 1; }
CFG=data/managed/config.json
[[ -f "$CFG" ]] || { echo "no console settings yet ($CFG missing) — nothing to do"; exit 0; }

python3 - "$CFG" "${1:-}" <<'PY'
import ipaddress, json, re, subprocess, sys
from pathlib import Path

cfg = json.loads(Path(sys.argv[1]).read_text())["config"]
dry = sys.argv[2] == "--dry-run"

def port(k, d):
    v = cfg.get(k, d)
    return v if isinstance(v, int) and 1 <= v <= 65535 else d

bind = str(cfg.get("decoys.bind_ip", "127.0.0.1"))
ipaddress.ip_address(bind)  # raises on garbage
want_env = {
    "DECOY_BIND_IP": bind,
    "DECOY_SSH_PORT": str(port("decoys.ssh_port", 2222)),
    "DECOY_HTTP_PORT": str(port("decoys.http_port", 8080)),
    "DECOY_MYSQL_PORT": str(port("decoys.mysql_port", 33060)),
}
if bind != "127.0.0.1":
    assigned = subprocess.run(["ip", "-4", "-o", "addr"], capture_output=True, text=True).stdout
    if f"inet {bind}/" not in assigned:
        sys.exit(f"refusing: {bind} is not assigned to this host (add it in netplan first)")

env_path = Path(".env")
env = env_path.read_text().splitlines()
changed = []
for k, v in want_env.items():
    for i, line in enumerate(env):
        if line.startswith(k + "="):
            if line != f"{k}={v}":
                env[i] = f"{k}={v}"; changed.append(f"{k}={v}")
            break
    else:
        env.append(f"{k}={v}"); changed.append(f"{k}={v}")

oc_path = Path("config/opencanary.conf")
oc = json.loads(oc_path.read_text())
for svc in ("ssh", "mysql"):
    want = bool(cfg.get(f"decoys.{svc}", True))
    if oc.get(f"{svc}.enabled") != want:
        oc[f"{svc}.enabled"] = want; changed.append(f"{svc}.enabled={want}")

http_on = bool(cfg.get("decoys.http", True))
state = Path("data/state/http_decoy_enabled")
if (state.read_text().strip() if state.exists() else "true") != str(http_on).lower():
    changed.append(f"http decoy={'on' if http_on else 'off'}")

if not changed:
    print("settings already applied"); sys.exit(0)
print("changes:", ", ".join(changed))
if dry:
    sys.exit(0)
env_path.write_text("\n".join(env) + "\n")
oc_path.write_text(json.dumps(oc, indent=4) + "\n")
state.write_text(str(http_on).lower())
subprocess.run(["docker", "compose", "up", "-d"], check=True)
if not http_on:
    subprocess.run(["docker", "compose", "stop", "phantomnet-web"], check=True)
print("applied.")
PY

# Re-apply host isolation if decoys moved to a network address.
if [[ "${1:-}" != "--dry-run" ]] && grep -q '^DECOY_BIND_IP=' .env && ! grep -q '^DECOY_BIND_IP=127.0.0.1$' .env; then
  scripts/apply-isolation.sh >/dev/null && echo "isolation rules re-applied"
fi
