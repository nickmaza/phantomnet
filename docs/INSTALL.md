# Installing PhantomNet v0.1

## 1. Host

| | Recommended (MVP target, not measured) |
|---|---|
| OS | Ubuntu Server 24.04 LTS, clean install, dedicated machine or VM |
| CPU / RAM | 4 cores / 8 GB |
| Disk | 40–80 GB SSD |
| Network | 1 NIC; a second NIC or dedicated VLAN for the decoy zone is preferred |

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y git curl jq nftables iptables iproute2 python3 python3-venv python3-pip
```

Install Docker Engine and the Compose plugin with the
[official Ubuntu instructions](https://docs.docker.com/engine/install/ubuntu/), then:

```bash
sudo docker --version
sudo docker compose version
sudo systemctl status docker
```

Optional but recommended — preserve real client source IPs for traffic arriving
from other hosts and avoid the userland proxy, in `/etc/docker/daemon.json`:

```json
{ "userland-proxy": false }
```

(Connections made from the PhantomNet host itself to `127.0.0.1` will appear
to come from the Docker bridge gateway — that is expected during local tests.)

## 2. Install

```bash
sudo git clone <your-fork-url> /opt/phantomnet
cd /opt/phantomnet
sudo scripts/install.sh
```

The installer:

1. creates `.env` from `.env.example` with a random dashboard password,
2. checks that `DECOY_SUBNET` (default `10.77.30.0/24`) doesn't overlap existing routes,
3. creates `data/` owned by UID 10001 (the unprivileged container user),
4. builds and starts the four containers,
5. applies host isolation rules if decoys are bound to a non-loopback address.

## 3. Local verification (decoys on 127.0.0.1)

```bash
scripts/smoke-test.sh 127.0.0.1
ssh -L 8800:127.0.0.1:8800 <you>@<phantomnet-host>    # from your workstation
```

Open http://127.0.0.1:8800 and sign in with `PN_ADMIN_USER` / `PN_ADMIN_PASSWORD`.

## 4. Go live on the decoy network

1. Reserve a decoy address with your network team (see [NETWORK.md](NETWORK.md)).
2. Assign it to the host (netplan) and set `DECOY_BIND_IP` in `.env`.
3. Optionally use standard ports: `DECOY_SSH_PORT=22`, `DECOY_HTTP_PORT=80`,
   `DECOY_MYSQL_PORT=3306` — only if the host's own sshd listens on a different
   address (management interface).
4. `sudo docker compose up -d && sudo scripts/apply-isolation.sh`
5. `sudo scripts/verify-isolation.sh`
6. Apply the matching rules on the router/firewall.
7. Run the acceptance tests in [TESTING.md](TESTING.md) from a separate test VM.

## Operations

| Task | Command |
|---|---|
| Status | `sudo docker compose ps` |
| Logs | `sudo docker compose logs -f phantomnet-core` |
| Rotate web persona now | `sudo scripts/rotate-now.sh [profile-id]` |
| Verify isolation | `sudo scripts/verify-isolation.sh` |
| Update | `git pull && sudo docker compose build && sudo docker compose up -d` |

## Removal

```bash
sudo scripts/uninstall.sh            # stop, remove containers and isolation rules; keep evidence
sudo scripts/uninstall.sh --purge    # also delete data/ and images (asks first)
```

Removing PhantomNet doesn't touch production routing, so real traffic is unaffected.
