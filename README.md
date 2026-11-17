# PhantomNet

**Linux network deception and moving-target defense platform — v0.1 (experimental)**

PhantomNet attaches to an existing network as a sensor. It presents convincing
fake servers, rotates the identity of those fakes so reconnaissance goes stale,
and correlates every touch on a decoy into incidents that defenders can act on.

It does **not** intercept, reroute, or hide real traffic. Production routing,
addresses, and firewalls stay exactly as they are. Stopping PhantomNet has no
effect on real applications.

| Layer | What it does in v0.1 |
|---|---|
| Network deception | Simulated SSH and MySQL (OpenCanary) plus a simulated admin web portal |
| Moving-target defense | The web decoy's persona (branding, `Server` header, robots.txt, breadcrumbs) rotates every 30–60 min, atomically, with health-checked rollback |
| Honeynet monitoring | Collector → redaction → per-source correlation → risk scoring → webhook/email alerts → dashboard |

## What it promises — and what it doesn't

PhantomNet helps you **detect** intrusions early by giving attackers false
targets that no legitimate user should ever touch.

It does **not** make your network invisible, guarantee attackers can't find
real servers, or replace firewalls, patching, or EDR. Moving-target behavior in
v0.1 applies to decoy identities only — never production addresses.

## Architecture

```
 attacker / suspicious client
            │
   existing router + firewall  ── production routing unchanged ──►  real network
            │
            ▼  (only traffic aimed at decoy addresses)
 ┌────────────────────────── PhantomNet host ──────────────────────────┐
 │ decoy-net (no egress)          backend-net (internal)   alert-net   │
 │  phantomnet-decoys  SSH, MySQL                                       │
 │  phantomnet-web     rotating portal ◄── health ── phantomnet-controller
 │        │ JSON event logs (shared volume, read-only to core)          │
 │        ▼                                                             │
 │  phantomnet-core   collector · correlator · alerts · dashboard ──► webhook/email
 └──────────────────────────────────────────────────────────────────────┘
         dashboard on 127.0.0.1 only → SSH tunnel / VPN
```

The core shares **no network** with any decoy; events flow through files the
core can only read. The controller holds no Docker socket and no firewall
rights — it can only rewrite the decoy state file.

## Quick start (Ubuntu Server 24.04)

```bash
sudo apt update && sudo apt install -y git curl jq nftables iptables python3 python3-venv
# Install Docker Engine + Compose plugin: https://docs.docker.com/engine/install/ubuntu/
git clone <your-fork-url> /opt/phantomnet && cd /opt/phantomnet
sudo scripts/install.sh
```

Decoys start bound to `127.0.0.1` (SSH 2222, HTTP 8080, MySQL 33060). Open the
dashboard through a tunnel:

```bash
ssh -L 8800:127.0.0.1:8800 admin@phantomnet-host   # then browse http://127.0.0.1:8800
```

Then follow [docs/TESTING.md](docs/TESTING.md) before you bind decoys to a real
network address ([docs/NETWORK.md](docs/NETWORK.md)).

## Repository layout

```
compose.yaml              four hardened services
config/opencanary.conf    SSH + MySQL simulation settings
config/policies.yaml      rotation schedule, scoring, honeytokens, authorized scanners
config/profiles/*.json    web decoy personas (linux-server, storage-server, admin-portal)
services/decoys/web/      rotating web decoy (stdlib HTTP server)
services/decoys/protocol/ OpenCanary image
controller/               profile validation + rotator
detection/                schema/redaction, collector, correlator, alerts, SQLite store
dashboard/                FastAPI security console
scripts/                  install, uninstall, isolation, verification, smoke test
tests/                    unit + integration tests (pytest)
docs/                     INSTALL, NETWORK, SECURITY, TESTING
```

## Detection scoring (starting hypotheses — tune them)

| Condition | Points |
|---|---|
| Connection to a high-value decoy | +25 |
| Authentication attempt against a decoy | +40 |
| Same source reaches 3 different decoys within 2 minutes | +20 |
| Authentication attempts across multiple decoy services | +15 |
| Use of a planted honeytoken username | +50 |

Each rule fires once per incident. Incidents expire after 30 idle minutes.
Severity: low < 40 ≤ medium < 70 ≤ high. Alerts go out when an incident first
reaches the minimum severity (default `medium`) and again on escalation.
Authorized scanners listed in `policies.yaml` are recorded but never scored.
PhantomNet never blocks anyone automatically.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
pytest -q
```

## Roadmap

- **v0.2** — reserved decoy IP pools on a deception VLAN, simulated network maps,
  more personas and protocols, SIEM integration.
- **v0.3** — optional public-facing gateway / reverse-proxy module.
- **v1.0** — AI-assisted recommendations and incident explanations, always
  subject to explicit policy.

## License

MIT for original PhantomNet code — see [LICENSE](LICENSE). Bundled and
downloaded dependencies keep their own licenses — see
[THIRD_PARTY.md](THIRD_PARTY.md). Security issues: [SECURITY.md](SECURITY.md).
