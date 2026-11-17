# Network design and isolation

## Zones

| Zone | Example subnet | Purpose |
|---|---|---|
| Management | 10.77.10.0/24 | Administrators, dashboard tunnel, monitoring |
| Deception | 10.77.30.0/24 | Decoy addresses and exposed decoy services |
| Production | existing | Real systems — unchanged |

These are example ranges. The installer checks `DECOY_SUBNET` against existing
routes; coordinate the real values with your network team.

> Note: `DECOY_SUBNET` is the *Docker bridge* subnet behind the decoys on the
> PhantomNet host. The address attackers see is `DECOY_BIND_IP`, which should
> sit in your deception VLAN.

## Required rules — enforce on the router/firewall

Docker networks and host rules are defense in depth, **not** a substitute for
network segmentation.

| # | From | To | Action |
|---|---|---|---|
| 1 | Approved client networks | `DECOY_BIND_IP` : decoy ports | Allow |
| 2 | Deception zone | Production | **Deny** (new connections) |
| 3 | Deception zone | Management | **Deny** |
| 4 | Deception zone | Internet | **Deny**, except explicit update/alert paths |
| 5 | Management | PhantomNet host SSH (management interface) | Allow |
| 6 | Anything else | PhantomNet host management / dashboard | Deny |

The dashboard listens only on `127.0.0.1:8800` on the host. Reach it with an
SSH tunnel or a VPN into the management network. Never publish it.

## Host-level rules (`scripts/apply-isolation.sh`)

| Bridge | Policy |
|---|---|
| `pn-decoy0` (decoys) | Replies to inbound connections only. Every NEW outbound flow — to production, management, internet, or the host — is dropped and rate-limit logged (`phantomnet-decoy-egress:`) |
| `pn-backend0` (web ↔ controller) | Docker `internal: true` — no external connectivity |
| `pn-alert0` (core) | DNS + TCP 443/465/587 to public addresses only; private ranges denied. Set `ALERT_EGRESS_CIDRS` to restrict to your webhook/SMTP endpoints |

Rules live in the chains `PHANTOMNET-FWD` (from `DOCKER-USER`) and
`PHANTOMNET-IN` (from `INPUT`). The installer adds the
`phantomnet-isolation.service` unit so they return after a reboot.

## What the containers can reach

| Container | Networks | Can initiate |
|---|---|---|
| phantomnet-decoys | decoy-net | nothing (dropped) |
| phantomnet-web | decoy-net, backend-net | nothing outside (dropped); listens for controller health on backend-net |
| phantomnet-controller | backend-net | web decoy health endpoint only |
| phantomnet-core | alert-net | webhook / SMTP only |

The core shares no network with any decoy and reads decoy events from a
read-only volume. A compromised decoy can't reach the dashboard or database.

## Do not

- rotate or spoof production addresses, or use random public IPs;
- use `network_mode: host` (OpenCanary's sample compose does — PhantomNet
  replaces it with bridge networking);
- expose the Docker socket to any PhantomNet container;
- put real credentials, personal data, or production databases in a decoy.

## v0.2 preview — decoy IP pools

A reserved pool of private aliases on the deception VLAN, rotated between decoy
services via a separate, allowlisted privileged helper. This needs reserved
addresses, conflict detection, and coordination with network administrators,
and is intentionally not part of v0.1.
