# Hardening and safe operation

A honeypot that gets compromised and can then reach real systems makes an
organization *less* safe. These are the controls PhantomNet ships with and the
ones you must add.

## Container defaults (compose.yaml)

- No privileged containers, `cap_drop: [ALL]`, no added capabilities.
- `no-new-privileges`, read-only root filesystems, tmpfs for scratch space.
- All processes run as UID/GID 10001.
- CPU, memory, and PID limits on every service.
- No `network_mode: host`, no Docker socket mounts.
- Log rotation on container stdout (10 MB × 3).

## Separation of duties

| Component | Can write | Cannot |
|---|---|---|
| Decoys | their own event log | read state, reach core, initiate egress |
| Controller | decoy state file + controller log | touch Docker, firewall, or production |
| Core | SQLite database | write decoy logs or state; talk to decoys |

## Data handling

- PhantomNet's database, dashboard, alerts, and exports never contain passwords
  typed into decoys — only their length. The web decoy never writes them at all.
- **Exception:** OpenCanary writes its own raw log (`data/events/opencanary.log`)
  *before* PhantomNet redacts anything, and that file does contain attempted
  SSH/MySQL passwords. Treat `data/events/` as sensitive: keep it root/UID-10001
  only, exclude it from backups that leave the host, and rotate it (for
  example with logrotate `copytruncate`; the collector re-reads a truncated
  file from the start).
- Keys matching password/secret/token/key/cookie/session/hash are redacted
  recursively; URL query parameters with such names are masked.
- Strings are truncated (256 chars) and stripped of control characters.
- Alerts and exports contain only redacted events.
- Usernames attempted against decoys *are* kept, as intelligence. If an
  employee types their real username into a decoy by mistake, that's a signal
  worth following up, not a leak of a secret.

## Honeytokens

`policies.yaml → honeytokens.usernames` lists fake account names planted in
decoy content (HTML comments, robots.txt). They must never be real accounts.
Profile validation rejects anything that looks like an embedded secret.

## Dashboard

- Loopback only; HTTP Basic auth with a ≥ 12 character password from `.env`.
- Strict security headers, no API docs exposed.
- Use an SSH tunnel or VPN. For TLS on a shared admin network, put a reverse
  proxy with TLS in front of the tunnel endpoint.

## Your responsibilities

- Enforce zone isolation on the network firewall ([NETWORK.md](NETWORK.md)).
- Keep the host patched; pin and update container base images deliberately.
- Run `scripts/verify-isolation.sh` after every change and on a schedule.
- Add authorized scanners to `policies.yaml` so they don't raise incidents.
- Review alerts before acting; PhantomNet never blocks anyone automatically.
