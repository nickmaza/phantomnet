# Acceptance tests — PhantomNet v0.1

Run from a **second Linux VM on an isolated test segment** acting as the
authorized test client. Publish only components that pass.

## Automated tests (no Docker needed)

```bash
pip install -r requirements-dev.txt
pytest -q
```

These cover redaction, OpenCanary normalization, scoring, cross-decoy
correlation, deduplication, window expiry, authorized-scanner suppression,
alert escalation, atomic rotation with rollback, the live web decoy (HTTP
server on loopback), and dashboard authentication.

## Release checklist

| # | Test | How | Pass when |
|---|---|---|---|
| 1 | SSH, HTTP, DB decoys respond | `scripts/smoke-test.sh <decoy-ip>` | SSH banner, HTTP 200 login page, MySQL handshake |
| 2 | Interactions generate events | dashboard → Activity, or `GET /api/events` | events for ssh, http, mysql with the test VM's IP |
| 3 | Several decoys → one incident | same smoke test | one incident, services = http, mysql, ssh; `multi_decoy` finding |
| 4 | Web rotation works and is recorded | `scripts/rotate-now.sh storage-server`; `curl -I http://<decoy>:8080/` | `Server: lighttpd/…`; "Decoy profile rotated" in timeline |
| 5 | Failed rotation rolls back, others unaffected | `pytest tests/test_rotator.py -k rollback`; live: see below | rollback event; SSH/MySQL keep answering |
| 6 | Decoys can't reach production/management | `VERIFY_TARGETS="<prod-ip>:443 <mgmt-ip>:22" sudo -E scripts/verify-isolation.sh` | every probe `timeout`/`unreachable`; PASS |
| 7 | Dashboard needs approved admin access | from the test VM: `curl http://<host>:8800/`; on host: `curl http://127.0.0.1:8800/` | test VM: connection fails; host without creds: 401 |
| 8 | No secrets in exported alerts | after smoke test: `GET /api/incidents/<id>/export`, grep for the test password | password absent; only `password_length` |
| 9 | Stopping PhantomNet doesn't affect real traffic | `docker compose down` while pinging/curling production services | no change in production reachability or latency |
| 10 | Clean-VM install succeeds | fresh Ubuntu 24.04 VM → `scripts/install.sh` | all four containers `running`; checks 1–3 pass |

### Live rollback test (5)

```bash
# Make the web decoy fail its health check, attempt a rotation, and confirm
# the controller restores the previous profile.
sudo docker compose stop phantomnet-web
sudo scripts/rotate-now.sh linux-server; echo "exit=$?"   # expect exit=1 (rolled back, decoy down)
sudo docker compose start phantomnet-web
nc -vz <decoy-ip> 2222 && nc -vz <decoy-ip> 33060        # protocol decoys unaffected
```

The dashboard shows "Profile rotation failed — rolled back".

## Also measure

- **Alert latency** — time from the smoke test to the webhook arriving
  (collector polls every 2 s).
- **False positives** — run a week alongside normal administration; tune
  `authorized_scanners` and scores.
- **Log continuity** — restart each container and rotate profiles mid-test;
  event counts must keep rising with no duplicates (offsets are persisted).
