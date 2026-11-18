"""Cloud console: accounts, terminal commands, sensor enrollment and sync.

The sensor's real CloudSync talks to the console's real FastAPI app in-process
(TestClient is an httpx.Client), with in-memory auth and storage.
"""
import importlib.util
import json
import re
import sys
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from detection.alerts import AlertDispatcher, AlertSettings
from detection.cloud import CloudSync
from detection.correlator import Correlator
from detection.policy import load_policy
from detection.schema import iso, make_event

ANSI = re.compile(r"\x1b\[[0-9;]*m")


@pytest.fixture(scope="module")
def console_mod(root):
    sys.path.insert(0, str(root / "console"))
    spec = importlib.util.spec_from_file_location("pn_console_app", root / "console" / "app.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def root():
    from pathlib import Path
    return Path(__file__).resolve().parents[1]


@pytest.fixture
def console(console_mod):
    from pnconsole.auth import MemoryAuth
    from pnconsole.store import MemoryStore
    st = MemoryStore()
    client = TestClient(console_mod.create_app(st, MemoryAuth()))
    client.store = st
    return client


def signup(client, email="ana@example.com", pw="correct-horse-1"):
    r = client.post("/api/auth/signup", json={"email": email, "password": pw})
    assert r.status_code == 200, r.text
    return {"Authorization": "Bearer " + r.json()["access_token"]}


def run(client, h, line, sensor=None):
    r = client.post("/api/command", json={"line": line, "sensor": sensor}, headers=h)
    assert r.status_code == 200, r.text
    d = r.json()
    d["text"] = ANSI.sub("", d["output"])
    return d


def add_sensor(client, h, name="office"):
    d = run(client, h, f"sensor add {name}")
    code = re.search(r"PN-[0-9A-F-]{20,}", d["text"]).group(0)
    return code


# ---------------------------------------------------------------------------

def test_auth_required_and_login(console):
    assert console.post("/api/command", json={"line": "help"}).status_code == 401
    signup(console)
    assert console.post("/api/auth/login", json={"email": "ana@example.com", "password": "nope"}).status_code == 400
    r = console.post("/api/auth/login", json={"email": "ana@example.com", "password": "correct-horse-1"})
    assert r.status_code == 200 and r.json()["access_token"]
    assert console.get("/").status_code == 200 and "PhantomNet" in console.get("/").text


def test_help_and_unknown_command(console):
    h = signup(console)
    assert "incidents" in run(console, h, "help")["text"]
    d = run(console, h, "incidnets")
    assert not d["ok"] and "did you mean" in d["text"]


def test_sensor_enrollment_is_single_use(console):
    h = signup(console)
    code = add_sensor(console, h)
    r = console.post("/api/sensor/enroll", json={"code": code})
    assert r.status_code == 200 and r.json()["token"].startswith("pns_")
    assert console.post("/api/sensor/enroll", json={"code": code}).status_code == 401
    assert "online" in run(console, h, "sensors")["text"]


def test_expired_enrollment_code_rejected(console):
    h = signup(console)
    code = add_sensor(console, h)
    s = next(iter(console.store.sensors.values()))
    s["enroll_expires_at"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    r = console.post("/api/sensor/enroll", json={"code": code})
    assert r.status_code == 401 and "expired" in r.json()["error"]


def test_config_validation(console):
    h = signup(console)
    add_sensor(console, h)
    assert "✓" in run(console, h, "config set rotation.interval_max_minutes 2h")["text"]
    bad = run(console, h, "config set rotation.interval_min_minutes 3000")
    assert not bad["ok"] and "between" in bad["text"]
    assert not run(console, h, "alerts webhook http://insecure.example")["ok"]
    assert "host runs" in run(console, h, "decoys disable mysql")["text"]
    assert not run(console, h, "config set nope.key 1")["ok"]
    shown = run(console, h, "config show rotation")["text"]
    assert "120" in shown


def test_secrets_masked_and_not_in_audit(console):
    h = signup(console)
    add_sensor(console, h)
    url = "https://hooks.slack.com/services/T000/B000/SECRETSECRETSECRET"
    run(console, h, f"alerts webhook {url}")
    assert "SECRETSECRET" not in run(console, h, "alerts")["text"]
    assert all("SECRET" not in a["command"] for a in console.store.audit)


def test_users_cannot_see_each_other(console):
    ha = signup(console, "a@example.com")
    hb = signup(console, "b@example.com")
    add_sensor(console, ha, "alpha")
    assert "no sensors" in run(console, hb, "sensors")["text"]
    assert not run(console, hb, "use alpha")["ok"]
    sid = next(iter(console.store.sensors))
    console.store.upsert_incidents(sid, [{"local_id": 1, "source_ip": "192.0.2.1", "severity": "high",
                                         "score": 90, "first_seen": "2026-11-18T00:00:00+00:00",
                                         "last_seen": "2026-11-18T00:01:00+00:00"}])
    assert not run(console, hb, "incident 1")["ok"]
    assert not run(console, hb, "ack 1")["ok"]
    assert run(console, ha, "incident 1")["ok"]


def test_sensor_token_required_for_sync(console):
    assert console.post("/api/sensor/sync", json={}).status_code == 401
    assert console.post("/api/sensor/sync", json={}, headers={"Authorization": "Bearer pns_bogus"}).status_code == 401


# ---------------------------------------------------------------------------

def attack(store, policy):
    c = Correlator(store, policy)
    t0 = datetime(2026, 11, 18, 14, 30, tzinfo=timezone.utc)
    for i, (svc, et, user) in enumerate([("http", "http_request", None),
                                         ("ssh", "authentication_attempt", "root"),
                                         ("mysql", "authentication_attempt", "sa")]):
        c.process(make_event(timestamp=iso(t0 + timedelta(seconds=10 * i)), source_ip="192.0.2.45",
                             destination_service=svc, event_type=et, username=user, source="test",
                             details={"password": "hunter2-secret"} if user else {}))


def test_full_sensor_sync_loop(console, store, policy, tmp_path):
    h = signup(console)
    code = add_sensor(console, h, "lab")
    state = tmp_path / "state"
    state.mkdir()
    (state / "active_profile.json").write_text(json.dumps({"profile_id": "storage-server"}))
    disp = AlertDispatcher(store, policy, AlertSettings())
    sync = CloudSync("http://testserver", store, disp, state, enroll_code=code,
                     managed=tmp_path / "managed", client=console)

    attack(store, policy)
    assert sync.sync_once()                         # enrolls, pushes incident, pulls config
    assert (tmp_path / "managed" / "cloud.json").exists()
    out = run(console, h, "incidents")["text"]
    assert "HIGH" in out and "192.0.2.45" in out
    inc_id = re.search(r"#(\d+)", out).group(1)
    detail = run(console, h, f"incident {inc_id}")["text"]
    assert "SUGGESTED RESPONSE" in detail
    assert "hunter2" not in json.dumps(console.store.incidents, default=str)
    assert "storage-server" in run(console, h, "status")["text"]

    # unchanged incidents are not re-sent
    pushed_before = len(sync.changed_incidents()[0])
    assert pushed_before == 0

    # settings flow console -> sensor and are re-validated into the policy
    run(console, h, "honeytokens add svc_backup")
    run(console, h, "scanners allow 10.0.5.0/24")
    assert sync.sync_once()
    cfg = json.loads((tmp_path / "managed" / "config.json").read_text())
    assert "svc_backup" in cfg["config"]["honeytokens"]
    p = load_policy()
    assert "svc_backup" in p.honeytoken_usernames and p.is_authorized_scanner("10.0.5.9")

    # incident workflow
    assert "acknowledged" in run(console, h, f"ack {inc_id} looking into it")["text"]
    sync.sync_once()  # a sensor update must not reset the console status
    assert console.store.get_incident(int(inc_id))["status"] == "acknowledged"
    exp = run(console, h, f"export {inc_id}")
    assert exp["download"]["filename"].endswith(".json") and "hunter2" not in exp["download"]["content"]


def test_actions_round_trip(console, store, policy, tmp_path):
    h = signup(console)
    code = add_sensor(console, h, "lab")
    state = tmp_path / "state"
    state.mkdir()
    managed = tmp_path / "managed"
    sync = CloudSync("http://testserver", store, AlertDispatcher(store, policy, AlertSettings()),
                     state, enroll_code=code, managed=managed, client=console)
    sync.sync_once()

    run(console, h, "persona rotate admin-portal")
    run(console, h, "alerts test")
    sync.sync_once()                                  # receives both actions
    req = managed / "requests"
    [rf] = list(req.glob("rotate-*.json"))
    rid = json.loads(rf.read_text())["id"]
    # controller would write this:
    (state / "action_results").mkdir()
    (state / "action_results" / f"{rid}.json").write_text(json.dumps(
        {"id": rid, "status": "done", "result": {"rotated": True, "active": "admin-portal"}}))
    sync.sync_once()                                  # reports both results
    acts = {a["kind"]: a for a in console.store.actions.values()}
    assert acts["rotate"]["status"] == "done" and acts["rotate"]["result"]["active"] == "admin-portal"
    assert acts["alert_test"]["status"] == "done"
    assert "no webhook" in acts["alert_test"]["result"]["error"]
    assert not list(req.glob("rotate-*.json"))        # request cleaned up
    assert "done" in run(console, h, "actions")["text"]


def test_removed_sensor_loses_access(console, store, policy, tmp_path):
    h = signup(console)
    code = add_sensor(console, h, "lab")
    sync = CloudSync("http://testserver", store, None, tmp_path, enroll_code=code,
                     managed=tmp_path / "m", client=console)
    assert sync.sync_once()
    run(console, h, "sensor remove lab --yes")
    assert sync.sync_once() is False
    assert not (tmp_path / "m" / "cloud.json").exists()


def test_cloud_url_must_be_https(store, tmp_path):
    with pytest.raises(ValueError):
        CloudSync("http://evil.example", store, None, tmp_path, managed=tmp_path / "m")
