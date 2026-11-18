"""End-to-end: decoy log files -> collector -> correlation -> alerts -> dashboard."""
import base64
import json

import pytest
from fastapi.testclient import TestClient

from dashboard.app import DashboardSettings, create_app
from detection.alerts import AlertDispatcher, AlertSettings
from detection.collector import Collector
from detection.correlator import Correlator

PW = "correct-horse-battery"


def write_lines(path, recs, partial=None):
    with path.open("a", encoding="utf-8") as fh:
        for r in recs:
            fh.write(json.dumps(r) + "\n")
        if partial:
            fh.write(partial)


def oc(logtype, sec, user=None, pw=None):
    data = {"USERNAME": user, "PASSWORD": pw} if user else {}
    return {"logtype": logtype, "src_host": "192.0.2.45", "src_port": 40000 + sec, "dst_port": 2222,
            "utc_time": f"2026-11-18 14:30:{sec:02d}.000000", "node_id": "phantomnet-01", "logdata": data}


@pytest.fixture
def env(tmp_path, store, policy):
    events = tmp_path / "events"; events.mkdir()
    state = tmp_path / "state"; state.mkdir()
    disp = AlertDispatcher(store, policy, AlertSettings())
    col = Collector(events, store, Correlator(store, policy), disp)
    app = create_app(store, DashboardSettings("admin", PW, state_dir=str(state)))
    return events, state, col, TestClient(app)


def auth(user="admin", pw=PW):
    return {"Authorization": "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()}


def test_pipeline_correlates_and_survives_restart(env, store, policy):
    events, _, col, _ = env
    write_lines(events / "opencanary.log", [
        {"logtype": 1001, "src_host": "", "utc_time": "2026-11-18 14:00:00", "logdata": {"msg": "Canary running"}},
        oc(4000, 1), oc(4002, 2, "root", "toor")])
    (events / "opencanary.log").open("a").write("garbage line\n")
    write_lines(events / "web.log", [{
        "timestamp": "2026-11-18T14:30:05Z", "source_ip": "192.0.2.45", "destination_service": "http",
        "decoy_profile": "admin-portal", "high_value": True, "event_type": "http_request",
        "details": {"path": "/"}}], partial='{"timestamp": "2026-11-18T14:30:0')
    write_lines(events / "opencanary.log", [oc(8001, 8, "sa", "pw")])

    n = col.run_once()
    assert n == 5  # boot msg, ssh conn, ssh auth, web request, mysql auth (junk skipped, partial deferred)
    [inc] = store.incidents()
    assert inc["services"] == {"ssh", "http", "mysql"}
    assert {"auth", "multi_decoy", "cross_service", "high_value"} <= inc["flags"]
    assert inc["severity"] == "high"
    assert "toor" not in json.dumps(store.events(), default=str)
    assert store.alerts()[0]["severity"] == "high"

    # A second pass (e.g. after restart) re-reads nothing; the partial line completes later.
    assert col.run_once() == 0
    (events / "web.log").open("a").write('5Z", "source_ip": "192.0.2.45", "event_type": "http_request", '
                                         '"destination_service": "http"}\n')
    assert col.run_once() == 1
    assert len(store.incidents()) == 1


def test_truncated_log_is_reread(env, store):
    events, _, col, _ = env
    write_lines(events / "opencanary.log", [oc(4000, 1), oc(4000, 2)])
    assert col.run_once() == 2
    (events / "opencanary.log").write_text(json.dumps(oc(4000, 3)) + "\n")
    assert col.run_once() == 1


def test_dashboard_requires_auth(env):
    _, _, _, client = env
    assert client.get("/").status_code == 401
    assert client.get("/api/summary").status_code == 401
    assert client.get("/", headers=auth(pw="wrong")).status_code == 401
    r = client.get("/", headers=auth())
    assert r.status_code == 200 and "PhantomNet" in r.text
    assert r.headers["X-Frame-Options"] == "DENY"
    assert client.get("/docs").status_code == 404


def test_dashboard_views_and_redacted_export(env, store):
    events, state, col, client = env
    (state / "active_profile.json").write_text(json.dumps(
        {"profile_id": "storage-server", "profile": {"display_name": "Storage appliance"}}))
    write_lines(events / "opencanary.log", [oc(4002, 1, "root", "TopSecretPw1")])
    write_lines(events / "controller.log", [{
        "timestamp": "2026-11-18T14:29:00Z", "event_type": "profile_rotation",
        "details": {"previous_profile": "linux-server", "new_profile": "storage-server"}}])
    col.run_once()
    h = auth()
    s = client.get("/api/summary", headers=h).json()
    assert s["active_profile"] == "storage-server" and s["events_24h"] >= 0
    page = client.get("/", headers=h).text
    assert "Storage appliance" in page and "Decoy profile rotated" in page
    inc_id = store.incidents()[0]["id"]
    detail = client.get(f"/incidents/{inc_id}", headers=h)
    assert detail.status_code == 200 and "suggested response" in detail.text.lower()
    export = client.get(f"/api/incidents/{inc_id}/export", headers=h)
    assert export.status_code == 200 and "TopSecretPw1" not in export.text
    assert export.json()["evidence"][0]["details"]["password_length"] == 12
    assert client.get("/incidents/9999", headers=h).status_code == 404
