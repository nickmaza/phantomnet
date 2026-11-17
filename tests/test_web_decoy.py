"""Run the real web decoy on loopback and exercise it over HTTP."""
import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest

from controller.profiles import load_profiles
from controller.rotator import atomic_write_json
from services.decoys.web.server import (EventLog, ProfileState, ThreadingHTTPServer,
                                        make_decoy_handler, make_health_handler)


@pytest.fixture
def decoy(tmp_path, root):
    state_dir, events_dir = tmp_path / "state", tmp_path / "events"
    state_dir.mkdir()
    state = ProfileState(state_dir, root / "config" / "profiles")
    log = EventLog(events_dir / "web.log", "test-node")
    web = ThreadingHTTPServer(("127.0.0.1", 0), make_decoy_handler(state, log, 8080))
    health = ThreadingHTTPServer(("127.0.0.1", 0), make_health_handler(state))
    for s in (web, health):
        threading.Thread(target=s.serve_forever, daemon=True).start()
    profiles = load_profiles(root / "config" / "profiles")

    class D:
        url = f"http://127.0.0.1:{web.server_address[1]}"
        health_url = f"http://127.0.0.1:{health.server_address[1]}/health"

        @staticmethod
        def apply(pid, gen):
            atomic_write_json(state_dir / "active_profile.json",
                              {"profile_id": pid, "profile": profiles[pid], "generation": gen})
            time.sleep(0.02)

        @staticmethod
        def events():
            p = events_dir / "web.log"
            return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []

    yield D
    web.shutdown(); health.shutdown()


def get(url, data=None):
    try:
        with urllib.request.urlopen(url, data=data, timeout=5) as r:
            return r.status, dict(r.headers), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()


def health(d):
    return json.loads(urllib.request.urlopen(d.health_url, timeout=5).read())


def test_serves_active_profile_and_rotates(decoy):
    decoy.apply("linux-server", 1)
    code, headers, body = get(decoy.url + "/")
    assert code == 200 and headers["Server"] == "nginx/1.24.0 (Ubuntu)"
    assert "ServerPanel" in body and "svc_deploy" in body
    assert health(decoy) == {"ok": True, "profile_id": "linux-server", "generation": 1, "error": None}

    decoy.apply("storage-server", 2)
    code, headers, body = get(decoy.url + "/")
    assert headers["Server"] == "lighttpd/1.4.69" and "StoreVault" in body
    assert health(decoy)["generation"] == 2


def test_login_attempt_logged_without_password(decoy):
    decoy.apply("admin-portal", 1)
    data = urllib.parse.urlencode({"username": "svc_deploy", "password": "Sup3rSecret!"}).encode()
    code, _, body = get(decoy.url + "/login", data)
    assert code == 401 and "Invalid credentials" in body
    raw = (json.dumps(decoy.events()))
    assert "Sup3rSecret!" not in raw
    [ev] = [e for e in decoy.events() if e["event_type"] == "authentication_attempt"]
    assert ev["username"] == "svc_deploy"
    assert ev["details"]["password_length"] == 12
    assert ev["decoy_profile"] == "admin-portal" and ev["high_value"] is True
    assert ev["source_ip"] == "127.0.0.1"


def test_robots_and_scan_paths(decoy):
    decoy.apply("linux-server", 1)
    code, _, body = get(decoy.url + "/robots.txt")
    assert code == 200 and "Disallow: /backup/" in body
    code, headers, body = get(decoy.url + "/.env")
    assert code == 404 and "nginx/1.24.0" in body
    assert any(e["details"].get("suspicious_path") for e in decoy.events())


def test_invalid_state_keeps_last_good_and_reports_unhealthy(decoy, tmp_path):
    decoy.apply("linux-server", 1)
    get(decoy.url + "/")
    (tmp_path / "state" / "active_profile.json").write_text('{"profile_id": "x", "profile": {"id": "BAD"}}')
    time.sleep(0.02)
    code, headers, _ = get(decoy.url + "/")
    assert code == 200 and headers["Server"] == "nginx/1.24.0 (Ubuntu)"   # still serving
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(decoy.health_url, timeout=5)
    status, h = exc.value.code, json.loads(exc.value.read())
    assert status == 503 and h["ok"] is False and h["profile_id"] == "linux-server"
