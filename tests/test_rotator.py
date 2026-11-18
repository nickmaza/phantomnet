import json
import random

import pytest

from controller.profiles import ProfileError, load_profiles, validate_profile
from controller.rotator import Rotator


@pytest.fixture
def profiles(root):
    return load_profiles(root / "config" / "profiles")


def make_rotator(tmp_path, profiles, policy, health):
    policy.health_timeout_seconds = 0.3
    return Rotator(profiles, policy, tmp_path / "state", tmp_path / "events", health,
                   poll_interval=0.05, rng=random.Random(1))


def controller_events(tmp_path):
    p = tmp_path / "events" / "controller.log"
    return [json.loads(line) for line in p.read_text().splitlines()] if p.exists() else []


def test_shipped_profiles_are_valid(profiles):
    assert set(profiles) == {"linux-server", "storage-server", "admin-portal"}


def test_profile_rejects_embedded_secret(profiles):
    bad = json.loads(json.dumps(profiles["linux-server"]))
    bad["http"]["breadcrumb_comment"] = "db password: Winter2026!"
    with pytest.raises(ProfileError):
        validate_profile(bad)


def test_profile_rejects_header_injection(profiles):
    bad = json.loads(json.dumps(profiles["linux-server"]))
    bad["http"]["server_header"] = "nginx\r\nSet-Cookie: x=1"
    with pytest.raises(ProfileError):
        validate_profile(bad)


def test_successful_rotation_is_atomic_and_logged(tmp_path, profiles, policy):
    state = {}

    def health():
        return {"ok": True, "profile_id": state.get("id"), "generation": state.get("gen")}

    r = make_rotator(tmp_path, profiles, policy, health)
    s = r.ensure_initial()
    assert s["profile_id"] == "linux-server" and s["generation"] == 1

    # Simulate the web decoy picking up whatever the state file says.
    orig_write = r._write_state

    def write_and_apply(profile, gen, prev):
        out = orig_write(profile, gen, prev)
        state.update(id=profile["id"], gen=gen)
        return out

    r._write_state = write_and_apply
    assert r.rotate("storage-server") is True
    s = r.read_state()
    assert s["profile_id"] == "storage-server" and s["previous_profile_id"] == "linux-server"
    assert s["generation"] == 2
    assert not list((tmp_path / "state").glob(".*.tmp"))  # no stray temp files
    ev = controller_events(tmp_path)[-1]
    assert ev["event_type"] == "profile_rotation"
    assert ev["details"]["previous_profile"] == "linux-server"
    assert ev["details"]["new_profile"] == "storage-server"


def test_failed_health_check_rolls_back(tmp_path, profiles, policy):
    applied = {}

    def health():
        # Decoy refuses the storage-server profile but serves anything else.
        if applied.get("id") == "storage-server":
            return {"ok": False, "profile_id": "linux-server", "generation": 1, "error": "render failed"}
        return {"ok": True, "profile_id": applied.get("id"), "generation": applied.get("gen")}

    r = make_rotator(tmp_path, profiles, policy, health)
    r.ensure_initial()
    orig_write = r._write_state

    def write_and_apply(profile, gen, prev):
        out = orig_write(profile, gen, prev)
        applied.update(id=profile["id"], gen=gen)
        return out

    r._write_state = write_and_apply
    assert r.rotate("storage-server") is False
    s = r.read_state()
    assert s["profile_id"] == "linux-server"     # previous profile restored
    assert s["generation"] == 3                  # 1 initial, 2 attempt, 3 rollback
    ev = controller_events(tmp_path)[-1]
    assert ev["event_type"] == "rotation_rollback"
    assert ev["details"]["attempted_profile"] == "storage-server"
    assert ev["details"]["rollback_result"] == "success"
    assert "render failed" in ev["details"]["reason"]


def test_unreachable_decoy_still_restores_state(tmp_path, profiles, policy):
    r = make_rotator(tmp_path, profiles, policy, lambda: None)
    r.ensure_initial()
    assert r.rotate("admin-portal") is False
    assert r.read_state()["profile_id"] == "linux-server"
    assert controller_events(tmp_path)[-1]["details"]["rollback_result"].startswith("failed")


def test_choose_next_never_repeats_current(tmp_path, profiles, policy):
    r = make_rotator(tmp_path, profiles, policy, lambda: None)
    for _ in range(50):
        assert r.choose_next("admin-portal") != "admin-portal"


def test_next_delay_within_policy(tmp_path, profiles, policy):
    r = make_rotator(tmp_path, profiles, policy, lambda: None)
    for _ in range(50):
        assert 30 * 60 <= r.next_delay() <= 60 * 60


def test_console_rotation_settings_and_requests(tmp_path, profiles, policy, monkeypatch, root):
    managed = tmp_path / "managed"
    (managed / "requests").mkdir(parents=True)
    monkeypatch.setenv("PN_MANAGED_DIR", str(managed))
    applied = {}

    def health():
        return {"ok": True, "profile_id": applied.get("id"), "generation": applied.get("gen")}

    r = make_rotator(tmp_path, profiles, policy, health)
    r.policy_path = str(root / "config" / "policies.yaml")
    orig = r._write_state

    def write_and_apply(profile, gen, prev):
        out = orig(profile, gen, prev)
        applied.update(id=profile["id"], gen=gen)
        return out

    r._write_state = write_and_apply
    r.ensure_initial()
    applied.update(id="linux-server", gen=1)

    # settings pushed by the console
    (managed / "config.json").write_text(json.dumps({"version": 2, "config": {
        "rotation.interval_min_minutes": 10, "rotation.interval_max_minutes": 15,
        "rotation.profiles": ["linux-server", "admin-portal"], "rotation.enabled": False}}))
    assert r.reload_policy_if_changed() is True
    assert (r.policy.interval_min_minutes, r.policy.interval_max_minutes) == (10, 15)
    assert r.eligible == ["linux-server", "admin-portal"] and r.policy.rotation_enabled is False
    assert r.reload_policy_if_changed() is False          # unchanged file -> no reload

    # garbage from the console is ignored, not applied
    (managed / "config.json").write_text(json.dumps({"version": 3, "config": {
        "rotation.interval_min_minutes": -5, "rotation.profiles": "nope"}}))
    import os, time as _t
    os.utime(managed / "config.json", (_t.time() + 5, _t.time() + 5))
    r.reload_policy_if_changed()
    assert r.policy.interval_min_minutes == 30            # defaults, not -5

    # "rotate now" request from the console
    (managed / "requests" / "rotate-7.json").write_text(json.dumps({"id": 7, "profile": "admin-portal"}))
    (managed / "requests" / "rotate-8.json").write_text(json.dumps({"id": 8, "profile": "evil-persona"}))
    assert r.process_requests() == 2
    res7 = json.loads((tmp_path / "state" / "action_results" / "7.json").read_text())
    res8 = json.loads((tmp_path / "state" / "action_results" / "8.json").read_text())
    assert res7["status"] == "done" and res7["result"]["active"] == "admin-portal"
    assert res8["status"] == "failed" and "unknown persona" in res8["result"]["error"]
    assert r.process_requests() == 0                      # never re-run a finished request
