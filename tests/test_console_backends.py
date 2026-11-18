"""Console backends: Firebase Auth (against a simulated Identity Toolkit) and a
storage contract every store must satisfy.

The Firestore run of the contract is opt-in and talks to a real project:
  PN_TEST_FIRESTORE_SA=<path to service-account.json> pytest tests/test_console_backends.py
"""
import json
import os
import sys
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "console"))

from pnconsole.auth import AuthError, FirebaseAuth  # noqa: E402
from pnconsole.store import MemoryStore  # noqa: E402


# ---------------------------------------------------------------- Firebase Auth

def fake_google(users: dict):
    def handler(req: httpx.Request) -> httpx.Response:
        assert req.url.params["key"] == "web-key"
        path = req.url.path
        if path.endswith("accounts:signUp"):
            b = json.loads(req.content)
            if b["email"] in users:
                return httpx.Response(400, json={"error": {"message": "EMAIL_EXISTS"}})
            if len(b["password"]) < 6:
                return httpx.Response(400, json={"error": {"message": "WEAK_PASSWORD : Password should be at least 6 characters"}})
            users[b["email"]] = b["password"]
            return httpx.Response(200, json={"idToken": "id-" + b["email"], "refreshToken": "rt-" + b["email"],
                                             "expiresIn": "3600", "email": b["email"], "localId": "uid-" + b["email"]})
        if path.endswith("accounts:signInWithPassword"):
            b = json.loads(req.content)
            if users.get(b["email"]) != b["password"]:
                return httpx.Response(400, json={"error": {"message": "INVALID_LOGIN_CREDENTIALS"}})
            return httpx.Response(200, json={"idToken": "id-" + b["email"], "refreshToken": "rt-" + b["email"],
                                             "expiresIn": "3600", "email": b["email"]})
        if path.endswith("accounts:lookup"):
            tok = json.loads(req.content)["idToken"]
            if not tok.startswith("id-"):
                return httpx.Response(400, json={"error": {"message": "INVALID_ID_TOKEN"}})
            email = tok[3:]
            return httpx.Response(200, json={"users": [{"localId": "uid-" + email, "email": email}]})
        if path.endswith("/token"):
            form = dict(x.split("=") for x in req.content.decode().split("&"))
            email = form["refresh_token"].replace("rt-", "").replace("%40", "@")
            return httpx.Response(200, json={"id_token": "id-" + email, "refresh_token": "rt-" + email,
                                             "expires_in": "3600", "user_id": "uid-" + email})
        return httpx.Response(404)
    return handler


@pytest.fixture
def fb():
    return FirebaseAuth("web-key", client=httpx.Client(transport=httpx.MockTransport(fake_google({}))))


def test_firebase_signup_login_lookup_refresh(fb):
    s = fb.signup("ana@example.com", "correct-horse-1")
    assert s["access_token"] == "id-ana@example.com" and s["refresh_token"] and s["email"] == "ana@example.com"
    assert fb.user(s["access_token"]).id == "uid-ana@example.com"
    assert fb.login("ana@example.com", "correct-horse-1")["access_token"]
    assert fb.refresh(s["refresh_token"])["access_token"] == "id-ana@example.com"


def test_firebase_errors_are_friendly(fb):
    fb.signup("ana@example.com", "correct-horse-1")
    with pytest.raises(AuthError, match="already exists"):
        fb.signup("ana@example.com", "another-pass-1")
    with pytest.raises(AuthError, match="invalid email or password"):
        fb.login("ana@example.com", "wrong-password")
    with pytest.raises(AuthError, match="at least 8"):
        fb.signup("bo@example.com", "short")
    with pytest.raises(AuthError, match="session expired") as e:
        fb.user("forged-token")
    assert e.value.status == 401


# ---------------------------------------------------------------- store contract

def stores():
    yield pytest.param(lambda: MemoryStore(), id="memory")
    sa = os.environ.get("PN_TEST_FIRESTORE_SA")
    if sa:
        def make():
            from pnconsole.firestore_store import FirestoreStore
            return FirestoreStore(Path(sa).read_text())
        yield pytest.param(make, id="firestore")


@pytest.mark.parametrize("make", list(stores()))
def test_store_contract(make):
    import uuid
    st = make()
    owner, other = f"test-{uuid.uuid4()}", f"test-{uuid.uuid4()}"
    s = st.create_sensor(owner, "lab", "enroll-hash", "2099-01-01T00:00:00+00:00")
    try:
        with pytest.raises(ValueError):
            st.create_sensor(owner, "lab", "x", "2099-01-01T00:00:00+00:00")
        assert [x["name"] for x in st.list_sensors(owner)] == ["lab"]
        assert st.list_sensors(other) == []
        assert st.sensor_by_name(owner, "lab")["id"] == s["id"]
        assert st.sensor_by("enroll_code_hash", "enroll-hash")["id"] == s["id"]
        st.update_sensor(s["id"], token_hash=f"tok-{s['id']}", enroll_code_hash=None)
        assert st.sensor_by("token_hash", f"tok-{s['id']}")["id"] == s["id"]

        assert st.get_config(s["id"]) == ({}, 1)
        assert st.set_config(s["id"], {"honeytokens": ["a"]}) == 2
        assert st.get_config(s["id"]) == ({"honeytokens": ["a"]}, 2)

        base = {"source_ip": "192.0.2.1", "severity": "high", "score": 90, "flags": ["auth"],
                "services": ["ssh"], "event_count": 3, "first_seen": "2026-11-18T00:00:00+00:00",
                "last_seen": "2026-11-18T00:01:00+00:00", "summary": "s", "findings": [], "guidance": [],
                "evidence": []}
        st.upsert_incidents(s["id"], [{"local_id": 1, **base}, {"local_id": 2, **base, "severity": "low",
                                                                "last_seen": "2026-11-18T00:02:00+00:00"}])
        rows = st.list_incidents([s["id"]])
        assert [r["local_id"] for r in rows] == [2, 1]               # newest first
        inc = next(r for r in rows if r["local_id"] == 1)
        st.update_incident(inc["id"], status="acknowledged", note="on it")
        st.upsert_incidents(s["id"], [{"local_id": 1, **base, "event_count": 9}])
        got = st.get_incident(inc["id"])
        assert got["status"] == "acknowledged" and got["note"] == "on it" and got["event_count"] == 9
        assert [r["local_id"] for r in st.list_incidents([s["id"]], ["open"])] == [2]
        assert [r["local_id"] for r in st.list_incidents([s["id"]], min_severity="high")] == [1]

        a = st.create_action(s["id"], "rotate", {"profile": "admin-portal"})
        assert [x["id"] for x in st.actions_for(s["id"], ["queued"])] == [a["id"]]
        st.update_action(a["id"], "someone-elses-sensor", status="done")   # ignored
        assert st.actions_for(s["id"])[0]["status"] == "queued"
        st.update_action(a["id"], s["id"], status="done", result={"ok": True})
        assert st.actions_for(s["id"])[0]["result"] == {"ok": True}

        st.add_audit(owner, None, "config set x 1")
        assert st.list_audit(owner)[0]["command"] == "config set x 1"
        assert st.list_audit(other) == []
    finally:
        st.delete_sensor(s["id"])
    assert st.list_sensors(owner) == [] and st.list_incidents([s["id"]]) == []
