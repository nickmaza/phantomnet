import ipaddress
from datetime import datetime, timedelta, timezone

from detection.alerts import AlertDispatcher, AlertSettings
from detection.correlator import Correlator
from detection.schema import iso, make_event

T0 = datetime(2026, 11, 18, 14, 30, tzinfo=timezone.utc)


def ev(service, etype, seconds=0, ip="192.0.2.45", username=None, high_value=False):
    return make_event(timestamp=iso(T0 + timedelta(seconds=seconds)), source_ip=ip,
                      destination_service=service, event_type=etype, username=username,
                      high_value=high_value, source="test")


def test_events_across_decoys_form_one_incident(store, policy):
    c = Correlator(store, policy)
    _, i1 = c.process(ev("http", "http_request", 0))
    _, i2 = c.process(ev("ssh", "connection", 20))
    _, i3 = c.process(ev("mysql", "connection", 40))
    assert i1["id"] == i2["id"] == i3["id"]
    inc = store.incident(i1["id"])
    assert inc["services"] == {"http", "ssh", "mysql"}
    assert inc["event_count"] == 3
    # high-value (ssh) 25 + multi-decoy 20
    assert inc["flags"] == {"high_value", "multi_decoy"}
    assert inc["score"] == 45 and inc["severity"] == "medium"
    assert len(store.incidents()) == 1


def test_rules_fire_once_per_incident(store, policy):
    c = Correlator(store, policy)
    for n in range(10):
        c.process(ev("ssh", "authentication_attempt", n))
    inc = store.incidents()[0]
    assert inc["score"] == 25 + 40
    assert inc["event_count"] == 10
    scores = [e["risk_score"] for e in store.events(incident_id=inc["id"])]
    assert sum(scores) == 65 and scores.count(0) == 9


def test_full_attack_reaches_high_and_caps(store, policy):
    c = Correlator(store, policy)
    c.process(ev("http", "http_request", 0))
    c.process(ev("ssh", "authentication_attempt", 10))
    c.process(ev("mysql", "authentication_attempt", 20))
    c.process(ev("http", "authentication_attempt", 30, username="SVC_DEPLOY"))
    inc = store.incidents()[0]
    assert inc["flags"] == {"high_value", "auth", "cross_service", "multi_decoy", "honeytoken"}
    assert inc["score"] == 100  # 150 capped
    assert inc["severity"] == "high"


def test_window_expiry_starts_new_incident(store, policy):
    c = Correlator(store, policy)
    _, a = c.process(ev("ssh", "connection", 0))
    _, b = c.process(ev("ssh", "connection", 31 * 60))
    assert a["id"] != b["id"]


def test_multi_decoy_window_respected(store, policy):
    c = Correlator(store, policy)
    c.process(ev("http", "http_request", 0))
    c.process(ev("ssh", "connection", 100))
    c.process(ev("mysql", "connection", 300))  # http is outside the 120 s window
    assert "multi_decoy" not in store.incidents()[0]["flags"]


def test_separate_sources_separate_incidents(store, policy):
    c = Correlator(store, policy)
    c.process(ev("ssh", "connection", 0, ip="192.0.2.1"))
    c.process(ev("ssh", "connection", 0, ip="192.0.2.2"))
    assert len(store.incidents()) == 2


def test_authorized_scanner_is_recorded_not_scored(store, policy):
    policy.authorized_scanners = [ipaddress.ip_network("198.51.100.0/24")]
    c = Correlator(store, policy)
    _, inc = c.process(ev("ssh", "authentication_attempt", 0, ip="198.51.100.7"))
    assert inc is None and store.incidents() == []
    [stored] = store.events()
    assert stored["action"] == "suppressed_authorized_scanner"


def test_controller_events_not_correlated(store, policy):
    c = Correlator(store, policy)
    _, inc = c.process(make_event(event_type="profile_rotation", source="controller",
                                  details={"previous_profile": "a", "new_profile": "b"}))
    assert inc is None and len(store.events()) == 1


def test_alerts_sent_once_per_level_and_on_escalation(store, policy):
    c = Correlator(store, policy)
    d = AlertDispatcher(store, policy, AlertSettings())
    _, inc = c.process(ev("http", "http_request", 0))
    assert d.maybe_alert(store.incident(inc["id"])) is None          # low: no alert
    c.process(ev("ssh", "authentication_attempt", 5))                   # 65 -> medium
    first = d.maybe_alert(store.incident(inc["id"]))
    assert first and first["severity"] == "medium"
    assert d.maybe_alert(store.incident(inc["id"])) is None            # no repeat
    c.process(ev("ssh", "authentication_attempt", 6, username="backup_admin"))  # -> high
    second = d.maybe_alert(store.incident(inc["id"]))
    assert second and second["severity"] == "high"
    assert any("honeytoken" in g.lower() or "fake credential" in g.lower() for g in second["guidance"])
    assert [a["severity"] for a in store.alerts()] == ["high", "medium"]


def test_alert_delivery_failure_is_recorded(store, policy):
    c = Correlator(store, policy)
    d = AlertDispatcher(store, policy, AlertSettings(webhook_url="http://127.0.0.1:9/nope"))
    _, inc = c.process(ev("ssh", "authentication_attempt", 0))
    d.maybe_alert(store.incident(inc["id"]))
    statuses = {(a["channel"], a["status"]) for a in store.alerts()}
    assert ("log", "sent") in statuses and ("webhook", "failed") in statuses
