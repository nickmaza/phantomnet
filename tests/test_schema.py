import json

from detection.schema import make_event, normalize_native, normalize_opencanary, redact


def test_redact_replaces_passwords_with_length():
    out = redact({"username": "root", "PASSWORD": "hunter2", "nested": {"api_key": "abc", "ok": 1}})
    assert "PASSWORD" not in out and "hunter2" not in json.dumps(out)
    assert out["password_length"] == 7
    assert out["nested"]["api_key"] == "[REDACTED]"
    assert out["nested"]["ok"] == 1


def test_redact_masks_sensitive_query_params_and_truncates():
    out = redact({"path": "/login?user=a&password=s3cret&token=t", "ua": "x" * 1000})
    assert "s3cret" not in out["path"] and "REDACTED" in out["path"] and "user=a" in out["path"]
    assert len(out["ua"]) == 256


def test_redact_strips_control_chars():
    assert redact({"ua": "a\x1b[31mb"})["ua"] == "a?[31mb"


def test_normalize_opencanary_ssh_login():
    rec = {"dst_host": "10.77.30.2", "dst_port": 2222, "local_time": "2026-11-18 14:30:00.000000",
           "utc_time": "2026-11-18 14:30:00.000000", "logtype": 4002, "node_id": "phantomnet-01",
           "src_host": "192.0.2.45", "src_port": 51515,
           "logdata": {"USERNAME": "root", "PASSWORD": "toor", "LOCALVERSION": "SSH-2.0-OpenSSH_8.9p1",
                       "REMOTEVERSION": "SSH-2.0-libssh"}}
    ev = normalize_opencanary(rec)
    assert ev["event_type"] == "authentication_attempt"
    assert ev["destination_service"] == "ssh"
    assert ev["source_ip"] == "192.0.2.45"
    assert ev["username"] == "root"
    assert ev["timestamp"] == "2026-11-18T14:30:00.000000Z"
    assert "toor" not in json.dumps(ev)
    assert ev["details"]["password_length"] == 4
    assert ev["simulation"] is True


def test_normalize_opencanary_mysql_and_boot():
    mysql = normalize_opencanary({"logtype": 8001, "src_host": "192.0.2.9", "utc_time": "2026-11-18 14:30:01",
                                  "logdata": {"USERNAME": "sa", "PASSWORD": "x"}})
    assert (mysql["destination_service"], mysql["event_type"]) == ("mysql", "authentication_attempt")
    boot = normalize_opencanary({"logtype": 1001, "src_host": "", "utc_time": "2026-11-18 14:00:00",
                                 "logdata": {"msg": "Canary running!!!"}})
    assert boot["source_ip"] is None and boot["event_type"] == "sensor_message"


def test_normalize_native_and_example_schema_fields():
    ev = normalize_native({"timestamp": "2026-11-18T14:30:00Z", "sensor_id": "phantomnet-01",
                           "source_ip": "192.0.2.45", "destination_service": "http",
                           "decoy_profile": "admin-portal", "event_type": "authentication_attempt",
                           "details": {"password": "pw"}}, "web")
    for key in ("timestamp", "sensor_id", "source_ip", "destination_service", "decoy_profile",
                "event_type", "risk_score", "action", "simulation"):
        assert key in ev
    assert ev["source"] == "web"
    assert normalize_native({"no": "type"}, "web") is None


def test_make_event_defaults():
    ev = make_event(event_type="connection", source_ip="192.0.2.1")
    assert ev["action"] == "log" and ev["risk_score"] == 0 and ev["details"] == {}
