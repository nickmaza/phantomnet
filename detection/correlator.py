"""Behavior correlation: group events from one source into incidents and score them.

Each rule fires at most once per incident (deduplication). Incidents close when
no event arrives from the source for ``incident_idle_minutes`` (window expiry).
Authorized scanners are stored but never scored. Scores drive alerts and
analyst attention only — PhantomNet never blocks production users on its own.
"""
from __future__ import annotations

from typing import Any

from .policy import SEVERITY_RANK, Policy
from .schema import SOURCE_EVENT_TYPES, parse_ts
from .store import Store

FLAG_LABELS = {
    "high_value": "Connected to a high-value decoy",
    "auth": "Attempted to authenticate against a decoy",
    "multi_decoy": "Contacted several different decoys within a short window",
    "cross_service": "Repeated authentication attempts across multiple decoy services",
    "honeytoken": "Used a planted honeytoken credential",
}


class Correlator:
    def __init__(self, store: Store, policy: Policy):
        self.store = store
        self.policy = policy

    def process(self, event: dict[str, Any]) -> tuple[int, dict | None]:
        """Store ``event``, correlate it, and return (event_id, incident or None)."""
        src = event.get("source_ip")
        if not src or event.get("event_type") not in SOURCE_EVENT_TYPES:
            return self.store.insert_event(event), None

        if self.policy.is_authorized_scanner(src):
            event = {**event, "action": "suppressed_authorized_scanner", "risk_score": 0}
            return self.store.insert_event(event), None

        ts = parse_ts(event["timestamp"]).timestamp()
        idle = self.policy.incident_idle_minutes * 60
        inc = self.store.open_incident_for(src, ts - idle) or self.store.create_incident(src, ts)

        event_id = self.store.insert_event({**event, "incident_id": inc["id"]})

        inc["last_seen"] = max(inc["last_seen"], ts)
        inc["first_seen"] = min(inc["first_seen"], ts)
        inc["event_count"] += 1
        service = event.get("destination_service")
        if service:
            inc["services"].add(service)

        points = self._score(event, inc, ts)
        inc["score"] = min(inc["score"] + points, self.policy.scoring.get("max_score", 100))
        inc["severity"] = self.policy.severity_for(inc["score"])
        self.store.save_incident(inc)

        alerting = SEVERITY_RANK[inc["severity"]] >= SEVERITY_RANK[self.policy.alert_min_severity]
        self.store.update_event(event_id, risk_score=points, action="alert" if alerting else "log")
        return event_id, inc

    def _score(self, event: dict, inc: dict, ts: float) -> int:
        s, flags, points = self.policy.scoring, inc["flags"], 0
        service = (event.get("destination_service") or "").lower()
        etype = event.get("event_type")

        def fire(flag: str, amount: int) -> None:
            nonlocal points
            if flag not in flags:
                flags.add(flag)
                points += amount

        if service in self.policy.high_value_services or event.get("high_value"):
            fire("high_value", s["high_value_connection"])

        if etype == "authentication_attempt":
            fire("auth", s["authentication_attempt"])
            if len(self.store.auth_services_for_incident(inc["id"])) >= 2:
                fire("cross_service", s["cross_service_attempts"])

        user = (event.get("username") or "").lower()
        if user and user in self.policy.honeytoken_usernames:
            fire("honeytoken", s["honeytoken"])

        window_start = ts - self.policy.multi_decoy_window_seconds
        services = self.store.distinct_services_since(event["source_ip"], window_start)
        if len(services) >= self.policy.multi_decoy_threshold:
            fire("multi_decoy", s["multi_decoy"])

        return points
