"""Alert building and delivery (log, webhook, email).

An alert is sent when an incident first reaches the configured minimum severity
and again each time it escalates to a higher severity — never repeatedly for
the same level.
"""
from __future__ import annotations

import json
import logging
import os
import smtplib
import time
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from email.message import EmailMessage

from .correlator import FLAG_LABELS
from .policy import SEVERITY_RANK, Policy
from .store import Store

log = logging.getLogger("phantomnet.alerts")

EVIDENCE_FIELDS = ("timestamp", "source_ip", "destination_service", "decoy_profile",
                   "event_type", "username", "risk_score", "details")

GUIDANCE = {
    "honeytoken": "A planted fake credential was used. The actor has read decoy content and is "
                  "acting on it: treat this as a likely intrusion and start incident response.",
    "auth": "Someone tried to log in to a system that does not exist for real users. Confirm "
            "whether the source is an authorized administrator; if not, investigate that host.",
    "multi_decoy": "The source is exploring several services in a short time, which is typical "
                   "of network reconnaissance or automated scanning.",
    "cross_service": "Login attempts against several different services suggest credential "
                     "guessing or reuse of stolen credentials.",
    "high_value": "The source reached a decoy that imitates a sensitive system.",
}
BASE_GUIDANCE = [
    "Decoys host no real data or users; any interaction with them is unexpected.",
    "Identify the device and owner behind the source address (DHCP, asset inventory, EDR).",
    "Do not block production users automatically from this alert alone; confirm first.",
]


def build_alert(incident: dict, events: list[dict], sensor_id: str) -> dict:
    flags = sorted(incident["flags"])
    guidance = [GUIDANCE[f] for f in ("honeytoken", "auth", "cross_service", "multi_decoy", "high_value")
                if f in flags] + BASE_GUIDANCE
    return {
        "type": "phantomnet.incident",
        "sensor_id": sensor_id,
        "incident_id": incident["id"],
        "severity": incident["severity"],
        "score": incident["score"],
        "source_ip": incident["source_ip"],
        "first_seen": _iso(incident["first_seen"]),
        "last_seen": _iso(incident["last_seen"]),
        "services": sorted(incident["services"]),
        "event_count": incident["event_count"],
        "findings": [FLAG_LABELS[f] for f in flags if f in FLAG_LABELS],
        "summary": (f"[{incident['severity'].upper()}] Source {incident['source_ip']} interacted with "
                    f"{len(incident['services'])} decoy service(s): {', '.join(sorted(incident['services'])) or 'n/a'} "
                    f"(score {incident['score']})."),
        "guidance": guidance,
        # Events are already redacted at ingestion; select fields to keep payloads small.
        "evidence": [{k: e.get(k) for k in EVIDENCE_FIELDS} for e in events[:20]],
    }


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class AlertSettings:
    webhook_url: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_to: str = ""
    sensor_id: str = "phantomnet-01"

    @classmethod
    def from_env(cls) -> "AlertSettings":
        e = os.environ.get
        return cls(webhook_url=e("PN_WEBHOOK_URL", ""), smtp_host=e("PN_SMTP_HOST", ""),
                   smtp_port=int(e("PN_SMTP_PORT", "587") or 587), smtp_user=e("PN_SMTP_USER", ""),
                   smtp_password=e("PN_SMTP_PASSWORD", ""), smtp_from=e("PN_SMTP_FROM", ""),
                   smtp_to=e("PN_SMTP_TO", ""), sensor_id=e("PN_NODE_ID", "phantomnet-01"))


class AlertDispatcher:
    def __init__(self, store: Store, policy: Policy, settings: AlertSettings):
        self.store, self.policy, self.settings = store, policy, settings

    def maybe_alert(self, incident: dict) -> dict | None:
        rank = SEVERITY_RANK[incident["severity"]]
        if rank < SEVERITY_RANK[self.policy.alert_min_severity]:
            return None
        prev = incident.get("alerted_severity")
        if prev is not None and rank <= SEVERITY_RANK[prev]:
            return None
        events = self.store.events(limit=50, incident_id=incident["id"])
        payload = build_alert(incident, events, self.settings.sensor_id)
        self._deliver(incident, payload)
        incident["alerted_severity"] = incident["severity"]
        self.store.save_incident(incident)
        return payload

    def _deliver(self, incident: dict, payload: dict) -> None:
        now = time.time()
        log.warning("ALERT %s", payload["summary"])
        self.store.insert_alert(incident["id"], now, incident["severity"], "log", "sent", None, payload)
        if self.settings.webhook_url:
            self._record(incident, payload, "webhook", self._send_webhook, payload)
        if self.settings.smtp_host and self.settings.smtp_to:
            self._record(incident, payload, "email", self._send_email, payload)

    def _record(self, incident, payload, channel, fn, arg) -> None:
        try:
            fn(arg)
            self.store.insert_alert(incident["id"], time.time(), incident["severity"], channel, "sent", None, payload)
        except Exception as exc:  # delivery must never crash the collector
            log.error("alert delivery via %s failed: %s", channel, exc)
            self.store.insert_alert(incident["id"], time.time(), incident["severity"], channel, "failed",
                                    str(exc)[:500], payload)

    def _send_webhook(self, payload: dict) -> None:
        body = json.dumps({"text": payload["summary"], **payload}).encode()
        req = urllib.request.Request(self.settings.webhook_url, data=body, method="POST",
                                     headers={"Content-Type": "application/json",
                                              "User-Agent": "PhantomNet/0.1"})
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310 (admin-configured URL)
            if resp.status >= 300:
                raise RuntimeError(f"webhook returned HTTP {resp.status}")

    def _send_email(self, payload: dict) -> None:
        s = self.settings
        msg = EmailMessage()
        msg["Subject"] = f"PhantomNet {payload['severity'].upper()} incident #{payload['incident_id']}"
        msg["From"] = s.smtp_from or s.smtp_user
        msg["To"] = s.smtp_to
        lines = [payload["summary"], "", "Findings:", *[f"- {f}" for f in payload["findings"]],
                 "", "Suggested response:", *[f"- {g}" for g in payload["guidance"]], "",
                 "Evidence (redacted):", json.dumps(payload["evidence"], indent=2)]
        msg.set_content("\n".join(lines))
        with smtplib.SMTP(s.smtp_host, s.smtp_port, timeout=15) as smtp:
            smtp.starttls()
            if s.smtp_user:
                smtp.login(s.smtp_user, s.smtp_password)
            smtp.send_message(msg)
