"""Moving-target controller: rotate the web decoy's simulated identity.

Only decoy personas rotate; real infrastructure is never touched. The
controller has no Docker socket and no firewall privileges — it can only
rewrite the decoy state file it owns.

Rotation is atomic (write temp file + os.replace). After each change the web
decoy's internal health endpoint must report the new profile and generation;
otherwise the previous profile is restored and a rollback event is logged.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import random
import time
import urllib.request
from pathlib import Path
from typing import Callable

from detection.policy import Policy, load_policy
from detection.schema import utc_now_iso

from .profiles import ProfileError, load_profiles, validate_profile

log = logging.getLogger("phantomnet.controller")

STATE_FILE = "active_profile.json"
STATUS_FILE = "controller_status.json"

HealthCheck = Callable[[], dict | None]


def atomic_write_json(path: Path, data: dict) -> None:
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def http_health_check(url: str) -> HealthCheck:
    def check() -> dict | None:
        try:
            with urllib.request.urlopen(url, timeout=3) as resp:  # noqa: S310 (internal URL)
                return json.loads(resp.read().decode())
        except Exception as exc:
            log.debug("health check failed: %s", exc)
            return None
    return check


class Rotator:
    def __init__(self, profiles: dict[str, dict], policy: Policy, state_dir: str | Path,
                 events_dir: str | Path, health_check: HealthCheck, node_id: str = "phantomnet-01",
                 poll_interval: float = 0.5, rng: random.Random | None = None):
        self.profiles = profiles
        self.policy = policy
        self.state_dir = Path(state_dir)
        self.events_path = Path(events_dir) / "controller.log"
        self.health_check = health_check
        self.node_id = node_id
        self.poll_interval = poll_interval
        self.rng = rng or random.Random()
        eligible = [p for p in (policy.web_profiles or list(profiles)) if p in profiles]
        if not eligible:
            raise ProfileError("no eligible web profiles; check rotation.web_profiles in policies.yaml")
        self.eligible = eligible
        self.state_dir.mkdir(parents=True, exist_ok=True)

    # -- state ----------------------------------------------------------
    @property
    def state_path(self) -> Path:
        return self.state_dir / STATE_FILE

    def read_state(self) -> dict | None:
        try:
            state = json.loads(self.state_path.read_text(encoding="utf-8"))
            validate_profile(state["profile"])
            return state
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def _write_state(self, profile: dict, generation: int, previous: str | None) -> dict:
        state = {"profile_id": profile["id"], "profile": profile, "generation": generation,
                 "previous_profile_id": previous, "applied_at": utc_now_iso()}
        atomic_write_json(self.state_path, state)
        return state

    # -- events ---------------------------------------------------------
    def log_event(self, event_type: str, **details) -> None:
        rec = {"timestamp": utc_now_iso(), "sensor_id": self.node_id, "event_type": event_type,
               "destination_service": None, "decoy_profile": details.get("new_profile"),
               "details": details}
        self.events_path.parent.mkdir(parents=True, exist_ok=True)
        with self.events_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
        log.info("%s %s", event_type, details)

    def write_status(self, **status) -> None:
        atomic_write_json(self.state_dir / STATUS_FILE,
                          {"heartbeat": utc_now_iso(), "node_id": self.node_id, **status})

    # -- health ---------------------------------------------------------
    def wait_healthy(self, profile_id: str, generation: int, timeout: float) -> tuple[bool, str]:
        deadline = time.monotonic() + timeout
        last = "no response from web decoy"
        while True:
            h = self.health_check()
            if h:
                if h.get("ok") and h.get("profile_id") == profile_id and h.get("generation") == generation:
                    return True, "ok"
                last = (f"web decoy reports profile={h.get('profile_id')} generation={h.get('generation')} "
                        f"ok={h.get('ok')} error={h.get('error')}")
            if time.monotonic() >= deadline:
                return False, last
            time.sleep(self.poll_interval)

    # -- operations -----------------------------------------------------
    def ensure_initial(self) -> dict:
        state = self.read_state()
        if state and state["profile_id"] in self.profiles:
            return state
        first = self.profiles[self.eligible[0]]
        state = self._write_state(first, 1, None)
        self.log_event("profile_applied", new_profile=first["id"], previous_profile=None,
                       generation=1, reason="initial")
        return state

    def choose_next(self, current: str | None) -> str:
        options = [p for p in self.eligible if p != current] or self.eligible
        return self.rng.choice(options)

    def rotate(self, target: str | None = None) -> bool:
        """Apply a new profile; roll back if the decoy fails its health check."""
        current = self.read_state() or self.ensure_initial()
        prev_id, gen = current["profile_id"], int(current.get("generation", 0))
        new_id = target or self.choose_next(prev_id)
        if new_id not in self.profiles:
            raise ProfileError(f"unknown profile {new_id}")
        new_gen = gen + 1
        self._write_state(self.profiles[new_id], new_gen, prev_id)
        ok, reason = self.wait_healthy(new_id, new_gen, self.policy.health_timeout_seconds)
        if ok:
            self.log_event("profile_rotation", previous_profile=prev_id, new_profile=new_id,
                           generation=new_gen, result="success")
            return True

        # Roll back to the exact previous snapshot under a new generation.
        rb_gen = new_gen + 1
        self._write_state(current["profile"], rb_gen, new_id)
        rb_ok, rb_reason = self.wait_healthy(prev_id, rb_gen, self.policy.health_timeout_seconds)
        self.log_event("rotation_rollback", previous_profile=new_id, new_profile=prev_id,
                       attempted_profile=new_id, generation=rb_gen, reason=reason,
                       rollback_result="success" if rb_ok else f"failed: {rb_reason}")
        return False

    def next_delay(self) -> float:
        return self.rng.uniform(self.policy.interval_min_minutes, self.policy.interval_max_minutes) * 60

    def run_forever(self) -> None:
        self.ensure_initial()
        next_at = time.time() + self.next_delay()
        last_result = "initial"
        while True:
            enabled = self.policy.rotation_enabled
            self.write_status(rotation_enabled=enabled, next_rotation_at=next_at if enabled else None,
                              last_result=last_result, active=(self.read_state() or {}).get("profile_id"),
                              web_health=self.health_check() or {"ok": False, "error": "unreachable"})
            if enabled and time.time() >= next_at:
                try:
                    last_result = "success" if self.rotate() else "rolled_back"
                except Exception as exc:
                    log.exception("rotation error")
                    last_result = f"error: {exc}"
                next_at = time.time() + self.next_delay()
            time.sleep(min(30.0, max(1.0, next_at - time.time())))


def build_from_env(health_check: HealthCheck | None = None) -> Rotator:
    e = os.environ.get
    return Rotator(
        profiles=load_profiles(e("PN_PROFILES_DIR", "config/profiles")),
        policy=load_policy(e("PN_POLICIES", "config/policies.yaml")),
        state_dir=e("PN_STATE_DIR", "data/state"),
        events_dir=e("PN_EVENTS_DIR", "data/events"),
        health_check=health_check or http_health_check(e("PN_WEB_HEALTH_URL", "http://127.0.0.1:9090/health")),
        node_id=e("PN_NODE_ID", "phantomnet-01"),
    )


def main() -> None:
    ap = argparse.ArgumentParser(description="PhantomNet decoy profile rotator")
    ap.add_argument("--once", action="store_true", help="rotate once and exit")
    ap.add_argument("--profile", help="rotate to this profile id (with --once)")
    args = ap.parse_args()
    logging.basicConfig(level=os.environ.get("PN_LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    r = build_from_env()
    if args.once:
        r.ensure_initial()
        raise SystemExit(0 if r.rotate(args.profile) else 1)
    r.run_forever()


if __name__ == "__main__":
    main()
