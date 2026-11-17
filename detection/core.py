"""phantomnet-core entry point: collector loop in a thread + dashboard via uvicorn."""
from __future__ import annotations

import logging
import os
import threading

import uvicorn

from dashboard.app import DashboardSettings, create_app

from .alerts import AlertDispatcher, AlertSettings
from .collector import Collector, default_events_dir
from .correlator import Correlator
from .policy import load_policy
from .store import Store

log = logging.getLogger("phantomnet.core")


def collector_loop(collector: Collector, stop: threading.Event, interval: float = 2.0) -> None:
    while not stop.is_set():
        try:
            n = collector.run_once()
            if n:
                log.info("processed %d event(s)", n)
        except Exception:  # keep the sensor alive; errors are logged
            log.exception("collector pass failed")
        stop.wait(interval)


def main() -> None:
    logging.basicConfig(level=os.environ.get("PN_LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    settings = DashboardSettings.from_env()  # fail fast if credentials are missing
    policy = load_policy()
    store = Store(os.environ.get("PN_DB_PATH", "data/db/phantomnet.sqlite3"))
    dispatcher = AlertDispatcher(store, policy, AlertSettings.from_env())
    collector = Collector(default_events_dir(), store, Correlator(store, policy), dispatcher)

    stop = threading.Event()
    t = threading.Thread(target=collector_loop, args=(collector, stop), daemon=True, name="collector")
    t.start()

    app = create_app(store, settings)
    try:
        uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PN_DASHBOARD_PORT", "8800")),
                    log_level="warning", proxy_headers=False, server_header=False)
    finally:
        stop.set()
        t.join(timeout=5)
        store.close()


if __name__ == "__main__":
    main()
