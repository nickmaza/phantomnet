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
from .cloud import from_env as cloud_from_env
from .policy import load_policy, read_managed_config
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
    logging.getLogger("httpx").setLevel(logging.WARNING)  # one line per sync is noise
    settings = DashboardSettings.from_env()  # fail fast if credentials are missing
    policy = load_policy()
    store = Store(os.environ.get("PN_DB_PATH", "data/db/phantomnet.sqlite3"))
    dispatcher = AlertDispatcher(store, policy, AlertSettings.from_env().with_managed(read_managed_config()))
    correlator = Correlator(store, policy)
    collector = Collector(default_events_dir(), store, correlator, dispatcher)

    def apply_console_config(cfg: dict) -> None:
        """Hot-reload policy and alert settings after the console pushes new settings."""
        try:
            new_policy = load_policy()
        except Exception:
            log.exception("console settings rejected; keeping current policy")
            return
        correlator.policy = dispatcher.policy = new_policy
        dispatcher.settings = AlertSettings.from_env().with_managed(cfg)

    stop = threading.Event()
    t = threading.Thread(target=collector_loop, args=(collector, stop), daemon=True, name="collector")
    t.start()

    cloud = cloud_from_env(store, dispatcher, on_config=apply_console_config)
    if cloud:
        log.info("cloud console sync enabled: %s", cloud.url)
        threading.Thread(target=cloud.run, args=(stop,), daemon=True, name="cloud-sync").start()

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
