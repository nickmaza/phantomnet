import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from detection.policy import load_policy  # noqa: E402
from detection.store import Store  # noqa: E402


@pytest.fixture(autouse=True)
def isolated_managed_dir(tmp_path, monkeypatch):
    # Never let a real data/managed/ (cloud settings) leak into tests.
    monkeypatch.setenv("PN_MANAGED_DIR", str(tmp_path / "managed"))


@pytest.fixture
def root() -> Path:
    return ROOT


@pytest.fixture
def policy():
    return load_policy(ROOT / "config" / "policies.yaml")


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "pn.sqlite3")
    yield s
    s.close()
