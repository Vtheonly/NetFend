"""Shared pytest fixtures — hermetic: no root, no network, no scapy."""
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Isolate all runtime state per test session
DATA = Path("/tmp/nf-pytest-data")


@pytest.fixture(autouse=True)
def isolated_env(tmp_path, monkeypatch):
    """Every test gets its own data dir + fresh config."""
    monkeypatch.setenv("NETFEND_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("NETFEND_DRY_RUN", raising=False)
    # Reset cached config between tests
    import netfend.utils.config as config_mod
    config_mod._config = {}
    # Re-point module-level path constants at the tmp dir
    monkeypatch.setattr(config_mod, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config_mod, "BLACKLIST_FILE", tmp_path / "blacklist.json")
    monkeypatch.setattr(config_mod, "DEVICE_REGISTRY_FILE", tmp_path / "devices.json")
    monkeypatch.setattr(config_mod, "EVENTS_FILE", tmp_path / "events.jsonl")
    monkeypatch.setattr(config_mod, "LOG_FILE", tmp_path / "netfend.log")
    monkeypatch.setattr(config_mod, "DASHBOARD_TOKEN_FILE", tmp_path / "dashboard.token")
    yield tmp_path


@pytest.fixture
def events(tmp_path):
    from netfend.models.events import EventStore
    store = EventStore(path=tmp_path / "events.jsonl", ring_size=100)
    yield store
    store.close()
