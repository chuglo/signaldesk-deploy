from __future__ import annotations

import importlib.util
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "wait-for-health.py"


def load_health_module():
    spec = importlib.util.spec_from_file_location("signaldesk_wait_for_health", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_sqlalchemy_postgres_driver_is_normalized_for_psycopg() -> None:
    module = load_health_module()
    assert module._psycopg_url(
        "postgresql+psycopg://signaldesk_app:secret@postgres:5432/signaldesk"
    ) == "postgresql://signaldesk_app:secret@postgres:5432/signaldesk"
