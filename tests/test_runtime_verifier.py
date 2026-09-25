from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify-runtime.py"


def load_verifier_module():
    spec = importlib.util.spec_from_file_location("signaldesk_verify_runtime", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_semantic_minio_check_rejects_wrong_expiry_and_retention() -> None:
    verifier = load_verifier_module()
    wrong_lifecycle = {
        "Rules": [
            {
                "ID": "wrong-one-day-rule",
                "Status": "Enabled",
                "Filter": {"Prefix": "exports/"},
                "Expiration": {"Days": 1},
            }
        ]
    }
    correct_retention = {
        "enabled": "Enabled",
        "mode": "COMPLIANCE",
        "validity": "7DAYS",
        "status": "success",
    }
    with pytest.raises(AssertionError):
        verifier.assert_exact_minio_lifecycle_and_retention(
            wrong_lifecycle, correct_retention
        )

    wrong_retention = correct_retention | {"validity": "1DAYS"}
    with pytest.raises(AssertionError):
        verifier.assert_exact_minio_lifecycle_and_retention(
            verifier.EXPECTED_LIFECYCLE, wrong_retention
        )

    verifier.assert_exact_minio_lifecycle_and_retention(
        verifier.EXPECTED_LIFECYCLE, correct_retention
    )
