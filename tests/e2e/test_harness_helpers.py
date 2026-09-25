from __future__ import annotations

from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
from uuid import UUID

import pytest


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "verify-e2e.py"
CRASH_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "e2e-crash-worker.py"


def load_harness():
    spec = importlib.util.spec_from_file_location("signaldesk_verify_e2e", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_crashpoint():
    spec = importlib.util.spec_from_file_location("signaldesk_e2e_crashpoint", CRASH_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_extract_csrf_requires_one_bounded_html_token() -> None:
    harness = load_harness()
    assert harness.extract_csrf(
        b'<form><input name="csrf_token" type="hidden" value="abc_DEF-123"></form>'
    ) == "abc_DEF-123"
    with pytest.raises(AssertionError, match="exactly one CSRF"):
        harness.extract_csrf(b'<input name="csrf_token" value="a"><input name="csrf_token" value="b">')
    with pytest.raises(AssertionError, match="too large"):
        harness.extract_csrf(b"x" * (harness.MAX_HTML_BYTES + 1))


def test_redirect_job_id_is_confined_to_expected_local_path() -> None:
    harness = load_harness()
    job_id = UUID("00000000-0000-4000-8000-000000000301")
    assert harness.job_id_from_location(f"/diagnostics/{job_id}", "diagnostics") == job_id
    assert harness.job_id_from_location(f"/exports/{job_id}", "exports") == job_id
    for invalid in (
        f"https://attacker.invalid/exports/{job_id}",
        f"/exports/{job_id}/download",
        f"/other/{job_id}",
        "/exports/not-a-uuid",
    ):
        with pytest.raises(AssertionError):
            harness.job_id_from_location(invalid, "exports")


def test_expected_artifacts_are_canonical_and_csv_formula_safe() -> None:
    harness = load_harness()
    row = {
        "id": "00000000-0000-4000-8000-000000000301",
        "organization_id": "00000000-0000-4000-8000-000000000201",
        "requested_by_user_id": "00000000-0000-4000-8000-000000000101",
        "target": "\t=HYPERLINK(\"https://invalid.test\")",
        "status": "completed",
        "result_json": {"outcome": "blocked", "error_code": "invalid_target"},
        "correlation_id": "00000000-0000-4000-8000-000000000401",
        "created_at": "2026-07-23T01:02:03+00:00",
        "updated_at": "2026-07-23T01:02:04+00:00",
    }
    expected_json = (json.dumps([
        row | {
            "result_json": {"error_code": "invalid_target", "outcome": "blocked"},
            "created_at": "2026-07-23T01:02:03Z",
            "updated_at": "2026-07-23T01:02:04Z",
        }
    ], ensure_ascii=False, allow_nan=False, separators=(",", ":")) + "\n").encode()
    assert harness.expected_artifact([row], "json") == expected_json
    csv_bytes = harness.expected_artifact([row], "csv")
    assert csv_bytes.endswith(b"\r\n")
    assert b'"\'\t=HYPERLINK(""https://invalid.test"")"' in csv_bytes
    assert csv_bytes.split(b"\r\n", 1)[0].decode() == ",".join(harness.EXPORT_FIELDS)


def test_assert_mailpit_messages_requires_exact_delivery_identity_and_recipient() -> None:
    harness = load_harness()
    delivery_id = UUID("00000000-0000-4000-8000-000000000501")
    correlation_id = UUID("00000000-0000-4000-8000-000000000401")
    message = {
        "MessageID": f"{delivery_id}@signaldesk.local",
        "To": [{"Address": "analyst-a@signaldesk.test"}],
        "Headers": {
            "Message-ID": [f"<{delivery_id}@signaldesk.local>"],
            "X-SignalDesk-Delivery-ID": [str(delivery_id)],
            "X-SignalDesk-Correlation-ID": [str(correlation_id)],
        },
        "Text": "Synthetic notification",
    }
    harness.assert_mailpit_message(
        message,
        delivery_id=delivery_id,
        correlation_id=correlation_id,
        recipient="analyst-a@signaldesk.test",
        forbidden=("analyst-b@signaldesk.test", "secret-sentinel"),
    )
    with pytest.raises(AssertionError):
        harness.assert_mailpit_message(
            message | {"To": [{"Address": "analyst-b@signaldesk.test"}]},
            delivery_id=delivery_id,
            correlation_id=correlation_id,
            recipient="analyst-a@signaldesk.test",
            forbidden=(),
        )


def test_dlq_redaction_requires_enumerated_shape_and_no_raw_poison() -> None:
    harness = load_harness()
    fields = {
        "event": "sha256:" + "a" * 64,
        "event_id": "invalid",
        "failure_code": "invalid_event",
        "source_stream": "signaldesk:diagnostics",
        "source_id": "1-0",
        "attempt_count": "1",
    }
    harness.assert_dlq_entry(fields, "signaldesk:diagnostics", ("password-sentinel",))
    with pytest.raises(AssertionError):
        harness.assert_dlq_entry(fields | {"detail": "password-sentinel"}, "signaldesk:diagnostics", ("password-sentinel",))


def test_redis_dump_scan_decodes_binary_dump_before_secret_check() -> None:
    harness = load_harness()
    import base64

    safe = {"signaldesk:safe": base64.b64encode(b"binary-safe-value").decode("ascii")}
    harness.assert_redis_dumps_safe(safe, ("secret-sentinel",))

    leaked = {
        "signaldesk:leaked": base64.b64encode(
            b"binary-prefix-secret-sentinel-binary-suffix"
        ).decode("ascii")
    }
    with pytest.raises(AssertionError, match="Redis dump leaked"):
        harness.assert_redis_dumps_safe(leaked, ("secret-sentinel",))


def test_http_secret_scan_checks_raw_body_and_headers() -> None:
    harness = load_harness()
    safe = harness.HttpResult(200, {"Content-Type": "text/plain"}, b"safe")
    harness.assert_http_responses_safe((safe,), ("secret-sentinel",))
    with pytest.raises(AssertionError, match="body leaked"):
        harness.assert_http_responses_safe(
            (harness.HttpResult(200, {}, b"prefix-secret-sentinel-suffix"),),
            ("secret-sentinel",),
        )
    with pytest.raises(AssertionError, match="header leaked"):
        harness.assert_http_responses_safe(
            (harness.HttpResult(200, {"X-Test": "secret-sentinel"}, b"safe"),),
            ("secret-sentinel",),
        )


def test_crashpoint_records_real_owner_and_source_before_sigkill(monkeypatch) -> None:
    crashpoint = load_crashpoint()

    class Killed(Exception):
        pass

    class FakeRedis:
        def __init__(self) -> None:
            self.armed = True
            self.observed: dict[str, str] = {}

        def get(self, _key: str):
            return b"1" if self.armed else None

        def pipeline(self, *, transaction: bool):
            assert transaction is True
            outer = self

            class Pipeline:
                def delete(self, _key: str):
                    outer.armed = False
                    return self

                def hset(self, _key: str, *, mapping: dict[str, str]):
                    outer.observed = mapping
                    return self

                def execute(self):
                    return [1, 3]

            return Pipeline()

    class Consumer:
        def __init__(self) -> None:
            self.redis = FakeRedis()
            self.consumer_identity = "worker-label:0123456789abcdef"
            self.original_ack_called = False

        def _ack(self, _entry_id: bytes | str, _attempts: int) -> bool:
            self.original_ack_called = True
            return True

    monkeypatch.setattr(
        crashpoint.os,
        "kill",
        lambda _pid, _signal: (_ for _ in ()).throw(Killed()),
    )
    crashpoint._install_crashpoint(Consumer, "diagnostic")
    consumer = Consumer()
    with pytest.raises(Killed):
        consumer._ack(b"123-0", 2)
    assert consumer.original_ack_called is False
    assert consumer.redis.observed == {
        "source_id": "123-0",
        "owner": consumer.consumer_identity,
        "attempts": "2",
    }


def test_normalize_timestamp_only_accepts_aware_canonical_values() -> None:
    harness = load_harness()
    assert harness.normalize_timestamp("2026-07-23T01:02:03+00:00") == "2026-07-23T01:02:03Z"
    assert harness.normalize_timestamp("2026-07-23T01:02:03.123456+00:00") == "2026-07-23T01:02:03.123456Z"
    with pytest.raises(AssertionError):
        harness.normalize_timestamp("2026-07-23T01:02:03")
    with pytest.raises(AssertionError):
        harness.normalize_timestamp(datetime.now(timezone.utc))
