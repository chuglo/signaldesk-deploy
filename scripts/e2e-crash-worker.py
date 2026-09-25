#!/usr/bin/env python3
"""E2E-only deterministic crash point after side effects and before Redis XACK."""

from __future__ import annotations

import os
import sys
from typing import Any


_VALID_SERVICES = {"diagnostic", "email", "export"}


def _source_id(entry_id: bytes | str) -> str:
    return entry_id.decode("ascii", "strict") if isinstance(entry_id, bytes) else entry_id


def _install_crashpoint(consumer_class: type[Any], service: str) -> None:
    original_ack = consumer_class._ack
    armed_key = f"signaldesk:task14:crash:armed:{service}"
    observed_key = f"signaldesk:task14:crash:observed:{service}"

    def crash_before_ack(self: Any, entry_id: bytes | str, attempts: int) -> bool:
        if self.redis.get(armed_key) == b"1":
            source_id = _source_id(entry_id)
            identity = getattr(
                self,
                "consumer_identity",
                getattr(self, "_consumer_identity", None),
            )
            if not isinstance(identity, str) or not identity:
                raise RuntimeError("Task 14 crashpoint could not read consumer identity")
            transaction = self.redis.pipeline(transaction=True)
            transaction.delete(armed_key)
            transaction.hset(
                observed_key,
                mapping={
                    "source_id": source_id,
                    "owner": identity,
                    "attempts": str(attempts),
                },
            )
            transaction.execute()
            os.kill(os.getpid(), 9)
            raise RuntimeError("SIGKILL crashpoint returned unexpectedly")
        return original_ack(self, entry_id, attempts)

    consumer_class._ack = crash_before_ack


def main(argv: list[str] | None = None) -> None:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments not in (["diagnostic"], ["email"], ["export"]):
        raise SystemExit("usage: e2e-crash-worker.py diagnostic|email|export")
    service = arguments[0]
    assert service in _VALID_SERVICES

    if service == "diagnostic":
        from signaldesk_diagnostic_worker import cli
        from signaldesk_diagnostic_worker.consumer import DiagnosticConsumer

        _install_crashpoint(DiagnosticConsumer, service)
        cli.main([])
        return
    if service == "email":
        from signaldesk_email_worker import cli
        from signaldesk_email_worker.consumer import EmailConsumer

        _install_crashpoint(EmailConsumer, service)
        cli.main([])
        return

    from signaldesk_export_worker.consumer import ExportConsumer
    from signaldesk_export_worker.cli import run_worker
    from signaldesk_export_worker.settings import Settings

    _install_crashpoint(ExportConsumer, service)
    # Mirror the accepted Compose init-source workaround without importing a
    # script outside this mounted E2E wrapper.
    def required(name: str) -> str:
        value = os.environ.get(name, "")
        if not value:
            raise RuntimeError(f"required E2E worker configuration is absent: {name}")
        return value

    settings = Settings(
        redis_url=required("SIGNALDESK_EXPORT_WORKER_REDIS_URL"),
        control_api_base_url=required(
            "SIGNALDESK_EXPORT_WORKER_CONTROL_API_BASE_URL"
        ),
        export_worker_service_credential=required(
            "SIGNALDESK_EXPORT_WORKER_EXPORT_WORKER_SERVICE_CREDENTIAL"
        ),
        consumer_name=required("SIGNALDESK_EXPORT_WORKER_CONSUMER_NAME"),
        minio_access_key=required("SIGNALDESK_EXPORT_WORKER_MINIO_ACCESS_KEY"),
        minio_secret_key=required("SIGNALDESK_EXPORT_WORKER_MINIO_SECRET_KEY"),
    )
    run_worker(settings)


if __name__ == "__main__":
    main()
