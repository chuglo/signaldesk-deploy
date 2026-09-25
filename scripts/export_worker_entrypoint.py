#!/usr/bin/env python3
"""Start export worker with explicit validated init values.

Pydantic Settings 2.14 pre-coerces ``AnyHttpUrl`` environment sources before
the worker's secret-masking model validator. Supplying the same environment
value through the higher-priority init source preserves that validator's
fail-closed contract without changing application code.
"""

from __future__ import annotations

import os
from signal import SIGINT, SIGTERM, getsignal, signal
from threading import Event

from signaldesk_export_worker.cli import make_stop_handler, run_worker
from signaldesk_export_worker.settings import Settings


def required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"required configuration is absent: {name}")
    return value


def load_settings() -> Settings:
    return Settings(
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


def main() -> None:
    stop = Event()
    handler = make_stop_handler(stop)
    previous = {SIGTERM: getsignal(SIGTERM), SIGINT: getsignal(SIGINT)}
    signal(SIGTERM, handler)
    signal(SIGINT, handler)
    try:
        run_worker(load_settings(), stop_event=stop)
    finally:
        signal(SIGTERM, previous[SIGTERM])
        signal(SIGINT, previous[SIGINT])


if __name__ == "__main__":
    main()
