#!/usr/bin/env python3
"""Dependency-aware container health checks with proxy-free network probes."""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
from typing import Any
from urllib.request import ProxyHandler, build_opener


def _http_ok(url: str, *, expected_json: dict[str, str] | None = None) -> None:
    opener = build_opener(ProxyHandler({}))
    with opener.open(url, timeout=3) as response:
        if response.status != 200:
            raise RuntimeError("HTTP dependency is not ready")
        body = response.read(4097)
    if len(body) > 4096:
        raise RuntimeError("HTTP health response is oversized")
    if expected_json is not None and json.loads(body) != expected_json:
        raise RuntimeError("HTTP health response is invalid")


def _redis_command(host: str, port: int, *parts: str) -> bytes:
    encoded = [part.encode("ascii") for part in parts]
    request = f"*{len(encoded)}\r\n".encode("ascii") + b"".join(
        f"${len(part)}\r\n".encode("ascii") + part + b"\r\n" for part in encoded
    )
    with socket.create_connection((host, port), timeout=3) as connection:
        connection.settimeout(3)
        connection.sendall(request)
        chunks: list[bytes] = []
        while sum(map(len, chunks)) <= 65536:
            chunk = connection.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
            if b"\r\n" in chunk and chunks[0][:1] in {b"+", b"-", b":"}:
                break
            if chunks[0][:1] == b"$" and b"\r\n" in b"".join(chunks)[1:]:
                raw = b"".join(chunks)
                header, _, body = raw.partition(b"\r\n")
                expected = int(header[1:])
                if len(body) >= expected + 2:
                    break
    response = b"".join(chunks)
    if not response or response.startswith(b"-"):
        raise RuntimeError("Redis dependency is not ready")
    return response


def _redis_ready(url: str) -> None:
    from urllib.parse import urlsplit

    parsed = urlsplit(url)
    if parsed.scheme != "redis" or parsed.hostname != "redis" or parsed.port not in {None, 6379}:
        raise RuntimeError("Redis URL is outside the Compose fixture")
    if _redis_command("redis", 6379, "PING") != b"+PONG\r\n":
        raise RuntimeError("Redis PING failed")
    info = _redis_command("redis", 6379, "INFO", "cluster")
    if b"cluster_enabled:0" not in info:
        raise RuntimeError("Redis must be standalone/nonclustered")


def _psycopg_url(url: str) -> str:
    prefix = "postgresql+psycopg://"
    if not url.startswith(prefix):
        raise RuntimeError("PostgreSQL URL must use the psycopg SQLAlchemy driver")
    return "postgresql://" + url[len(prefix) :]


def _postgres_ready(url: str) -> None:
    import psycopg

    with psycopg.connect(_psycopg_url(url), connect_timeout=3) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            if cursor.fetchone() != (1,):
                raise RuntimeError("PostgreSQL readiness query failed")


def _smtp_ready() -> None:
    with socket.create_connection(("mailpit", 1025), timeout=3) as connection:
        connection.settimeout(3)
        if not connection.recv(1024).startswith(b"220"):
            raise RuntimeError("Mailpit SMTP is not ready")
        connection.sendall(b"QUIT\r\n")


def _control_api_ready() -> None:
    _http_ok("http://control-api:8000/healthz", expected_json={"status": "ok"})


def check(role: str) -> None:
    if role == "control-api":
        from signaldesk_control_api.settings import Settings

        settings = Settings()  # type: ignore[call-arg]
        _postgres_ready(settings.database_url.unicode_string())
        _redis_ready(settings.redis_url.unicode_string())
        _http_ok("http://127.0.0.1:8000/healthz", expected_json={"status": "ok"})
    elif role == "outbox-publisher":
        from signaldesk_control_api.settings import OutboxPublisherSettings

        settings = OutboxPublisherSettings()  # type: ignore[call-arg]
        _postgres_ready(settings.database_url.unicode_string())
        _redis_ready(settings.redis_url.unicode_string())
    elif role == "web":
        from signaldesk_web.settings import Settings

        Settings()  # type: ignore[call-arg]
        _control_api_ready()
        _http_ok("http://127.0.0.1:8080/healthz", expected_json={"status": "ok"})
    elif role == "diagnostic-worker":
        from signaldesk_diagnostic_worker.settings import Settings

        settings = Settings()  # type: ignore[call-arg]
        _redis_ready(settings.redis_url.get_secret_value())
        _control_api_ready()
    elif role == "email-worker":
        from signaldesk_email_worker.settings import Settings

        settings = Settings()  # type: ignore[call-arg]
        _redis_ready(settings.redis_url.get_secret_value())
        _control_api_ready()
        _http_ok("http://mailpit:8025/livez")
        _smtp_ready()
    elif role == "export-worker":
        from export_worker_entrypoint import load_settings

        settings = load_settings()
        _redis_ready(settings.redis_url.get_secret_value())
        _control_api_ready()
        _http_ok("http://minio:9000/minio/health/ready")
    else:
        raise RuntimeError("unknown health-check role")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("role")
    arguments = parser.parse_args(argv)
    try:
        check(arguments.role)
    except Exception as error:
        print(f"not ready: {type(error).__name__}", file=sys.stderr)
        return 1
    print(f"ready: {arguments.role}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
