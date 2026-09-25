#!/usr/bin/env python3
"""Verify Task 13 runtime readiness without implementing Task 14 workflows."""

from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path
import subprocess
import sys
import textwrap
from typing import Any
from urllib.request import ProxyHandler, build_opener


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = [
    "docker",
    "compose",
    "--env-file",
    str(ROOT / ".env.example"),
    "-f",
    str(ROOT / "compose.yaml"),
]
APPLICATIONS = (
    "control-api",
    "outbox-publisher",
    "web",
    "diagnostic-worker",
    "email-worker",
    "export-worker",
)
EXPECTED_LIFECYCLE = json.loads(
    (ROOT / "config" / "minio-lifecycle.json").read_text(encoding="utf-8")
)


def run(*arguments: str, capture: bool = True) -> str:
    completed = subprocess.run(
        [*COMPOSE, *arguments],
        cwd=ROOT,
        check=True,
        capture_output=capture,
        text=True,
    )
    return completed.stdout.strip() if capture else ""


def minio_admin(command: str) -> str:
    return run(
        "run",
        "--rm",
        "--no-deps",
        "--entrypoint",
        "/bin/sh",
        "minio-init",
        "-c",
        "export MC_CONFIG_DIR=/tmp/mc && "
        "mc alias set local http://minio:9000 \"$MINIO_ROOT_USER\" "
        "\"$MINIO_ROOT_PASSWORD\" >/dev/null && "
        + command,
    )


def read_minio_lifecycle_and_retention() -> tuple[dict[str, Any], dict[str, Any]]:
    lifecycle = json.loads(minio_admin("mc ilm rule export local/signaldesk-exports"))
    retention = json.loads(
        minio_admin(
            "mc retention info --default --json local/signaldesk-exports"
        )
    )
    return lifecycle, retention


def assert_exact_minio_lifecycle_and_retention(
    lifecycle: dict[str, Any], retention: dict[str, Any]
) -> None:
    assert lifecycle == EXPECTED_LIFECYCLE, lifecycle
    assert retention.get("enabled") == "Enabled", retention
    assert retention.get("mode") == "COMPLIANCE", retention
    assert retention.get("validity") == "7DAYS", retention
    assert retention.get("status") == "success", retention


def docker_inspect(container_id: str) -> dict[str, Any]:
    completed = subprocess.run(
        ["docker", "inspect", container_id], check=True, capture_output=True, text=True
    )
    return json.loads(completed.stdout)[0]


def container_id(service: str) -> str:
    identifier = run("ps", "--all", "-q", service)
    if not identifier:
        raise AssertionError(f"{service} has no container")
    return identifier


def assert_runtime_states() -> None:
    migrate = docker_inspect(container_id("migrate"))
    migrate_state = migrate["State"]
    assert migrate_state["Status"] == "exited"
    assert migrate_state["ExitCode"] == 0
    assert migrate["RestartCount"] == 0
    migration_finished = datetime.fromisoformat(
        migrate_state["FinishedAt"].replace("Z", "+00:00")
    )

    for service in APPLICATIONS:
        inspected = docker_inspect(container_id(service))
        state = inspected["State"]
        assert state["Status"] == "running", (service, state)
        assert state["Health"]["Status"] == "healthy", (service, state["Health"])
        started = datetime.fromisoformat(state["StartedAt"].replace("Z", "+00:00"))
        assert started >= migration_finished, f"{service} started before migration completed"

    for service in ("postgres", "redis", "mailpit", "minio"):
        state = docker_inspect(container_id(service))["State"]
        assert state["Status"] == "running"
        assert state["Health"]["Status"] == "healthy"


def assert_migration_and_seed() -> None:
    # One migration container, no restarts, one Alembic head row: migrations exactly once.
    result = run(
        "exec",
        "-T",
        "postgres",
        "psql",
        "-U",
        "signaldesk_app",
        "-d",
        "signaldesk",
        "-Atc",
        "SELECT version_num FROM alembic_version",
    )
    assert result == "20260723_0007", result
    counts = run(
        "exec",
        "-T",
        "postgres",
        "psql",
        "-U",
        "signaldesk_app",
        "-d",
        "signaldesk",
        "-Atc",
        "SELECT (SELECT count(*) FROM users), (SELECT count(*) FROM organizations), "
        "(SELECT count(*) FROM memberships)",
    )
    assert counts == "2|2|2", counts


def assert_service_discovery() -> None:
    # service discovery: each process resolves only the exact local hostnames it needs.
    matrix = {
        "control-api": ("postgres", "redis"),
        "outbox-publisher": ("postgres", "redis"),
        "web": ("control-api",),
        "diagnostic-worker": ("redis", "control-api"),
        "email-worker": ("redis", "control-api", "mailpit"),
        "export-worker": ("redis", "control-api", "minio"),
    }
    for service, names in matrix.items():
        code = (
            "import socket; names="
            + repr(names)
            + "; assert all(socket.getaddrinfo(name, None) for name in names); print('ok')"
        )
        assert run("exec", "-T", service, "python", "-c", code) == "ok"


def assert_redis_standalone() -> None:
    assert run("exec", "-T", "redis", "redis-cli", "PING") == "PONG"
    info = run("exec", "-T", "redis", "redis-cli", "INFO", "cluster")
    assert "cluster_enabled:0" in info


def assert_object_store_boundaries() -> None:
    # Exercise MinIO conditional PUT support plus canonical/final permissions.
    probe = textwrap.dedent(
        """
        import os
        from uuid import uuid4
        import boto3
        from botocore import UNSIGNED
        from botocore.config import Config
        from botocore.exceptions import ClientError

        endpoint = "http://minio:9000"
        bucket = "signaldesk-exports"
        client = boto3.client(
            "s3", endpoint_url=endpoint,
            aws_access_key_id=os.environ["SIGNALDESK_EXPORT_WORKER_MINIO_ACCESS_KEY"],
            aws_secret_access_key=os.environ["SIGNALDESK_EXPORT_WORKER_MINIO_SECRET_KEY"],
            config=Config(signature_version="s3v4", proxies={}, s3={"addressing_style": "path"}),
        )
        token = uuid4().hex
        keys = (
            f"exports/runtime-verification/{token}.json",
            f"exports/.canonical/runtime-verification/{token}/snapshot.json",
        )
        for key in keys:
            client.put_object(Bucket=bucket, Key=key, Body=b"{}", IfNoneMatch="*", ContentType="application/json")
            try:
                client.put_object(Bucket=bucket, Key=key, Body=b"changed", IfNoneMatch="*", ContentType="application/json")
            except ClientError as error:
                assert error.response["Error"]["Code"] in {"PreconditionFailed", "412"}
            else:
                raise AssertionError("MinIO accepted a duplicate conditional PUT")
            assert client.get_object(Bucket=bucket, Key=key)["Body"].read() == b"{}"
            try:
                client.delete_object(Bucket=bucket, Key=key)
            except ClientError as error:
                assert error.response["Error"]["Code"] == "AccessDenied"
            else:
                raise AssertionError("worker can delete immutable export object")

        public = boto3.client(
            "s3", endpoint_url=endpoint,
            config=Config(signature_version=UNSIGNED, proxies={}, s3={"addressing_style": "path"}),
        )
        try:
            public.get_object(Bucket=bucket, Key=keys[0])
        except ClientError as error:
            assert error.response["Error"]["Code"] in {"AccessDenied", "403"}
        else:
            raise AssertionError("public object read unexpectedly succeeded")
        print("conditional/canonical/final/AccessDenied/public: ok")
        """
    )
    result = run("exec", "-T", "export-worker", "python", "-c", probe)
    assert "conditional/canonical/final/AccessDenied/public: ok" in result

    # Read root-only policy state without exposing root credentials to application
    # containers. Prove drift is detected, then prove bootstrap reconciles it.
    lifecycle, retention = read_minio_lifecycle_and_retention()
    assert_exact_minio_lifecycle_and_retention(lifecycle, retention)

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
    encoded_wrong = json.dumps(wrong_lifecycle, separators=(",", ":"))
    minio_admin(
        f"printf '%s' '{encoded_wrong}' | mc ilm rule import local/signaldesk-exports"
    )
    drifted_lifecycle, drifted_retention = read_minio_lifecycle_and_retention()
    try:
        assert_exact_minio_lifecycle_and_retention(
            drifted_lifecycle, drifted_retention
        )
    except AssertionError:
        pass
    else:
        raise AssertionError("one-day MinIO lifecycle drift was not detected")

    run("run", "--rm", "minio-init")
    repaired_lifecycle, repaired_retention = read_minio_lifecycle_and_retention()
    assert_exact_minio_lifecycle_and_retention(
        repaired_lifecycle, repaired_retention
    )

    policy_state = minio_admin("mc anonymous get local/signaldesk-exports")
    print(policy_state)
    assert "Access permission for `local/signaldesk-exports` is `private`" in policy_state


def assert_published_ports() -> None:
    # published ports: only web is host-reachable in the ordinary profile.
    published: dict[str, dict[str, object]] = {}
    for service in (
        "postgres",
        "redis",
        "mailpit",
        "minio",
        "control-api",
        "diagnostic-worker",
        "email-worker",
        "export-worker",
        "web",
    ):
        inspected = docker_inspect(container_id(service))
        port_map = inspected["NetworkSettings"]["Ports"]
        bound = {port: bindings for port, bindings in port_map.items() if bindings}
        if bound:
            published[service] = bound
    assert set(published) == {"web"}, published
    assert published["web"] == {
        "8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8080"}]
    }
    opener = build_opener(ProxyHandler({}))
    with opener.open("http://127.0.0.1:8080/healthz", timeout=3) as response:
        assert response.status == 200
        assert json.loads(response.read(1024)) == {"status": "ok"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.parse_args(argv)
    checks = (
        ("startup ordering and health", assert_runtime_states),
        ("migrations exactly once and synthetic seed", assert_migration_and_seed),
        ("service discovery", assert_service_discovery),
        ("Redis standalone", assert_redis_standalone),
        ("MinIO conditional PUT and object boundaries", assert_object_store_boundaries),
        ("published ports", assert_published_ports),
    )
    for label, check in checks:
        check()
        print(f"PASS: {label}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, subprocess.CalledProcessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1) from None
