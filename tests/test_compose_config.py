from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "compose.yaml"
ENV_EXAMPLE = ROOT / ".env.example"
EXPECTED_SERVICES = {
    "postgres",
    "redis",
    "mailpit",
    "minio",
    "minio-init",
    "migrate",
    "seed",
    "control-api",
    "outbox-publisher",
    "web",
    "diagnostic-worker",
    "email-worker",
    "export-worker",
}
LONG_RUNNING = {
    "postgres",
    "redis",
    "mailpit",
    "minio",
    "control-api",
    "outbox-publisher",
    "web",
    "diagnostic-worker",
    "email-worker",
    "export-worker",
}
APPLICATIONS = {
    "control-api",
    "outbox-publisher",
    "web",
    "diagnostic-worker",
    "email-worker",
    "export-worker",
}
WORKERS = {"diagnostic-worker", "email-worker", "export-worker"}


def compose_config(*extra_files: str) -> dict[str, object]:
    command = [
        "docker",
        "compose",
        "--env-file",
        str(ENV_EXAMPLE),
        "-f",
        str(COMPOSE),
    ]
    for path in extra_files:
        command.extend(["-f", str(ROOT / path)])
    command.extend(["config", "--format", "json"])
    completed = subprocess.run(command, check=True, capture_output=True, text=True)
    return json.loads(completed.stdout)


@pytest.fixture(scope="module")
def config() -> dict[str, object]:
    return compose_config()


def test_compose_renders_all_task_13_services(config: dict[str, object]) -> None:
    assert set(config["services"]) == EXPECTED_SERVICES


def test_missing_required_secret_fails_closed(tmp_path: Path) -> None:
    filtered = "\n".join(
        line
        for line in ENV_EXAMPLE.read_text().splitlines()
        if not line.startswith("SIGNALDESK_WEB_BFF_SERVICE_CREDENTIAL=")
    )
    env_file = tmp_path / "missing-secret.env"
    env_file.write_text(filtered + "\n")
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("SIGNALDESK_") and not key.startswith("MINIO_")
    }

    completed = subprocess.run(
        [
            "docker",
            "compose",
            "--env-file",
            str(env_file),
            "-f",
            str(COMPOSE),
            "config",
        ],
        capture_output=True,
        text=True,
        env=environment,
    )

    assert completed.returncode != 0
    assert "SIGNALDESK_WEB_BFF_SERVICE_CREDENTIAL" in completed.stderr


def test_only_web_is_published_in_ordinary_profile(config: dict[str, object]) -> None:
    services = config["services"]
    published = {
        name: service.get("ports", [])
        for name, service in services.items()
        if service.get("ports")
    }
    assert set(published) == {"web"}
    assert published["web"] == [
        {
            "mode": "ingress",
            "target": 8080,
            "published": "8080",
            "protocol": "tcp",
            "host_ip": "127.0.0.1",
        }
    ]


def test_developer_override_publishes_only_mailpit_ui_on_loopback() -> None:
    config = compose_config("compose.dev.yaml")
    published = {
        name: service.get("ports", [])
        for name, service in config["services"].items()
        if service.get("ports")
    }
    assert set(published) == {"web", "mailpit"}
    assert published["mailpit"] == [
        {
            "mode": "ingress",
            "target": 8025,
            "published": "8025",
            "protocol": "tcp",
            "host_ip": "127.0.0.1",
        }
    ]


def test_health_checks_and_one_shot_ordering_are_explicit(config: dict[str, object]) -> None:
    services = config["services"]
    assert all(services[name].get("healthcheck") for name in LONG_RUNNING)
    assert services["migrate"]["restart"] == "no"
    assert services["seed"]["restart"] == "no"
    assert services["minio-init"]["restart"] == "no"
    assert services["migrate"]["depends_on"] == {
        "postgres": {"condition": "service_healthy", "required": True}
    }
    assert services["seed"]["depends_on"] == {
        "migrate": {"condition": "service_completed_successfully", "required": True}
    }
    for name in APPLICATIONS:
        assert services[name]["depends_on"]["migrate"]["condition"] == "service_completed_successfully"
        assert services[name]["depends_on"]["seed"]["condition"] == "service_completed_successfully"
        command_value = services[name].get("command") or []
        command = " ".join(command_value)
        assert "alembic" not in command
        assert "migrat" not in command.lower()


def test_service_credentials_labels_streams_and_hostnames_are_exact(config: dict[str, object]) -> None:
    services = config["services"]
    control = services["control-api"]["environment"]
    credentials = {
        control["SIGNALDESK_WEB_BFF_SERVICE_CREDENTIAL"],
        control["SIGNALDESK_DIAGNOSTIC_WORKER_SERVICE_CREDENTIAL"],
        control["SIGNALDESK_EMAIL_WORKER_SERVICE_CREDENTIAL"],
        control["SIGNALDESK_EXPORT_WORKER_SERVICE_CREDENTIAL"],
    }
    assert len(credentials) == 4
    assert all(len(value) >= 32 for value in credentials)

    assert {
        "SIGNALDESK_DIAGNOSTIC_WORKER_CONTROL_API_BASE_URL": "http://control-api:8000",
        "SIGNALDESK_DIAGNOSTIC_WORKER_REDIS_URL": "redis://redis:6379/0",
        "SIGNALDESK_DIAGNOSTIC_WORKER_STREAM_NAME": "signaldesk:diagnostics",
        "SIGNALDESK_DIAGNOSTIC_WORKER_CONSUMER_GROUP": "diagnostic-workers",
        "SIGNALDESK_DIAGNOSTIC_WORKER_CONSUMER_NAME": "diagnostic-worker-local",
    }.items() <= services["diagnostic-worker"]["environment"].items()
    assert {
        "SIGNALDESK_EMAIL_WORKER_CONTROL_API_BASE_URL": "http://control-api:8000",
        "SIGNALDESK_EMAIL_WORKER_REDIS_URL": "redis://redis:6379/0",
        "SIGNALDESK_EMAIL_WORKER_MAILPIT_API_BASE_URL": "http://mailpit:8025",
        "SIGNALDESK_EMAIL_WORKER_SMTP_HOST": "mailpit",
        "SIGNALDESK_EMAIL_WORKER_SMTP_PORT": "1025",
        "SIGNALDESK_EMAIL_WORKER_STREAM_NAME": "signaldesk:emails",
        "SIGNALDESK_EMAIL_WORKER_CONSUMER_GROUP": "email-workers",
        "SIGNALDESK_EMAIL_WORKER_CONSUMER_NAME": "email-worker-local",
    }.items() <= services["email-worker"]["environment"].items()
    assert {
        "SIGNALDESK_EXPORT_WORKER_CONTROL_API_BASE_URL": "http://control-api:8000",
        "SIGNALDESK_EXPORT_WORKER_REDIS_URL": "redis://redis:6379/0",
        "SIGNALDESK_EXPORT_WORKER_MINIO_ENDPOINT": "http://minio:9000",
        "SIGNALDESK_EXPORT_WORKER_MINIO_BUCKET": "signaldesk-exports",
        "SIGNALDESK_EXPORT_WORKER_STREAM_NAME": "signaldesk:exports",
        "SIGNALDESK_EXPORT_WORKER_CONSUMER_GROUP": "export-workers",
        "SIGNALDESK_EXPORT_WORKER_CONSUMER_NAME": "export-worker-local",
    }.items() <= services["export-worker"]["environment"].items()


def test_datastores_are_isolated_and_runtime_is_hardened(config: dict[str, object]) -> None:
    services = config["services"]
    networks = config["networks"]
    assert networks["edge"].get("internal") is not True
    assert all(
        networks[name].get("internal") is True
        for name in {"data", "service", "mail", "object"}
    )
    assert set(services["web"]["networks"]) == {"service", "edge"}
    assert all("edge" not in service.get("networks", {}) for name, service in services.items() if name != "web")
    for name, service in services.items():
        assert "/var/run/docker.sock" not in json.dumps(service)
        assert service.get("privileged") is not True
        assert service.get("cap_add") in (None, [])
        if name not in {"postgres", "minio"}:
            assert service.get("read_only") is True
        if name in APPLICATIONS:
            assert service.get("user") == "10001:10001"
            assert service["environment"]["HTTP_PROXY"] == ""
            assert service["environment"]["HTTPS_PROXY"] == ""
            assert service["environment"]["ALL_PROXY"] == ""
    assert not services["postgres"].get("ports")
    assert not services["redis"].get("ports")
    assert not services["minio"].get("ports")
    assert not services["control-api"].get("ports")
    assert all(not services[name].get("ports") for name in WORKERS)


def test_images_and_python_bases_are_pinned() -> None:
    text = COMPOSE.read_text()
    images = re.findall(r"^\s*image:\s*(\S+)", text, flags=re.MULTILINE)
    assert images
    assert all(":latest" not in image and "@sha256:" in image for image in images)
    for repository in (
        "signaldesk-control-api",
        "signaldesk-diagnostic-worker",
        "signaldesk-email-worker",
        "signaldesk-export-worker",
        "signaldesk-web",
    ):
        dockerfile = ROOT.parent / repository / "Dockerfile"
        dockerfile_text = dockerfile.read_text()
        first_line = dockerfile_text.splitlines()[0]
        assert re.fullmatch(r"FROM python:3\.11\.\d+-slim-bookworm@sha256:[0-9a-f]{64}", first_line)
        assert " uv.lock /build/" in dockerfile_text
        assert "uv sync --locked --no-dev --no-editable" in dockerfile_text
        assert "uv pip install" not in dockerfile_text


def test_control_runtime_server_is_declared_in_project_lock() -> None:
    project = (ROOT.parent / "signaldesk-control-api" / "pyproject.toml").read_text()
    lock = (ROOT.parent / "signaldesk-control-api" / "uv.lock").read_text()
    assert '"uvicorn==0.35.0"' in project
    assert 'name = "uvicorn"' in lock


def test_runtime_scripts_are_readable_by_nonroot_images() -> None:
    repositories = (
        "signaldesk-control-api",
        "signaldesk-diagnostic-worker",
        "signaldesk-email-worker",
        "signaldesk-export-worker",
        "signaldesk-web",
    )
    for repository in repositories:
        dockerfile = (ROOT.parent / repository / "Dockerfile").read_text()
        assert "chmod 0555 /opt/signaldesk/" in dockerfile
    control_dockerfile = (ROOT.parent / "signaldesk-control-api" / "Dockerfile").read_text()
    assert "chmod -R a=rX /app/alembic /app/alembic.ini" in control_dockerfile


def test_minio_nonroot_data_mount_is_writable(config: dict[str, object]) -> None:
    minio = config["services"]["minio"]
    assert minio["user"] == "1000:1000"
    assert any(
        entry.startswith("/data:rw") and "uid=1000" in entry and "gid=1000" in entry
        for entry in minio["tmpfs"]
    )
    assert not minio.get("volumes")


def test_minio_policy_preserves_private_immutable_replay_objects() -> None:
    policy = json.loads((ROOT / "config" / "minio-export-worker-policy.json").read_text())
    serialized = json.dumps(policy)
    assert "s3:PutObject" in serialized
    assert "s3:GetObject" in serialized
    assert "s3:DeleteObject" not in serialized
    assert "s3:PutBucketPolicy" not in serialized
    assert "signaldesk-exports/exports/*" in serialized

    bootstrap = (ROOT / "scripts" / "minio-init.sh").read_text()
    assert "anonymous set none" in bootstrap
    assert "--with-lock" in bootstrap
    assert "retention set --default COMPLIANCE 7d" in bootstrap
    assert "ilm rule import" in bootstrap
    assert "ilm rule add" not in bootstrap
    lifecycle = json.loads((ROOT / "config" / "minio-lifecycle.json").read_text())
    assert lifecycle == {
        "Rules": [
            {
                "ID": "signaldesk-exports-expire-30-days",
                "Status": "Enabled",
                "Filter": {"Prefix": "exports/"},
                "Expiration": {"Days": 30},
            }
        ]
    }
    assert "grep" not in bootstrap
    verifier = (ROOT / "scripts" / "verify-runtime.py").read_text()
    assert "is `private`" in verifier
    assert 'retention.get("mode") == "COMPLIANCE"' in verifier
    assert 'retention.get("validity") == "7DAYS"' in verifier
    assert "wrong-one-day-rule" in verifier


def test_export_entrypoint_preserves_strict_settings_with_current_pydantic_sources(
    config: dict[str, object],
) -> None:
    assert config["services"]["export-worker"]["command"] == [
        "python",
        "/opt/signaldesk/export_worker_entrypoint.py",
    ]
    dockerfile = (ROOT.parent / "signaldesk-export-worker" / "Dockerfile").read_text()
    assert "scripts/export_worker_entrypoint.py" in dockerfile
    entrypoint = (ROOT / "scripts" / "export_worker_entrypoint.py").read_text()
    assert "Settings(" in entrypoint
    assert "SIGNALDESK_EXPORT_WORKER_CONTROL_API_BASE_URL" in entrypoint


def test_postgres_readiness_and_verifier_use_authenticated_queries(
    config: dict[str, object],
) -> None:
    postgres_environment = config["services"]["postgres"]["environment"]
    assert postgres_environment["PGPASSWORD"] == postgres_environment["POSTGRES_PASSWORD"]


def test_runtime_verifier_includes_exited_one_shot_containers() -> None:
    verifier = (ROOT / "scripts" / "verify-runtime.py").read_text()
    assert 'run("ps", "--all", "-q", service)' in verifier


def test_runtime_verifier_uses_writable_minio_client_config() -> None:
    verifier = (ROOT / "scripts" / "verify-runtime.py").read_text()
    assert "export MC_CONFIG_DIR=/tmp/mc" in verifier


def test_runtime_verifier_inspects_effective_port_bindings() -> None:
    verifier = (ROOT / "scripts" / "verify-runtime.py").read_text()
    assert 'inspected["NetworkSettings"]["Ports"]' in verifier
    assert '["docker", "port"' not in verifier
    assert 'http://127.0.0.1:8080/healthz' in verifier


def test_runtime_verifier_covers_required_live_boundaries() -> None:
    verifier = (ROOT / "scripts" / "verify-runtime.py").read_text()
    for marker in (
        "service discovery",
        "cluster_enabled:0",
        "alembic_version",
        "IfNoneMatch",
        "PreconditionFailed",
        "canonical",
        "AccessDenied",
        "public",
        "published ports",
    ):
        assert marker in verifier
