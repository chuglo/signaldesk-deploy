#!/usr/bin/env python3
"""Task 14 deterministic full-stack SignalDesk verification harness."""

from __future__ import annotations

import argparse
import base64
from http.cookiejar import CookieJar
import csv
from datetime import datetime, timezone
from html import unescape
from html.parser import HTMLParser
from io import StringIO
import json
from pathlib import Path
import re
import subprocess
import sys
import time
import traceback
import unicodedata
from typing import Any, NamedTuple, Sequence
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    HTTPCookieProcessor,
    ProxyHandler,
    Request,
    build_opener,
)
from uuid import UUID, uuid4


ROOT = Path(__file__).resolve().parents[1]
MAX_HTML_BYTES = 65_536
EXPORT_FIELDS = (
    "id",
    "organization_id",
    "requested_by_user_id",
    "target",
    "status",
    "result_json",
    "correlation_id",
    "created_at",
    "updated_at",
)
_DLQ_FIELDS = {
    "event",
    "event_id",
    "failure_code",
    "source_stream",
    "source_id",
    "attempt_count",
}
_SAFE_FAILURE_CODES = {
    "invalid_stream_fields",
    "oversized_event",
    "invalid_event_id",
    "invalid_event",
    "event_id_mismatch",
    "job_not_found",
    "delivery_not_found",
    "scope_mismatch",
    "delivery_failed",
    "invalid_authority",
    "smtp_terminal",
    "existing_object_mismatch",
    "export_too_large_or_invalid",
}


class _CsrfParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tokens: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        del tag
        values = dict(attrs)
        if values.get("name") == "csrf_token" and values.get("value") is not None:
            self.tokens.append(values["value"] or "")


def extract_csrf(body: bytes) -> str:
    assert len(body) <= MAX_HTML_BYTES, "HTML response too large"
    parser = _CsrfParser()
    try:
        parser.feed(body.decode("utf-8", "strict"))
    except (UnicodeDecodeError, ValueError):
        raise AssertionError("invalid login HTML") from None
    assert len(parser.tokens) == 1, "expected exactly one CSRF token"
    token = parser.tokens[0]
    assert 8 <= len(token) <= 256 and re.fullmatch(r"[A-Za-z0-9_-]+", token), (
        "invalid CSRF token"
    )
    return token


def job_id_from_location(location: str, resource: str) -> UUID:
    assert resource in {"diagnostics", "exports"}
    parsed = urlsplit(location)
    assert not parsed.scheme and not parsed.netloc and not parsed.query and not parsed.fragment
    match = re.fullmatch(rf"/{resource}/([0-9a-f]{{8}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{12}})", parsed.path)
    assert match is not None, f"invalid {resource} redirect"
    identifier = UUID(match.group(1))
    assert str(identifier) == match.group(1)
    return identifier


def normalize_timestamp(value: object) -> str:
    assert isinstance(value, str), "timestamp must be text"
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise AssertionError("timestamp must be ISO-8601") from None
    assert parsed.tzinfo is not None and parsed.utcoffset() is not None, (
        "timestamp must be timezone-aware"
    )
    normalized = parsed.isoformat().replace("+00:00", "Z")
    assert normalized.endswith("Z"), "timestamp must normalize to UTC"
    return normalized


def _protect_csv(value: str) -> str:
    if value.startswith(("=", "+", "-", "@", "\t", "\r", "\n")):
        return "'" + value
    index = 0
    while index < len(value):
        character = value[index]
        if not (character.isspace() or unicodedata.category(character) in {"Cc", "Cf"}):
            break
        index += 1
    return "'" + value if index < len(value) and value[index] in "=+-@" else value


def _normalized_row(row: dict[str, Any]) -> dict[str, Any]:
    assert set(row) == set(EXPORT_FIELDS), f"unexpected snapshot fields: {set(row)}"
    normalized = dict(row)
    for field in ("id", "organization_id", "requested_by_user_id", "correlation_id"):
        assert isinstance(normalized[field], str)
        assert str(UUID(normalized[field])) == normalized[field]
    assert isinstance(normalized["target"], str)
    assert isinstance(normalized["status"], str)
    assert normalized["result_json"] is None or isinstance(normalized["result_json"], dict)
    if normalized["result_json"] is not None:
        normalized["result_json"] = json.loads(
            json.dumps(
                normalized["result_json"],
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
    normalized["created_at"] = normalize_timestamp(normalized["created_at"])
    normalized["updated_at"] = normalize_timestamp(normalized["updated_at"])
    return normalized


def expected_artifact(rows: Sequence[dict[str, Any]], export_format: str) -> bytes:
    normalized = [_normalized_row(row) for row in rows]
    if export_format == "json":
        return (
            json.dumps(
                normalized,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
    assert export_format == "csv", "unsupported export format"
    output = StringIO(newline="")
    writer = csv.writer(output, dialect="excel", lineterminator="\r\n")
    writer.writerow(EXPORT_FIELDS)
    for row in normalized:
        rendered: list[str] = []
        for field in EXPORT_FIELDS:
            value = row[field]
            if field == "result_json":
                value = "" if value is None else json.dumps(
                    value,
                    ensure_ascii=False,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
            rendered.append(_protect_csv(str(value)))
        writer.writerow(rendered)
    return output.getvalue().encode("utf-8")


def assert_no_forbidden(value: object, forbidden: Sequence[str]) -> None:
    rendered = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    for sentinel in forbidden:
        assert sentinel not in rendered, f"forbidden value leaked: {sentinel}"


def assert_http_responses_safe(
    responses: Sequence[HttpResult], forbidden: Sequence[str]
) -> None:
    for response in responses:
        header_bytes = "\n".join(
            f"{name}: {value}" for name, value in response.headers.items()
        ).encode("utf-8", "strict")
        for sentinel in forbidden:
            encoded = sentinel.encode("utf-8")
            assert encoded not in response.body, "HTTP response body leaked forbidden value"
            assert encoded not in header_bytes, "HTTP response header leaked forbidden value"


def assert_redis_dumps_safe(
    dumps: dict[str, str], forbidden: Sequence[str]
) -> None:
    assert_no_forbidden(tuple(dumps), forbidden)
    for key, encoded in dumps.items():
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError):
            raise AssertionError(f"invalid Redis dump encoding for {key}") from None
        for sentinel in forbidden:
            assert sentinel.encode("utf-8") not in raw, (
                f"Redis dump leaked forbidden value in {key}"
            )


def assert_mailpit_message(
    message: dict[str, Any],
    *,
    delivery_id: UUID,
    correlation_id: UUID,
    recipient: str,
    forbidden: Sequence[str],
) -> None:
    assert set(message) >= {"MessageID", "To", "Headers", "Text"}, set(message)
    assert message["MessageID"] == f"{delivery_id}@signaldesk.local", message["MessageID"]
    recipients = message["To"]
    assert isinstance(recipients, list) and len(recipients) == 1, recipients
    recipient_record = recipients[0]
    assert isinstance(recipient_record, dict), recipient_record
    assert set(recipient_record) <= {"Address", "Name"}, recipient_record
    assert recipient_record.get("Address") == recipient, recipient_record
    assert recipient_record.get("Name", "") == "", recipient_record
    headers = message["Headers"]
    assert isinstance(headers, dict)
    assert headers.get("Message-ID") == [f"<{delivery_id}@signaldesk.local>"], headers
    assert headers.get("X-SignalDesk-Delivery-ID") == [str(delivery_id)], headers
    assert headers.get("X-SignalDesk-Correlation-ID") == [str(correlation_id)], headers
    assert_no_forbidden(message, forbidden)


def assert_dlq_entry(
    fields: dict[str, str], source_stream: str, forbidden: Sequence[str]
) -> None:
    assert set(fields) == _DLQ_FIELDS, fields
    assert fields["source_stream"] == source_stream
    assert re.fullmatch(r"\d+-\d+", fields["source_id"])
    assert fields["attempt_count"].isdigit() and int(fields["attempt_count"]) >= 1
    assert fields["failure_code"] in _SAFE_FAILURE_CODES
    if fields["event_id"] == "invalid":
        assert re.fullmatch(r"sha256:[0-9a-f]{64}", fields["event"])
    else:
        assert str(UUID(fields["event_id"])) == fields["event_id"]
        parsed = json.loads(fields["event"])
        assert parsed["event_id"] == fields["event_id"]
    assert_no_forbidden(fields, forbidden)


COMPOSE = [
    "docker", "compose", "--env-file", str(ROOT / ".env.example"),
    "-f", str(ROOT / "compose.yaml"), "-f", str(ROOT / "compose.e2e.yaml"),
]
WEB_BASE = "http://127.0.0.1:8080"
TENANT_A_USER = UUID("00000000-0000-4000-8000-000000000101")
TENANT_B_USER = UUID("00000000-0000-4000-8000-000000000102")
TENANT_A = UUID("00000000-0000-4000-8000-000000000201")
TENANT_B = UUID("00000000-0000-4000-8000-000000000202")
TENANT_A_EMAIL = "analyst-a@signaldesk.test"
TENANT_B_EMAIL = "analyst-b@signaldesk.test"
SEED_PASSWORD = "SignalDesk-local-users-only-2026"
POISON_SENTINEL = "task14-poison-password-sentinel"
SYNTHETIC_SECRET_VALUES = (
    "local-only-postgres-password-2026",
    "local-only-web-bff-credential-000000000001",
    "local-only-diagnostic-worker-credential-000002",
    "local-only-email-worker-credential-000000003",
    "local-only-export-worker-credential-00000004",
    "local-only-current-flask-signing-key-00000005",
    "local-only-fallback-flask-signing-key-000006",
    "local-only-minio-root-password-00000007",
    "local-only-minio-export-secret-00000008",
    SEED_PASSWORD,
    POISON_SENTINEL,
)


class HttpResult(NamedTuple):
    status: int
    headers: dict[str, str]
    body: bytes


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self, req: Request, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        del req, fp, code, msg, headers, newurl
        return None


class BrowserSession:
    def __init__(self) -> None:
        self.cookies = CookieJar()
        self.opener = build_opener(
            ProxyHandler({}), HTTPCookieProcessor(self.cookies), _NoRedirect()
        )
        self.responses: list[HttpResult] = []

    def request(
        self, method: str, path: str, *, form: dict[str, str] | None = None
    ) -> HttpResult:
        assert re.fullmatch(r"/[A-Za-z0-9_./-]*", path), f"invalid local path: {path}"
        data = None
        headers = {"Accept-Encoding": "identity"}
        if form is not None:
            data = urlencode(form).encode("ascii")
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        request = Request(WEB_BASE + path, data=data, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=3) as response:
                result = HttpResult(
                    response.status,
                    dict(response.headers.items()),
                    response.read(MAX_HTML_BYTES + 1),
                )
        except HTTPError as error:
            result = HttpResult(
                error.code,
                dict(error.headers.items()),
                error.read(MAX_HTML_BYTES + 1),
            )
        assert len(result.body) <= MAX_HTML_BYTES, "web response too large"
        assert result.headers.get("Content-Encoding", "identity") in {"", "identity"}
        self.responses.append(result)
        return result


def compose(*args: str, check: bool = True) -> str:
    completed = subprocess.run(
        [*COMPOSE, *args], cwd=ROOT, text=True, capture_output=True,
        check=False, timeout=120,
    )
    if check and completed.returncode != 0:
        raise AssertionError(
            f"compose command failed ({' '.join(args)}): {completed.stderr.strip()}"
        )
    return completed.stdout.strip()


def psql(query: str) -> list[str]:
    output = compose(
        "exec", "-T", "postgres", "psql", "-v", "ON_ERROR_STOP=1",
        "-U", "signaldesk_app", "-d", "signaldesk", "-At", "-c", query,
    )
    return [] if not output else output.splitlines()


def json_rows(query: str) -> list[dict[str, Any]]:
    rows = []
    for line in psql(query):
        parsed = json.loads(line)
        assert isinstance(parsed, dict)
        rows.append(parsed)
    return rows


def redis_cli(*args: str, parse_json: bool = False) -> Any:
    command = ["exec", "-T", "redis", "redis-cli"]
    if parse_json:
        command.append("--json")
    output = compose(*command, *args)
    return json.loads(output) if parse_json and output else (None if parse_json else output)


def poll(
    label: str, probe: Any, predicate: Any, *, timeout: float = 20.0,
    interval: float = 0.1,
) -> Any:
    deadline = time.monotonic() + timeout
    last: Any = None
    while True:
        last = probe()
        if predicate(last):
            return last
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AssertionError(f"timed out awaiting {label}; last={last!r}")
        time.sleep(min(interval, remaining))


def login(browser: BrowserSession, email: str, organization_id: UUID) -> None:
    page = browser.request("GET", "/login")
    assert page.status == 200
    response = browser.request(
        "POST", "/login",
        form={"csrf_token": extract_csrf(page.body), "email": email,
              "password": SEED_PASSWORD, "organization_id": str(organization_id)},
    )
    assert response.status == 302 and response.headers.get("Location") == "/"
    dashboard = browser.request("GET", "/")
    assert dashboard.status == 200 and b"Signed in." in dashboard.body


def create_diagnostic(browser: BrowserSession, target: str) -> tuple[UUID, UUID]:
    page = browser.request("GET", "/diagnostics")
    assert page.status == 200
    response = browser.request(
        "POST", "/diagnostics",
        form={"csrf_token": extract_csrf(page.body), "target": target},
    )
    assert response.status == 303
    return (
        job_id_from_location(response.headers["Location"], "diagnostics"),
        UUID(response.headers["X-Correlation-ID"]),
    )


def create_export(browser: BrowserSession, export_format: str) -> tuple[UUID, UUID]:
    page = browser.request("GET", "/exports")
    assert page.status == 200
    response = browser.request(
        "POST", "/exports",
        form={"csrf_token": extract_csrf(page.body), "format": export_format},
    )
    assert response.status == 303
    return (
        job_id_from_location(response.headers["Location"], "exports"),
        UUID(response.headers["X-Correlation-ID"]),
    )


def diagnostic_row(job_id: UUID) -> dict[str, Any] | None:
    rows = json_rows(
        "SELECT json_build_object("
        "'id',id::text,'organization_id',organization_id::text,"
        "'requested_by_user_id',requested_by_user_id::text,'target',target,"
        "'status',status,'result_json',result_json,'correlation_id',correlation_id::text,"
        "'created_at',created_at,'updated_at',updated_at) "
        f"FROM diagnostic_jobs WHERE id='{job_id}'"
    )
    assert len(rows) <= 1
    return rows[0] if rows else None


def export_row(job_id: UUID) -> dict[str, Any] | None:
    rows = json_rows(
        "SELECT json_build_object("
        "'id',id::text,'organization_id',organization_id::text,"
        "'requested_by_user_id',requested_by_user_id::text,'format',format,"
        "'status',status,'object_key',object_key,'object_sha256',object_sha256,"
        "'size_bytes',size_bytes,'snapshot_id',snapshot_id::text,"
        "'correlation_id',correlation_id::text,'created_at',created_at,'updated_at',updated_at) "
        f"FROM export_jobs WHERE id='{job_id}'"
    )
    assert len(rows) <= 1
    return rows[0] if rows else None


def email_rows(correlation_id: UUID) -> list[dict[str, Any]]:
    return json_rows(
        "SELECT json_build_object("
        "'id',id::text,'organization_id',organization_id::text,"
        "'recipient_user_id',recipient_user_id::text,'template_name',template_name,"
        "'template_data',template_data_json,'status',status,"
        "'correlation_id',correlation_id::text,'attempted_at',attempted_at,"
        "'recipient_email_snapshot',recipient_email_snapshot,'sent_at',sent_at) "
        f"FROM email_deliveries WHERE correlation_id='{correlation_id}' ORDER BY id"
    )


def outbox_row(event_type: str, aggregate_id: UUID) -> dict[str, Any]:
    allowed = {
        "diagnostic.requested.v1", "diagnostic.completed.v1", "email.requested.v1",
        "export.requested.v1", "export.completed.v1",
    }
    assert event_type in allowed
    rows = json_rows(
        "SELECT json_build_object("
        "'id',id::text,'event_type',event_type,'aggregate_id',aggregate_id::text,"
        "'payload',payload_json,'published_at',published_at,"
        "'attempt_count',attempt_count,'next_attempt_at',next_attempt_at) "
        f"FROM outbox_events WHERE event_type='{event_type}' AND aggregate_id='{aggregate_id}'"
    )
    assert len(rows) == 1, (event_type, aggregate_id, rows)
    return rows[0]


def authoritative_diagnostic_rows(organization_id: UUID) -> list[dict[str, Any]]:
    return json_rows(
        "SELECT row_to_json(source) FROM (SELECT id::text,organization_id::text,"
        "requested_by_user_id::text,target,status,result_json,correlation_id::text,"
        "created_at,updated_at FROM diagnostic_jobs "
        f"WHERE organization_id='{organization_id}' ORDER BY created_at,id) AS source"
    )


def snapshot_rows(export_id: UUID) -> list[dict[str, Any]]:
    return json_rows(
        "SELECT row_to_json(snapshot) FROM (SELECT id::text,organization_id::text,"
        "requested_by_user_id::text,target,status,result_json,correlation_id::text,"
        "created_at,updated_at FROM export_diagnostic_snapshots "
        f"WHERE export_job_id='{export_id}' ORDER BY position) AS snapshot"
    )


def stream_length(stream: str) -> int:
    return int(redis_cli("XLEN", stream))


def pending_count(stream: str, group: str) -> int:
    value = redis_cli("XPENDING", stream, group, parse_json=True)
    assert isinstance(value, list) and value
    return int(value[0])


def assert_process_ownership_identity(stream: str, group: str, label: str) -> None:
    consumers = redis_cli("XINFO", "CONSUMERS", stream, group, parse_json=True)
    assert isinstance(consumers, list) and consumers, consumers
    names = {str(consumer["name"]) for consumer in consumers}
    assert label not in names, names
    assert any(name.startswith(label + ":") for name in names), names


def xadd_event(stream: str, payload: dict[str, Any], event_id: UUID) -> str:
    source_id = redis_cli(
        "XADD", stream, "*", "event",
        json.dumps(payload, separators=(",", ":"), sort_keys=True),
        "event_id", str(event_id),
    )
    assert re.fullmatch(r"\d+-\d+", source_id)
    return source_id


def arm_real_worker_crash(service: str) -> None:
    assert service in {"diagnostic", "email", "export"}
    redis_cli("DEL", f"signaldesk:task14:crash:observed:{service}")
    assert redis_cli("SET", f"signaldesk:task14:crash:armed:{service}", "1") == "OK"


def crash_observation(service: str) -> dict[str, str] | None:
    key = f"signaldesk:task14:crash:observed:{service}"
    fields = ("source_id", "owner", "attempts")
    raw = redis_cli("HMGET", key, *fields, parse_json=True)
    assert isinstance(raw, list) and len(raw) == len(fields), raw
    if all(value is None for value in raw):
        return None
    assert all(isinstance(value, str) and value for value in raw), raw
    return dict(zip(fields, raw, strict=True))


def assert_real_crashed_pending(
    *,
    service: str,
    stream: str,
    group: str,
    operator_label: str,
) -> dict[str, str]:
    observed = poll(
        f"real {service} pre-ACK crash",
        lambda: crash_observation(service),
        lambda value: value is not None,
        timeout=20,
    )
    assert observed is not None
    assert re.fullmatch(r"\d+-\d+", observed["source_id"])
    assert observed["owner"].startswith(operator_label + ":")
    pending = redis_cli(
        "XPENDING",
        stream,
        group,
        observed["source_id"],
        observed["source_id"],
        "1",
        parse_json=True,
    )
    assert isinstance(pending, list) and len(pending) == 1, pending
    source_id, owner, _idle, deliveries = pending[0]
    assert source_id == observed["source_id"]
    assert owner == observed["owner"]
    assert int(deliveries) == int(observed["attempts"])
    return observed


def stream_entries(stream: str) -> list[tuple[str, dict[str, str]]]:
    raw = redis_cli("XRANGE", stream, "-", "+", parse_json=True)
    assert isinstance(raw, list)
    entries: list[tuple[str, dict[str, str]]] = []
    for entry in raw:
        assert isinstance(entry, list) and len(entry) == 2
        source_id, flat = entry
        assert isinstance(source_id, str) and isinstance(flat, list) and len(flat) % 2 == 0
        entries.append((source_id, {
            str(flat[index]): str(flat[index + 1])
            for index in range(0, len(flat), 2)
        }))
    return entries


def mailpit_messages() -> list[dict[str, Any]]:
    code = r'''
import json
from email import policy
from email.parser import BytesParser
from urllib.request import ProxyHandler, build_opener
opener=build_opener(ProxyHandler({}))
with opener.open("http://mailpit:8025/api/v1/messages", timeout=2) as response:
    summary=json.load(response)
items=[]
for item in summary["messages"]:
    base="http://mailpit:8025/api/v1/message/"+item["ID"]
    with opener.open(base, timeout=2) as response:
        detail=json.load(response)
    with opener.open(base+"/raw", timeout=2) as response:
        raw=response.read(65537)
    if len(raw)>65536:
        raise ValueError("Mailpit raw message too large")
    parsed=BytesParser(policy=policy.default).parsebytes(raw)
    detail["Headers"]={name:parsed.get_all(name,[]) for name in (
        "Message-ID","X-SignalDesk-Delivery-ID","X-SignalDesk-Correlation-ID"
    )}
    items.append(detail)
print(json.dumps(items,separators=(",",":"),sort_keys=True))
'''
    output = compose(
        "run", "--rm", "--no-deps", "--entrypoint", "python",
        "email-worker", "-c", code,
    )
    parsed = json.loads(output)
    assert isinstance(parsed, list)
    return parsed


def object_record(key: str) -> dict[str, Any]:
    assert re.fullmatch(r"exports/[.A-Za-z0-9_/-]+", key) and ".." not in key
    code = r'''
import base64,json,os,sys
import boto3
from botocore.config import Config
client=boto3.client("s3",endpoint_url="http://minio:9000",aws_access_key_id=os.environ["SIGNALDESK_EXPORT_WORKER_MINIO_ACCESS_KEY"],aws_secret_access_key=os.environ["SIGNALDESK_EXPORT_WORKER_MINIO_SECRET_KEY"],config=Config(signature_version="s3v4",proxies={},s3={"addressing_style":"path"}))
key=sys.argv[1]
head=client.head_object(Bucket="signaldesk-exports",Key=key)
body=client.get_object(Bucket="signaldesk-exports",Key=key)["Body"].read()
print(json.dumps({"body":base64.b64encode(body).decode("ascii"),"content_type":head["ContentType"],"content_length":head["ContentLength"],"metadata":head["Metadata"]},separators=(",",":"),sort_keys=True))
'''
    parsed = json.loads(compose(
        "run", "--rm", "--no-deps", "--entrypoint", "python",
        "export-worker", "-c", code, key,
    ))
    assert isinstance(parsed, dict)
    return parsed


def decode_object(record: dict[str, Any]) -> bytes:
    body = base64.b64decode(record["body"], validate=True)
    assert len(body) == record["content_length"]
    return body


def wait_for_sent(correlation_id: UUID) -> dict[str, Any]:
    rows = poll(
        f"sent email for {correlation_id}", lambda: email_rows(correlation_id),
        lambda value: len(value) == 1 and value[0]["status"] == "sent", timeout=20,
    )
    return rows[0]


def verify_delivery(
    correlation_id: UUID, *, expected_template: str, forbidden: Sequence[str]
) -> dict[str, Any]:
    delivery = wait_for_sent(correlation_id)
    assert delivery["organization_id"] == str(TENANT_A)
    assert delivery["recipient_user_id"] == str(TENANT_A_USER)
    assert delivery["recipient_email_snapshot"] == TENANT_A_EMAIL
    assert delivery["template_name"] == expected_template
    assert delivery["attempted_at"] is not None and delivery["sent_at"] is not None
    delivery_id = UUID(delivery["id"])
    matches = [m for m in mailpit_messages()
               if m.get("MessageID") == f"{delivery_id}@signaldesk.local"]
    assert len(matches) == 1, (delivery_id, len(matches))
    assert_mailpit_message(
        matches[0], delivery_id=delivery_id, correlation_id=correlation_id,
        recipient=TENANT_A_EMAIL, forbidden=forbidden,
    )
    return delivery


def verify_export_artifact(
    job: dict[str, Any], authoritative_rows: Sequence[dict[str, Any]]
) -> tuple[bytes, dict[str, Any], dict[str, Any]]:
    import hashlib
    export_id = UUID(job["id"])
    frozen_rows = snapshot_rows(export_id)
    assert frozen_rows == list(authoritative_rows)
    expected = expected_artifact(authoritative_rows, job["format"])
    final = object_record(job["object_key"])
    canonical_key = (
        f"exports/.canonical/{job['organization_id']}/{job['id']}/"
        f"{job['snapshot_id']}.{job['format']}"
    )
    canonical = object_record(canonical_key)
    final_body = decode_object(final)
    canonical_body = decode_object(canonical)
    assert final_body == canonical_body, (
        f"final/canonical mismatch: {final_body!r} != {canonical_body!r}"
    )
    assert final_body == expected, (
        f"artifact mismatch: actual={final_body!r} expected={expected!r}"
    )
    digest = hashlib.sha256(expected).hexdigest()
    assert (job["object_sha256"], job["size_bytes"]) == (digest, len(expected))
    expected_media = "application/json" if job["format"] == "json" else "text/csv; charset=utf-8"
    expected_metadata = {
        "sha256": digest, "export-id": job["id"], "org-id": job["organization_id"],
        "correlation-id": job["correlation_id"], "snapshot-id": job["snapshot_id"],
    }
    assert final["content_type"] == canonical["content_type"] == expected_media
    assert final["metadata"] == expected_metadata
    assert canonical["metadata"] == expected_metadata | {"canonical-version": "1"}
    assert_no_forbidden(final["metadata"], SYNTHETIC_SECRET_VALUES)
    assert_no_forbidden(canonical["metadata"], SYNTHETIC_SECRET_VALUES)
    return expected, final, canonical


def assert_web_export_path(browser: BrowserSession, job: dict[str, Any]) -> None:
    detail = browser.request("GET", f"/exports/{job['id']}")
    assert detail.status == 200
    assert job["correlation_id"].encode() in detail.body and b"completed" in detail.body
    download = browser.request("GET", f"/exports/{job['id']}/download")
    assert download.status == 200
    for value in (job["object_key"], job["object_sha256"], str(job["size_bytes"])):
        assert value.encode() in download.body
    assert b"http://minio" not in download.body and b"MINIO" not in download.body


def assert_relevant_outbox_complete(aggregate_ids: Sequence[UUID]) -> None:
    values = ",".join(f"'{item}'" for item in aggregate_ids)
    rows = json_rows(
        "SELECT json_build_object('id',id::text,'payload',payload_json,"
        "'published',published_at IS NOT NULL,'attempt_count',attempt_count,"
        "'next_attempt_at',next_attempt_at) FROM outbox_events "
        f"WHERE aggregate_id IN ({values}) ORDER BY created_at,id"
    )
    assert rows
    for row in rows:
        assert row["published"] is True
        assert row["attempt_count"] == 0 and row["next_attempt_at"] is None
        assert_no_forbidden(row, SYNTHETIC_SECRET_VALUES)


def verify_replay(stream: str, group: str, event: dict[str, Any], event_id: UUID) -> None:
    before = stream_length(stream)
    xadd_event(stream, event, event_id)
    assert stream_length(stream) == before + 1
    poll(
        f"replayed {stream} ACK", lambda: pending_count(stream, group),
        lambda value: value == 0, timeout=15,
    )


def inject_dlq_cases(
    *, stream: str, group: str, dlq: str, event_type: str,
    aggregate_field: str, aggregate_id: UUID, correlation_id: UUID,
) -> list[dict[str, str]]:
    before = stream_length(dlq)
    redis_cli(
        "XADD", stream, "*", "event", json.dumps({"credential": POISON_SENTINEL}),
        "event_id", "not-a-uuid",
    )
    forged_id = uuid4()
    forged = {
        "schema_version": 1, "event_id": str(forged_id), "event_type": event_type,
        "occurred_at": datetime.now(timezone.utc).isoformat(),
        "correlation_id": str(correlation_id), "organization_id": str(TENANT_B),
        aggregate_field: str(aggregate_id),
    }
    xadd_event(stream, forged, forged_id)
    poll(
        f"two {dlq} entries", lambda: stream_length(dlq),
        lambda value: value == before + 2, timeout=15,
    )
    assert pending_count(stream, group) == 0
    added = [fields for _source_id, fields in stream_entries(dlq)[before:]]
    assert len(added) == 2
    for fields in added:
        assert_dlq_entry(fields, stream, SYNTHETIC_SECRET_VALUES)
    assert {item["failure_code"] for item in added} == {"invalid_event", "scope_mismatch"}
    return added


def verify_runtime() -> None:
    print("PASS: harness helper invariants loaded")
    browser_a = BrowserSession()
    login(browser_a, TENANT_A_EMAIL, TENANT_A)
    print("PASS: tenant A login and dashboard")

    target = '=HYPERLINK("https://task14.invalid","blocked")'
    diagnostic_id, diagnostic_correlation = create_diagnostic(browser_a, target)
    diagnostic = poll(
        "completed diagnostic", lambda: diagnostic_row(diagnostic_id),
        lambda value: value is not None and value["status"] == "completed", timeout=20,
    )
    assert diagnostic["organization_id"] == str(TENANT_A)
    assert diagnostic["requested_by_user_id"] == str(TENANT_A_USER)
    assert diagnostic["correlation_id"] == str(diagnostic_correlation)
    assert diagnostic["target"] == target
    assert diagnostic["result_json"] == {"error_code": "invalid_target", "outcome": "blocked"}
    detail = browser_a.request("GET", f"/diagnostics/{diagnostic_id}")
    assert detail.status == 200
    detail_text = unescape(detail.body.decode("utf-8", "strict"))
    for value in (target, "invalid_target", str(diagnostic_correlation), "completed"):
        assert value in detail_text, value
    diagnostic_index = browser_a.request("GET", "/diagnostics")
    export_index = browser_a.request("GET", "/exports")
    assert diagnostic_index.status == export_index.status == 200
    authoritative_snapshot_oracle = authoritative_diagnostic_rows(TENANT_A)
    assert authoritative_snapshot_oracle == [diagnostic]
    diagnostic_delivery = verify_delivery(
        diagnostic_correlation, expected_template="diagnostic_completed",
        forbidden=(TENANT_B_EMAIL, *SYNTHETIC_SECRET_VALUES),
    )
    print("PASS: diagnostic processing, detail/history, correlation, and exactly-once email")

    csv_id, csv_correlation = create_export(browser_a, "csv")
    json_id, json_correlation = create_export(browser_a, "json")
    completed_exports: dict[str, dict[str, Any]] = {}
    artifacts: dict[str, tuple[bytes, dict[str, Any], dict[str, Any]]] = {}
    export_deliveries: dict[str, dict[str, Any]] = {}
    for export_format, export_id, correlation_id in (
        ("csv", csv_id, csv_correlation), ("json", json_id, json_correlation),
    ):
        job = poll(
            f"completed {export_format} export", lambda job_id=export_id: export_row(job_id),
            lambda value: value is not None and value["status"] == "completed", timeout=25,
        )
        assert job["organization_id"] == str(TENANT_A)
        assert job["requested_by_user_id"] == str(TENANT_A_USER)
        assert job["correlation_id"] == str(correlation_id) and job["format"] == export_format
        assert_web_export_path(browser_a, job)
        completed_exports[export_format] = job
        artifacts[export_format] = verify_export_artifact(
            job, authoritative_snapshot_oracle
        )
        export_deliveries[export_format] = verify_delivery(
            correlation_id, expected_template="export_completed",
            forbidden=(TENANT_B_EMAIL, *SYNTHETIC_SECRET_VALUES),
        )
    assert snapshot_rows(csv_id) == authoritative_snapshot_oracle
    assert snapshot_rows(json_id) == authoritative_snapshot_oracle
    assert b"'=HYPERLINK" in artifacts["csv"][0]
    assert json.loads(artifacts["json"][0]) == [
        _normalized_row(row) for row in authoritative_snapshot_oracle
    ]
    assert len(mailpit_messages()) == 3
    print("PASS: CSV/JSON web paths, exact artifacts, escaping, snapshots, MinIO canonical/final, and email")

    browser_b = BrowserSession()
    login(browser_b, TENANT_B_EMAIL, TENANT_B)
    tenant_b_indexes = (
        browser_b.request("GET", "/diagnostics"),
        browser_b.request("GET", "/exports"),
    )
    assert all(response.status == 200 for response in tenant_b_indexes)
    leaked_values = (
        target,
        str(diagnostic_id),
        str(diagnostic_correlation),
        str(csv_id),
        str(csv_correlation),
        str(json_id),
        str(json_correlation),
        completed_exports["csv"]["object_key"],
        completed_exports["csv"]["object_sha256"],
        completed_exports["json"]["object_key"],
        completed_exports["json"]["object_sha256"],
        TENANT_A_EMAIL,
    )
    for healthy in tenant_b_indexes:
        for value in leaked_values:
            assert value.encode() not in healthy.body
    for path in (
        f"/diagnostics/{diagnostic_id}", f"/exports/{csv_id}",
        f"/exports/{csv_id}/download", f"/exports/{json_id}/download",
    ):
        denied = browser_b.request("GET", path)
        # The web BFF deliberately maps tenant-scoped control-plane absence to
        # one generic unavailable response rather than exposing existence.
        assert denied.status == 503
        for value in leaked_values:
            assert value.encode() not in denied.body
    assert len(mailpit_messages()) == 3
    print("PASS: tenant B HTTP detail/download denial and no response/artifact/mail leakage")

    counts_before_replay = {
        "mail": len(mailpit_messages()),
        "objects": {key: (decode_object(value[1]), decode_object(value[2]))
                    for key, value in artifacts.items()},
        "diagnostic_updated": diagnostic["updated_at"],
        "csv_updated": completed_exports["csv"]["updated_at"],
    }
    replay_rows = (
        (("signaldesk:diagnostics", "diagnostic-workers"),
         outbox_row("diagnostic.requested.v1", diagnostic_id)),
        (("signaldesk:emails", "email-workers"),
         outbox_row("email.requested.v1", UUID(diagnostic_delivery["id"]))),
        (("signaldesk:exports", "export-workers"),
         outbox_row("export.requested.v1", csv_id)),
    )
    for (stream, group), row in replay_rows:
        verify_replay(stream, group, row["payload"], UUID(row["id"]))
    assert len(mailpit_messages()) == counts_before_replay["mail"]
    assert diagnostic_row(diagnostic_id)["updated_at"] == counts_before_replay["diagnostic_updated"]
    assert export_row(csv_id)["updated_at"] == counts_before_replay["csv_updated"]
    for key, job in completed_exports.items():
        current = verify_export_artifact(job, authoritative_snapshot_oracle)
        assert (decode_object(current[1]), decode_object(current[2])) == counts_before_replay["objects"][key]
    print("PASS: duplicate diagnostic/export/email events ACK with no duplicate side effects")

    requested = outbox_row("diagnostic.requested.v1", diagnostic_id)
    diagnostic_stream_before = stream_length("signaldesk:diagnostics")
    psql(f"UPDATE outbox_events SET published_at=NULL WHERE id='{requested['id']}'")
    compose(
        "run", "--rm", "--no-deps", "outbox-publisher",
        "signaldesk-outbox-publisher", "--once", "--batch-size", "1",
    )
    assert outbox_row("diagnostic.requested.v1", diagnostic_id)["published_at"] is not None
    assert stream_length("signaldesk:diagnostics") == diagnostic_stream_before
    print("PASS: Redis publication marker replay recovers DB without duplicate append")

    mail_before_real_crashes = len(mailpit_messages())
    arm_real_worker_crash("diagnostic")
    arm_real_worker_crash("email")
    late_id, late_correlation = create_diagnostic(
        browser_a, "invalid synthetic crash target"
    )
    diagnostic_crash = assert_real_crashed_pending(
        service="diagnostic",
        stream="signaldesk:diagnostics",
        group="diagnostic-workers",
        operator_label="diagnostic-worker-local",
    )
    late = poll(
        "diagnostic side effect before pre-ACK crash",
        lambda: diagnostic_row(late_id),
        lambda value: value is not None and value["status"] == "completed",
        timeout=20,
    )
    assert diagnostic_crash["source_id"] in {
        source_id for source_id, _fields in stream_entries("signaldesk:diagnostics")
    }
    late_updated_at = late["updated_at"]
    email_crash = assert_real_crashed_pending(
        service="email",
        stream="signaldesk:emails",
        group="email-workers",
        operator_label="email-worker-local",
    )
    late_delivery = verify_delivery(
        late_correlation,
        expected_template="diagnostic_completed",
        forbidden=(TENANT_B_EMAIL, *SYNTHETIC_SECRET_VALUES),
    )
    assert email_crash["source_id"] in {
        source_id for source_id, _fields in stream_entries("signaldesk:emails")
    }
    late_delivery_sent_at = late_delivery["sent_at"]
    assert len(mailpit_messages()) == mail_before_real_crashes + 1

    compose("start", "diagnostic-worker")
    compose("start", "email-worker")
    poll(
        "real diagnostic crashed entry reclaim and ACK",
        lambda: pending_count("signaldesk:diagnostics", "diagnostic-workers"),
        lambda value: value == 0,
        timeout=20,
    )
    poll(
        "real email crashed entry reclaim and ACK",
        lambda: pending_count("signaldesk:emails", "email-workers"),
        lambda value: value == 0,
        timeout=20,
    )
    late_after_recovery = diagnostic_row(late_id)
    assert late_after_recovery is not None
    assert late_after_recovery["updated_at"] == late_updated_at
    assert email_rows(late_correlation)[0]["sent_at"] == late_delivery_sent_at
    assert len(mailpit_messages()) == mail_before_real_crashes + 1
    print(
        "PASS: real diagnostic completion and email SMTP side effects survive "
        "process SIGKILL before XACK without duplicates"
    )

    # Existing export snapshots must not absorb the later diagnostic.
    assert snapshot_rows(csv_id) == authoritative_snapshot_oracle
    assert snapshot_rows(json_id) == authoritative_snapshot_oracle

    crash_export_oracle = authoritative_diagnostic_rows(TENANT_A)
    arm_real_worker_crash("export")
    crash_export_id, crash_export_correlation = create_export(browser_a, "csv")
    export_crash = assert_real_crashed_pending(
        service="export",
        stream="signaldesk:exports",
        group="export-workers",
        operator_label="export-worker-local",
    )
    crash_export_job = poll(
        "export object/control side effect before pre-ACK crash",
        lambda: export_row(crash_export_id),
        lambda value: value is not None and value["status"] == "completed",
        timeout=25,
    )
    crash_export_before = verify_export_artifact(
        crash_export_job, crash_export_oracle
    )
    crash_export_updated_at = crash_export_job["updated_at"]
    assert export_crash["source_id"] in {
        source_id for source_id, _fields in stream_entries("signaldesk:exports")
    }
    crash_export_delivery = verify_delivery(
        crash_export_correlation,
        expected_template="export_completed",
        forbidden=(TENANT_B_EMAIL, *SYNTHETIC_SECRET_VALUES),
    )
    mail_before_export_recovery = len(mailpit_messages())
    compose("start", "export-worker")
    poll(
        "real export crashed entry reclaim and ACK",
        lambda: pending_count("signaldesk:exports", "export-workers"),
        lambda value: value == 0,
        timeout=20,
    )
    crash_export_job_after = export_row(crash_export_id)
    assert crash_export_job_after is not None
    crash_export_after = verify_export_artifact(
        crash_export_job_after, crash_export_oracle
    )
    assert decode_object(crash_export_before[1]) == decode_object(
        crash_export_after[1]
    )
    assert crash_export_job_after["updated_at"] == crash_export_updated_at
    assert len(mailpit_messages()) == mail_before_export_recovery
    print(
        "PASS: real export object/control side effect survives process SIGKILL "
        "before XACK without duplicate mutation"
    )

    dlq_results = []
    dlq_results += inject_dlq_cases(
        stream="signaldesk:diagnostics", group="diagnostic-workers",
        dlq="signaldesk:diagnostics:dlq", event_type="diagnostic.requested.v1",
        aggregate_field="diagnostic_job_id", aggregate_id=diagnostic_id,
        correlation_id=diagnostic_correlation,
    )
    dlq_results += inject_dlq_cases(
        stream="signaldesk:emails", group="email-workers", dlq="signaldesk:emails:dlq",
        event_type="email.requested.v1", aggregate_field="email_delivery_id",
        aggregate_id=UUID(diagnostic_delivery["id"]), correlation_id=diagnostic_correlation,
    )
    dlq_results += inject_dlq_cases(
        stream="signaldesk:exports", group="export-workers", dlq="signaldesk:exports:dlq",
        event_type="export.requested.v1", aggregate_field="export_job_id",
        aggregate_id=csv_id, correlation_id=csv_correlation,
    )
    assert len(mailpit_messages()) == 5
    assert_no_forbidden(dlq_results, SYNTHETIC_SECRET_VALUES)
    print("PASS: malformed and forged foreign events DLQ atomically with redacted reasons")

    all_aggregates = [
        diagnostic_id, late_id, csv_id, json_id, crash_export_id,
        UUID(diagnostic_delivery["id"]),
        UUID(late_delivery["id"]), UUID(export_deliveries["csv"]["id"]),
        UUID(export_deliveries["json"]["id"]), UUID(crash_export_delivery["id"]),
    ]
    assert_relevant_outbox_complete(all_aggregates)
    for stream, group in (
        ("signaldesk:diagnostics", "diagnostic-workers"),
        ("signaldesk:emails", "email-workers"),
        ("signaldesk:exports", "export-workers"),
    ):
        assert pending_count(stream, group) == 0
    for stream, group, label in (
        ("signaldesk:diagnostics", "diagnostic-workers", "diagnostic-worker-local"),
        ("signaldesk:emails", "email-workers", "email-worker-local"),
        ("signaldesk:exports", "export-workers", "export-worker-local"),
    ):
        assert_process_ownership_identity(stream, group, label)
    for row in (
        diagnostic_row(diagnostic_id), late, export_row(csv_id),
        export_row(json_id), export_row(crash_export_id),
    ):
        assert row is not None and row["status"] == "completed"
    for correlation in (
        diagnostic_correlation, late_correlation, csv_correlation,
        json_correlation, crash_export_correlation,
    ):
        assert email_rows(correlation)[0]["status"] == "sent"
    print("PASS: final Redis pending/DLQ, Postgres jobs/deliveries/outbox, MinIO, and Mailpit state")

    redis_dump_code = r'''
import base64,json,redis
client=redis.Redis.from_url("redis://redis:6379/0")
print(json.dumps({key.decode("utf-8","replace"):base64.b64encode(client.dump(key) or b"").decode("ascii") for key in client.scan_iter(match="signaldesk:*")},separators=(",",":"),sort_keys=True))
'''
    redis_dump_text = compose("exec", "-T", "control-api", "python", "-c", redis_dump_code)
    redis_dumps = json.loads(redis_dump_text)
    assert isinstance(redis_dumps, dict)
    logs = compose("logs", "--no-color")
    assert_redis_dumps_safe(redis_dumps, SYNTHETIC_SECRET_VALUES)
    assert_no_forbidden(logs, SYNTHETIC_SECRET_VALUES)
    assert_http_responses_safe(
        (*browser_a.responses, *browser_b.responses), SYNTHETIC_SECRET_VALUES
    )
    assert_no_forbidden(mailpit_messages(), SYNTHETIC_SECRET_VALUES)
    print("PASS: no credentials/poison in Redis dumps, logs, responses, Mailpit, or object metadata")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    verify_runtime()
    print("PASS: Task 14 full-stack verification complete")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, subprocess.SubprocessError, ValueError, KeyError) as error:
        traceback.print_exc()
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1) from None
