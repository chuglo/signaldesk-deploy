#!/usr/bin/env python3
"""Idempotently seed two entirely synthetic local tenants after migration."""

from __future__ import annotations

import os
from uuid import UUID

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from werkzeug.security import generate_password_hash


USERS = (
    (UUID("00000000-0000-4000-8000-000000000101"), "analyst-a@signaldesk.test"),
    (UUID("00000000-0000-4000-8000-000000000102"), "analyst-b@signaldesk.test"),
)
ORGANIZATIONS = (
    (UUID("00000000-0000-4000-8000-000000000201"), "Synthetic Tenant A"),
    (UUID("00000000-0000-4000-8000-000000000202"), "Synthetic Tenant B"),
)


def main() -> None:
    raw_url = os.environ.get("SIGNALDESK_DATABASE_URL", "")
    password = os.environ.get("SIGNALDESK_SEED_USER_PASSWORD", "")
    if not raw_url or not password:
        raise SystemExit("database URL and synthetic seed password are required")
    url = make_url(raw_url)
    if url.drivername not in {"postgresql", "postgresql+psycopg"} or url.host != "postgres":
        raise SystemExit("seed database must be Compose PostgreSQL")
    if len(password) < 16 or not password.isascii() or password != password.strip():
        raise SystemExit("synthetic seed password must be at least 16 ASCII characters")

    engine = create_engine(raw_url)
    try:
        with engine.begin() as connection:
            for user_id, email in USERS:
                connection.execute(
                    text(
                        "INSERT INTO users (id, email, password_hash, active) "
                        "VALUES (:id, :email, :password_hash, true) "
                        "ON CONFLICT (id) DO NOTHING"
                    ),
                    {
                        "id": user_id,
                        "email": email,
                        "password_hash": generate_password_hash(password),
                    },
                )
            for organization_id, name in ORGANIZATIONS:
                connection.execute(
                    text(
                        "INSERT INTO organizations (id, name) VALUES (:id, :name) "
                        "ON CONFLICT (id) DO NOTHING"
                    ),
                    {"id": organization_id, "name": name},
                )
            for (user_id, _), (organization_id, _) in zip(
                USERS, ORGANIZATIONS, strict=True
            ):
                connection.execute(
                    text(
                        "INSERT INTO memberships (user_id, organization_id, role) "
                        "VALUES (:user_id, :organization_id, 'analyst') "
                        "ON CONFLICT (user_id, organization_id) DO NOTHING"
                    ),
                    {"user_id": user_id, "organization_id": organization_id},
                )
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
