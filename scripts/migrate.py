#!/usr/bin/env python3
"""Run the vetted Alembic chain once from an explicit PostgreSQL URL."""

from __future__ import annotations

import os

from alembic import command
from alembic.config import Config
from sqlalchemy.engine import make_url


def main() -> None:
    raw_url = os.environ.get("SIGNALDESK_DATABASE_URL", "")
    if not raw_url:
        raise SystemExit("SIGNALDESK_DATABASE_URL is required")
    url = make_url(raw_url)
    if url.drivername not in {"postgresql", "postgresql+psycopg"} or url.host != "postgres":
        raise SystemExit("migration database must be Compose PostgreSQL")
    config = Config("/app/alembic.ini")
    config.set_main_option("sqlalchemy.url", raw_url.replace("%", "%%"))
    command.upgrade(config, "head")


if __name__ == "__main__":
    main()
