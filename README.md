# SignalDesk local deployment

Task 13 assembles the local-only SignalDesk fixture. It starts PostgreSQL 16,
standalone Redis 7, Mailpit, MinIO, a single Alembic migration job, an idempotent
synthetic seed job, and the six long-running application processes.

## Start

```sh
cp .env.example .env
docker compose --env-file .env config --quiet
docker compose --env-file .env up --build -d --wait
python3 scripts/verify-runtime.py
```

The ordinary profile publishes only `http://127.0.0.1:8080`. To publish the
Mailpit developer UI on loopback as well:

```sh
docker compose --env-file .env \
  -f compose.yaml -f compose.dev.yaml up --build -d --wait
# Mailpit UI: http://127.0.0.1:8025
```

PostgreSQL, Redis, MinIO, the control API, and all workers have no host port.
Data, service, mail, and object networks are `internal`. Only web also joins a
minimal edge bridge so Docker Desktop can publish its intended loopback port;
the runtime environment clears upper- and lower-case HTTP(S)/ALL proxy variables.
Application containers run as UID
10001 with a read-only root filesystem, all capabilities dropped, no-new-
privileges, bounded tmpfs, and no Docker socket.

## Fail-closed configuration

Every password, service credential, signing key, seed password, and MinIO
credential uses Compose's `${NAME:?message}` interpolation. Configuration fails
before any container is created if an input is absent. The values in
`.env.example` are explicit synthetic local-only values; they are not
production defaults. The control API additionally validates that its BFF and
three worker credentials are strong and pairwise distinct. Each worker receives
only its own service credential and an operator label:

- `diagnostic-worker-local` / `signaldesk:diagnostics` / `diagnostic-workers`
- `email-worker-local` / `signaldesk:emails` / `email-workers`
- `export-worker-local` / `signaldesk:exports` / `export-workers`

Worker code derives process-incarnation ownership identities from these labels.
Local hostnames are exactly `postgres`, `redis`, `control-api`, `mailpit`, and
`minio`.

## Startup and readiness

`migrate` is the only service that runs Alembic. It waits for an authenticated
PostgreSQL query, applies the vetted chain through `20260723_0007`, exits once,
and has restart policy `no`. `seed` waits for successful migration and inserts
two synthetic tenants idempotently. Every application waits for successful
migration and seed; MinIO-dependent work also waits for successful `minio-init`.
No application command runs migrations.

Health checks use authenticated SQL, Redis `PING` plus `cluster_enabled:0`,
Mailpit's `readyz`, MinIO's readiness endpoint, validated service settings, and
real HTTP/SMTP/dependency connections. They do not merely inspect process IDs.
`scripts/verify-runtime.py` additionally proves startup ordering, the Alembic
head and seed counts, DNS service discovery, standalone Redis, published-port
boundaries, and object-store behavior.

## Object-store boundary

`minio-init` creates a private, versioned, object-lock-enabled
`signaldesk-exports` bucket. The export worker's dedicated IAM identity may
list `exports/` and conditionally create/read objects below that prefix. It
cannot delete objects, change bucket policy, or grant public access. Final keys
and `exports/.canonical/` snapshot keys receive default seven-day COMPLIANCE
retention (the replay window) and a 30-day lifecycle expiry for synthetic data.
The runtime verifier exercises `If-None-Match: *`, canonical/final reads,
worker delete denial, and anonymous read denial against real MinIO.

## Task 14 end-to-end verification

Run the clean, bounded full-stack workflow with:

```sh
scripts/test-e2e.sh
```

The wrapper runs static tests first, recreates all synthetic state, runs the Task 13
runtime verifier, then verifies tenant A/B browser journeys, exact CSV/JSON objects,
Mailpit delivery identity, replay/idempotency, SIGKILL pending reclaim, owner-fenced
ACK/DLQ behavior, and final Postgres/Redis/MinIO/Mailpit state. It always removes
containers, networks, and volumes through a trap and retains only a sanitized
Compose log under `test-artifacts/`.

## Images

Third-party images and the Python base use immutable registry digests while
retaining human-readable version tags. Resolved values are recorded in
`system-manifests/task13-images.json`. Locally built service images do not have
registry `RepoDigest` values until they are pushed to a registry; their
content-addressed local image IDs are the unavoidable local-build boundary.

## Stop and remove synthetic state

```sh
docker compose --env-file .env down --volumes --remove-orphans
```

The only named volume is labeled synthetic fixture state (`postgres-data`).
Redis, Mailpit, and MinIO use disposable tmpfs storage; MinIO's tmpfs is
explicitly owned by its non-root UID.
