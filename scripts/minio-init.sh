#!/bin/sh
set -eu

: "${MINIO_ROOT_USER:?MINIO_ROOT_USER is required}"
: "${MINIO_ROOT_PASSWORD:?MINIO_ROOT_PASSWORD is required}"
: "${MINIO_EXPORT_WORKER_ACCESS_KEY:?MINIO_EXPORT_WORKER_ACCESS_KEY is required}"
: "${MINIO_EXPORT_WORKER_SECRET_KEY:?MINIO_EXPORT_WORKER_SECRET_KEY is required}"

export MC_CONFIG_DIR=/tmp/mc
mc alias set local http://minio:9000 "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD"
mc ready local
mc mb --ignore-existing --with-lock local/signaldesk-exports
mc version enable local/signaldesk-exports
mc anonymous set none local/signaldesk-exports
mc retention set --default COMPLIANCE 7d local/signaldesk-exports
if mc admin user info local "$MINIO_EXPORT_WORKER_ACCESS_KEY" >/dev/null 2>&1; then
  mc admin user enable local "$MINIO_EXPORT_WORKER_ACCESS_KEY"
else
  mc admin user add local "$MINIO_EXPORT_WORKER_ACCESS_KEY" "$MINIO_EXPORT_WORKER_SECRET_KEY"
fi
mc admin policy create local signaldesk-export-worker /config/minio-export-worker-policy.json
mc admin policy attach local signaldesk-export-worker --user "$MINIO_EXPORT_WORKER_ACCESS_KEY"

# Both final exports and .canonical snapshots remain private, immutable to the
# worker, object-locked for the seven-day replay window, and expire only after
# the 30-day synthetic-fixture retention period.
# Reconcile the entire lifecycle configuration to one exact immutable-fixture rule.
# Full import replaces stale or wrong-duration rules instead of accepting any
# rule that merely mentions the exports prefix.
mc ilm rule import local/signaldesk-exports < /config/minio-lifecycle.json
