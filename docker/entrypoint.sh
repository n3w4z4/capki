#!/bin/sh
set -eu

alembic -c /app/alembic.ini upgrade head

python -m capki.bootstrap

exec uvicorn capki.main:app \
    --host 0.0.0.0 \
    --port 8443 \
    --ssl-certfile "${TLS_MATERIALIZED_DIR}/tls.crt" \
    --ssl-keyfile "${TLS_MATERIALIZED_DIR}/tls.key"
