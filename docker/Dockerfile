FROM node:22-alpine AS frontend-build
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim AS backend
WORKDIR /app

RUN groupadd --system capki && useradd --system --gid capki --home-dir /app capki

# libxmlsec1 + headers: needed to build and run python3-saml's xmlsec
# extension (SAML signature validation). Kept in the final image rather
# than a separate builder stage — simpler, and the size cost is small.
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config libxml2-dev libxmlsec1-dev libxmlsec1-openssl build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY backend/pyproject.toml ./
COPY backend/alembic.ini ./
COPY backend/alembic ./alembic
COPY backend/src ./src
RUN pip install --no-cache-dir -e .

COPY --from=frontend-build /src/backend/src/capki/static ./src/capki/static
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV PYTHONPATH=/app/src \
    DATABASE_PATH=/data/app.db \
    CA_MASTER_KEY_FILE=/data/secrets/master.key \
    TLS_MATERIALIZED_DIR=/run/app-tls

RUN mkdir -p /data /run/app-tls && chown -R capki:capki /app /data /run/app-tls

VOLUME ["/data"]
EXPOSE 8443

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD python -c "import urllib.request,ssl; ctx=ssl.SSLContext(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE; urllib.request.urlopen('https://127.0.0.1:8443/api/v1/healthz', context=ctx, timeout=3)" || exit 1

USER capki
ENTRYPOINT ["/entrypoint.sh"]
