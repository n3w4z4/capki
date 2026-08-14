import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from capki.api.routers import (
    audit,
    auth,
    ca,
    certificate_requests,
    certificates,
    csr,
    health,
    saml,
    settings as settings_router,
    tokens,
    users,
)
from capki.config import settings
from capki.core.crypto.key_vault import key_vault
from capki.db.session import SessionLocal
from capki.scheduler import start_scheduler
from capki.services.user_service import bootstrap_initial_admin

logging.basicConfig(level=logging.INFO)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    db = SessionLocal()
    try:
        bootstrap_initial_admin(db)
        key_vault.load_intermediate(db)
    finally:
        db.close()

    scheduler = start_scheduler()
    yield
    scheduler.shutdown(wait=False)


app = FastAPI(
    title="capki",
    description=(
        "Self-hosted PKI management API — certificate authorities, certificate issuance/revocation, "
        "the request/approval workflow, ephemeral CSR generation, users, and settings.\n\n"
        "Authenticate with either a session cookie (log in via the web UI first) or an API token: "
        "`Authorization: Bearer catk_...` (create one under API Tokens once logged in)."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.include_router(health.router, prefix="/api/v1")
app.include_router(auth.router, prefix="/api/v1")
app.include_router(ca.router, prefix="/api/v1")
app.include_router(certificates.router, prefix="/api/v1")
app.include_router(certificate_requests.router, prefix="/api/v1")
app.include_router(tokens.router, prefix="/api/v1")
app.include_router(saml.router, prefix="/api/v1")
app.include_router(settings_router.router, prefix="/api/v1")
app.include_router(audit.router, prefix="/api/v1")
app.include_router(users.router, prefix="/api/v1")
app.include_router(csr.router, prefix="/api/v1")

if settings.static_dir.exists():
    assets_dir = settings.static_dir / "assets"
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa(full_path: str) -> FileResponse:
        candidate = settings.static_dir / full_path
        if full_path and candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(settings.static_dir / "index.html")
