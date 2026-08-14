import logging
import os
import threading

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from capki.api.deps import require_permission
from capki.core.rbac.context import AuthContext
from capki.core.rbac.permissions import SETTINGS_MANAGE, SETTINGS_READ
from capki.db.models.settings import SamlConfig, TlsListenerConfig
from capki.db.session import get_db
from capki.services import settings_service, tls_service

router = APIRouter(prefix="/settings", tags=["settings"])
logger = logging.getLogger(__name__)


def _schedule_restart(delay_seconds: float = 0.5) -> None:
    """Exits the process shortly after the response is sent, so
    `restart: unless-stopped` (or systemd) brings it back up having
    re-materialized the newly persisted TLS cert/key from the DB — see
    core/crypto/tls_bootstrap.py / bootstrap.py, which run on every start."""
    logger.warning("TLS listener config changed — restarting process in %.1fs to apply it", delay_seconds)
    threading.Timer(delay_seconds, lambda: os._exit(0)).start()


class SamlConfigResponse(BaseModel):
    enabled: bool
    idp_entity_id: str | None
    idp_sso_url: str | None
    idp_slo_url: str | None
    idp_x509_cert: str | None
    sp_entity_id: str | None
    group_role_map: dict[str, str] | None

    @classmethod
    def from_model(cls, config: SamlConfig) -> "SamlConfigResponse":
        return cls(
            enabled=config.enabled,
            idp_entity_id=config.idp_entity_id,
            idp_sso_url=config.idp_sso_url,
            idp_slo_url=config.idp_slo_url,
            idp_x509_cert=config.idp_x509_cert,
            sp_entity_id=config.sp_entity_id,
            group_role_map=config.group_role_map,
        )


class SamlConfigUpdate(BaseModel):
    enabled: bool | None = None
    idp_entity_id: str | None = None
    idp_sso_url: str | None = None
    idp_slo_url: str | None = None
    idp_x509_cert: str | None = None
    sp_entity_id: str | None = None
    group_role_map: dict[str, str] | None = None


@router.get("/saml", response_model=SamlConfigResponse)
def get_saml_settings(
    db: Session = Depends(get_db), _actor: AuthContext = Depends(require_permission(SETTINGS_READ))
):
    return SamlConfigResponse.from_model(settings_service.get_saml_config(db))


@router.patch("/saml", response_model=SamlConfigResponse)
def update_saml_settings(
    payload: SamlConfigUpdate,
    db: Session = Depends(get_db),
    _actor: AuthContext = Depends(require_permission(SETTINGS_MANAGE)),
):
    config = settings_service.update_saml_config(db, **payload.model_dump())
    return SamlConfigResponse.from_model(config)


class TlsStatusResponse(BaseModel):
    source: str
    not_before: str
    not_after: str


class UploadTlsRequest(BaseModel):
    certificate_pem: str
    private_key_pem: str


class TlsReplaceResponse(BaseModel):
    status: TlsStatusResponse
    restarting: bool


def _tls_status(config: TlsListenerConfig) -> TlsStatusResponse:
    return TlsStatusResponse(
        source=config.source.value,
        not_before=config.not_before.isoformat(),
        not_after=config.not_after.isoformat(),
    )


_TLS_ERROR_STATUS = {
    "invalid_pem": status.HTTP_400_BAD_REQUEST,
    "unsupported_key_type": status.HTTP_400_BAD_REQUEST,
    "cert_key_mismatch": status.HTTP_400_BAD_REQUEST,
    "intermediate_not_ready": status.HTTP_503_SERVICE_UNAVAILABLE,
}


@router.get("/tls", response_model=TlsStatusResponse)
def get_tls_settings(
    db: Session = Depends(get_db), _actor: AuthContext = Depends(require_permission(SETTINGS_READ))
):
    config = tls_service.get_tls_config(db)
    if config is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return _tls_status(config)


@router.post("/tls/upload", response_model=TlsReplaceResponse)
def upload_tls_settings(
    payload: UploadTlsRequest,
    db: Session = Depends(get_db),
    actor: AuthContext = Depends(require_permission(SETTINGS_MANAGE)),
):
    try:
        config = tls_service.replace_with_uploaded(
            db,
            certificate_pem=payload.certificate_pem,
            private_key_pem=payload.private_key_pem,
            actor_user_id=actor.user_id,
        )
    except tls_service.TlsReplaceError as exc:
        raise HTTPException(
            status_code=_TLS_ERROR_STATUS.get(str(exc), status.HTTP_400_BAD_REQUEST), detail=str(exc)
        ) from exc

    _schedule_restart()
    return TlsReplaceResponse(status=_tls_status(config), restarting=True)


@router.post("/tls/issue-from-intermediate", response_model=TlsReplaceResponse)
def issue_tls_from_intermediate(
    db: Session = Depends(get_db),
    actor: AuthContext = Depends(require_permission(SETTINGS_MANAGE)),
):
    try:
        config = tls_service.replace_with_intermediate(db, actor_user_id=actor.user_id)
    except tls_service.TlsReplaceError as exc:
        raise HTTPException(
            status_code=_TLS_ERROR_STATUS.get(str(exc).split(":")[0], status.HTTP_400_BAD_REQUEST),
            detail=str(exc),
        ) from exc

    _schedule_restart()
    return TlsReplaceResponse(status=_tls_status(config), restarting=True)
