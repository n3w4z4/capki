import logging
import os
import threading

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from capki.api.deps import require_permission
from capki.core.rbac.context import AuthContext
from capki.core.rbac.permissions import SETTINGS_MANAGE, SETTINGS_READ
from capki.db.base import utcnow
from capki.db.models.settings import (
    LogForwardingConfig,
    NotificationConfig,
    SamlConfig,
    TlsListenerConfig,
    TrustedCaCert,
)
from capki.db.models.users import User
from capki.db.session import get_db
from capki.services import (
    log_forwarding_service,
    notification_service,
    settings_service,
    tls_service,
    trust_service,
)

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


class NotificationConfigResponse(BaseModel):
    expiry_warning_days: int
    email_enabled: bool
    smtp_host: str | None
    smtp_port: int
    smtp_username: str | None
    smtp_password_set: bool
    smtp_use_tls: bool
    smtp_from_address: str | None
    telegram_enabled: bool
    telegram_bot_token_set: bool

    @classmethod
    def from_model(cls, config: NotificationConfig) -> "NotificationConfigResponse":
        return cls(
            expiry_warning_days=config.expiry_warning_days,
            email_enabled=config.email_enabled,
            smtp_host=config.smtp_host,
            smtp_port=config.smtp_port,
            smtp_username=config.smtp_username,
            smtp_password_set=config.smtp_password_encrypted is not None,
            smtp_use_tls=config.smtp_use_tls,
            smtp_from_address=config.smtp_from_address,
            telegram_enabled=config.telegram_enabled,
            telegram_bot_token_set=config.telegram_bot_token_encrypted is not None,
        )


class NotificationConfigUpdate(BaseModel):
    expiry_warning_days: int | None = None
    email_enabled: bool | None = None
    smtp_host: str | None = None
    smtp_port: int | None = None
    smtp_username: str | None = None
    smtp_password: str | None = None  # blank/omitted = leave the stored secret unchanged
    smtp_use_tls: bool | None = None
    smtp_from_address: str | None = None
    telegram_enabled: bool | None = None
    telegram_bot_token: str | None = None  # blank/omitted = leave the stored secret unchanged


class NotificationTestResponse(BaseModel):
    email_sent: bool
    email_error: str | None
    telegram_sent: bool
    telegram_error: str | None


@router.get("/notifications", response_model=NotificationConfigResponse)
def get_notification_settings(
    db: Session = Depends(get_db), _actor: AuthContext = Depends(require_permission(SETTINGS_READ))
):
    return NotificationConfigResponse.from_model(notification_service.get_notification_config(db))


@router.patch("/notifications", response_model=NotificationConfigResponse)
def update_notification_settings(
    payload: NotificationConfigUpdate,
    db: Session = Depends(get_db),
    _actor: AuthContext = Depends(require_permission(SETTINGS_MANAGE)),
):
    config = notification_service.update_notification_config(db, **payload.model_dump())
    return NotificationConfigResponse.from_model(config)


@router.post("/notifications/test", response_model=NotificationTestResponse)
def test_notification_settings(
    db: Session = Depends(get_db),
    actor: AuthContext = Depends(require_permission(SETTINGS_MANAGE)),
):
    """Sends a one-off test message on every enabled channel to the calling
    admin's own email / Telegram chat ID, so config mistakes (bad SMTP
    creds, wrong bot token) surface immediately instead of on tomorrow's
    scheduled expiry check."""
    config = notification_service.get_notification_config(db)
    actor_user = db.get(User, actor.user_id)

    email_sent = False
    email_error: str | None = None
    if not config.email_enabled:
        email_error = "email_notifications_disabled_in_saved_settings"
    elif actor_user is None or not actor_user.email:
        email_error = "no_email_on_account"
    else:
        try:
            notification_service.send_email(
                config,
                to_address=actor_user.email,
                subject="capki: test notification",
                body="This is a test notification from capki's certificate-expiry alerting.",
            )
            email_sent = True
        except Exception as exc:
            email_error = str(exc) or exc.__class__.__name__

    telegram_sent = False
    telegram_error: str | None = None
    if not config.telegram_enabled:
        telegram_error = "telegram_notifications_disabled_in_saved_settings"
    elif actor_user is None or not actor_user.telegram_chat_id:
        telegram_error = "no_telegram_chat_id_on_account"
    else:
        try:
            notification_service.send_telegram(
                config,
                chat_id=actor_user.telegram_chat_id,
                text="capki: test notification\n\nThis is a test notification from capki's certificate-expiry alerting.",
            )
            telegram_sent = True
        except Exception as exc:
            telegram_error = str(exc) or exc.__class__.__name__

    return NotificationTestResponse(
        email_sent=email_sent,
        email_error=email_error,
        telegram_sent=telegram_sent,
        telegram_error=telegram_error,
    )


class LogForwardingConfigResponse(BaseModel):
    app_log_min_level: str
    hec_enabled: bool
    hec_send_app_logs: bool
    hec_send_audit_logs: bool
    hec_url: str | None
    hec_token_set: bool
    hec_source: str | None
    hec_sourcetype: str | None
    hec_index: str | None
    hec_verify_tls: bool
    syslog_enabled: bool
    syslog_send_app_logs: bool
    syslog_send_audit_logs: bool
    syslog_host: str | None
    syslog_port: int
    syslog_protocol: str
    syslog_facility: int

    @classmethod
    def from_model(cls, config: LogForwardingConfig) -> "LogForwardingConfigResponse":
        return cls(
            app_log_min_level=config.app_log_min_level,
            hec_enabled=config.hec_enabled,
            hec_send_app_logs=config.hec_send_app_logs,
            hec_send_audit_logs=config.hec_send_audit_logs,
            hec_url=config.hec_url,
            hec_token_set=config.hec_token_encrypted is not None,
            hec_source=config.hec_source,
            hec_sourcetype=config.hec_sourcetype,
            hec_index=config.hec_index,
            hec_verify_tls=config.hec_verify_tls,
            syslog_enabled=config.syslog_enabled,
            syslog_send_app_logs=config.syslog_send_app_logs,
            syslog_send_audit_logs=config.syslog_send_audit_logs,
            syslog_host=config.syslog_host,
            syslog_port=config.syslog_port,
            syslog_protocol=config.syslog_protocol,
            syslog_facility=config.syslog_facility,
        )


class LogForwardingConfigUpdate(BaseModel):
    app_log_min_level: str | None = None
    hec_enabled: bool | None = None
    hec_send_app_logs: bool | None = None
    hec_send_audit_logs: bool | None = None
    hec_url: str | None = None
    hec_token: str | None = None  # blank/omitted = leave the stored secret unchanged
    hec_source: str | None = None
    hec_sourcetype: str | None = None
    hec_index: str | None = None
    hec_verify_tls: bool | None = None
    syslog_enabled: bool | None = None
    syslog_send_app_logs: bool | None = None
    syslog_send_audit_logs: bool | None = None
    syslog_host: str | None = None
    syslog_port: int | None = None
    syslog_protocol: str | None = None
    syslog_facility: int | None = None


class LogForwardingTestResponse(BaseModel):
    hec_sent: bool
    hec_error: str | None
    syslog_sent: bool
    syslog_error: str | None


@router.get("/log-forwarding", response_model=LogForwardingConfigResponse)
def get_log_forwarding_settings(
    db: Session = Depends(get_db), _actor: AuthContext = Depends(require_permission(SETTINGS_READ))
):
    return LogForwardingConfigResponse.from_model(log_forwarding_service.get_log_forwarding_config(db))


@router.patch("/log-forwarding", response_model=LogForwardingConfigResponse)
def update_log_forwarding_settings(
    payload: LogForwardingConfigUpdate,
    db: Session = Depends(get_db),
    _actor: AuthContext = Depends(require_permission(SETTINGS_MANAGE)),
):
    try:
        config = log_forwarding_service.update_log_forwarding_config(db, **payload.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return LogForwardingConfigResponse.from_model(config)


@router.post("/log-forwarding/test", response_model=LogForwardingTestResponse)
def test_log_forwarding_settings(
    db: Session = Depends(get_db),
    _actor: AuthContext = Depends(require_permission(SETTINGS_MANAGE)),
):
    """Sends one synthetic test event straight to each enabled output
    (bypassing the queue, so failures surface in this response instead of
    silently in the background worker's debug log)."""
    config = log_forwarding_service.get_log_forwarding_config(db)
    test_event = {
        "timestamp": utcnow().isoformat(),
        "level": "INFO",
        "logger": "capki.settings",
        "message": "capki log forwarding test event",
    }

    hec_sent = False
    hec_error: str | None = None
    if not config.hec_enabled:
        hec_error = "hec_disabled_in_saved_settings"
    else:
        try:
            log_forwarding_service.send_hec_event(config, test_event)
            hec_sent = True
        except Exception as exc:
            hec_error = str(exc) or exc.__class__.__name__

    syslog_sent = False
    syslog_error: str | None = None
    if not config.syslog_enabled:
        syslog_error = "syslog_disabled_in_saved_settings"
    else:
        try:
            log_forwarding_service.send_syslog_event(config, test_event, severity=6, msgid="test")
            syslog_sent = True
        except Exception as exc:
            syslog_error = str(exc) or exc.__class__.__name__

    return LogForwardingTestResponse(
        hec_sent=hec_sent, hec_error=hec_error, syslog_sent=syslog_sent, syslog_error=syslog_error
    )


# --- Trusted CA certificates (outbound TLS trust store) ----------------


class TrustedCaResponse(BaseModel):
    id: int
    label: str | None
    subject_dn: str
    issuer_dn: str
    serial_hex: str
    sha256_fingerprint: str
    not_before: str
    not_after: str
    is_self_signed: bool
    enabled: bool
    added_at: str

    @classmethod
    def from_model(cls, row: TrustedCaCert) -> "TrustedCaResponse":
        return cls(
            id=row.id,
            label=row.label,
            subject_dn=row.subject_dn,
            issuer_dn=row.issuer_dn,
            serial_hex=row.serial_hex,
            sha256_fingerprint=row.sha256_fingerprint,
            not_before=row.not_before.isoformat(),
            not_after=row.not_after.isoformat(),
            is_self_signed=row.is_self_signed,
            enabled=row.enabled,
            added_at=row.added_at.isoformat(),
        )


class AddTrustedCaRequest(BaseModel):
    pem: str
    label: str | None = None


class UpdateTrustedCaRequest(BaseModel):
    enabled: bool | None = None
    label: str | None = None


class TrustedCaUrlTestRequest(BaseModel):
    url: str


class TrustedCaUrlTestResponse(BaseModel):
    ok: bool
    error: str | None


_TRUST_ERROR_STATUS = {
    "invalid_pem": status.HTTP_400_BAD_REQUEST,
    "not_a_ca": status.HTTP_400_BAD_REQUEST,
    "duplicate": status.HTTP_409_CONFLICT,
    "no_certificates": status.HTTP_400_BAD_REQUEST,
}


@router.get("/trusted-cas", response_model=list[TrustedCaResponse])
def list_trusted_cas(
    db: Session = Depends(get_db), _actor: AuthContext = Depends(require_permission(SETTINGS_READ))
):
    return [TrustedCaResponse.from_model(row) for row in trust_service.list_trusted_cas(db)]


@router.post("/trusted-cas", response_model=list[TrustedCaResponse])
def add_trusted_ca(
    payload: AddTrustedCaRequest,
    db: Session = Depends(get_db),
    actor: AuthContext = Depends(require_permission(SETTINGS_MANAGE)),
):
    try:
        added = trust_service.add_trusted_cas(
            db, pem=payload.pem, label=payload.label, actor_user_id=actor.user_id
        )
    except trust_service.TrustStoreError as exc:
        raise HTTPException(
            status_code=_TRUST_ERROR_STATUS.get(str(exc), status.HTTP_400_BAD_REQUEST),
            detail=str(exc),
        ) from exc
    return [TrustedCaResponse.from_model(row) for row in added]


@router.patch("/trusted-cas/{ca_id}", response_model=TrustedCaResponse)
def update_trusted_ca(
    ca_id: int,
    payload: UpdateTrustedCaRequest,
    db: Session = Depends(get_db),
    actor: AuthContext = Depends(require_permission(SETTINGS_MANAGE)),
):
    row = trust_service.update_trusted_ca(
        db,
        ca_id,
        enabled=payload.enabled,
        label=payload.label,
        actor_user_id=actor.user_id,
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return TrustedCaResponse.from_model(row)


@router.delete("/trusted-cas/{ca_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_trusted_ca(
    ca_id: int,
    db: Session = Depends(get_db),
    actor: AuthContext = Depends(require_permission(SETTINGS_MANAGE)),
):
    if not trust_service.delete_trusted_ca(db, ca_id, actor_user_id=actor.user_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)


@router.post("/trusted-cas/test", response_model=TrustedCaUrlTestResponse)
def test_trusted_ca_url(
    payload: TrustedCaUrlTestRequest,
    _actor: AuthContext = Depends(require_permission(SETTINGS_MANAGE)),
):
    ok, error = trust_service.test_url(payload.url)
    return TrustedCaUrlTestResponse(ok=ok, error=error)
