"""Email + Telegram delivery for certificate-expiry notices, and the
NotificationConfig singleton (SMTP/Telegram settings, admin-managed via
Settings). `smtp_password`/`telegram_bot_token` are stored envelope-encrypted
with the app master key (see core/crypto/envelope.py) — same approach as the
CA/TLS private keys, just for a small secret instead of a key.
"""

import json
import logging
import smtplib
import urllib.error
import urllib.request
from email.message import EmailMessage

from sqlalchemy.orm import Session

from capki.core.crypto import envelope
from capki.core.crypto.master_key import load_or_create_master_key
from capki.core.net import trust_store
from capki.db.base import utcnow
from capki.db.models.certificates import Certificate
from capki.db.models.settings import NotificationConfig
from capki.db.models.users import User

logger = logging.getLogger(__name__)

_SMTP_PASSWORD_AAD = b"notification_config:smtp_password"
_TELEGRAM_TOKEN_AAD = b"notification_config:telegram_bot_token"


class NotificationError(Exception):
    """Raised when email/Telegram delivery can't proceed — not configured,
    or the provider rejected the request."""


def get_notification_config(db: Session) -> NotificationConfig:
    config = db.get(NotificationConfig, 1)
    if config is None:
        config = NotificationConfig(id=1, updated_at=utcnow())
        db.add(config)
        db.commit()
        db.refresh(config)
    return config


def _encrypt_secret(plaintext: str, aad: bytes) -> tuple[bytes, dict]:
    master_key = load_or_create_master_key()
    return envelope.wrap_with_master_key(plaintext.encode("utf-8"), master_key, aad)


def _decrypt_secret(ciphertext: bytes, meta: dict, aad: bytes) -> str:
    master_key = load_or_create_master_key()
    return envelope.unwrap_with_master_key(ciphertext, master_key, meta, aad).decode("utf-8")


def update_notification_config(
    db: Session,
    *,
    expiry_warning_days: int | None = None,
    email_enabled: bool | None = None,
    smtp_host: str | None = None,
    smtp_port: int | None = None,
    smtp_username: str | None = None,
    smtp_password: str | None = None,
    smtp_use_tls: bool | None = None,
    smtp_from_address: str | None = None,
    telegram_enabled: bool | None = None,
    telegram_bot_token: str | None = None,
) -> NotificationConfig:
    """Updates whichever fields are non-None. `smtp_password`/
    `telegram_bot_token` are only re-encrypted when a non-empty value is
    passed — an empty string means "leave the stored secret unchanged", same
    convention as the TLS/SAML settings forms (never round-trip secrets back
    to the client, so there's nothing to "unset" here)."""
    config = get_notification_config(db)
    if expiry_warning_days is not None:
        config.expiry_warning_days = expiry_warning_days
    if email_enabled is not None:
        config.email_enabled = email_enabled
    if smtp_host is not None:
        config.smtp_host = smtp_host
    if smtp_port is not None:
        config.smtp_port = smtp_port
    if smtp_username is not None:
        config.smtp_username = smtp_username
    if smtp_password:
        config.smtp_password_encrypted, config.smtp_password_wrap_meta = _encrypt_secret(
            smtp_password, _SMTP_PASSWORD_AAD
        )
    if smtp_use_tls is not None:
        config.smtp_use_tls = smtp_use_tls
    if smtp_from_address is not None:
        config.smtp_from_address = smtp_from_address
    if telegram_enabled is not None:
        config.telegram_enabled = telegram_enabled
    if telegram_bot_token:
        config.telegram_bot_token_encrypted, config.telegram_bot_token_wrap_meta = _encrypt_secret(
            telegram_bot_token, _TELEGRAM_TOKEN_AAD
        )
    config.updated_at = utcnow()
    db.commit()
    return config


def send_email(config: NotificationConfig, *, to_address: str, subject: str, body: str) -> None:
    if not config.smtp_host or not config.smtp_from_address:
        raise NotificationError("smtp_not_configured")

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = config.smtp_from_address
    message["To"] = to_address
    message.set_content(body)

    with smtplib.SMTP(config.smtp_host, config.smtp_port, timeout=10) as smtp:
        if config.smtp_use_tls:
            smtp.starttls(context=trust_store.build_ssl_context())
        if config.smtp_username and config.smtp_password_encrypted:
            password = _decrypt_secret(
                config.smtp_password_encrypted, config.smtp_password_wrap_meta, _SMTP_PASSWORD_AAD
            )
            smtp.login(config.smtp_username, password)
        smtp.send_message(message)


def send_telegram(config: NotificationConfig, *, chat_id: str, text: str) -> None:
    if not config.telegram_bot_token_encrypted:
        raise NotificationError("telegram_not_configured")
    token = _decrypt_secret(
        config.telegram_bot_token_encrypted, config.telegram_bot_token_wrap_meta, _TELEGRAM_TOKEN_AAD
    )
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = json.dumps({"chat_id": chat_id, "text": text}).encode("utf-8")
    request = urllib.request.Request(
        url, data=payload, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(
            request, timeout=10, context=trust_store.build_ssl_context()
        ) as response:
            if response.status != 200:
                raise NotificationError(f"telegram_send_failed:{response.status}")
    except urllib.error.HTTPError as exc:
        raise NotificationError(f"telegram_send_failed:{exc.code}") from exc


def notify_expiring_certificate(
    db: Session, config: NotificationConfig, cert: Certificate, owner: User
) -> bool:
    """Attempts delivery on every channel the owner has enabled + configured
    contact info for. Returns True if at least one channel succeeded, so the
    caller can mark the cert as notified — if every channel fails (e.g. bad
    SMTP creds) it returns False so tomorrow's scheduler run retries."""
    days_left = (cert.not_after - utcnow()).days
    subject_line = f"Certificate expiring soon: {cert.subject_dn}"
    body = (
        f"Certificate {cert.subject_dn} (serial {cert.serial_hex}, profile {cert.profile_code}) "
        f"expires on {cert.not_after.strftime('%Y-%m-%d')} ({days_left} day(s) from now).\n\n"
        "Renew it before it expires to avoid an outage."
    )

    delivered = False

    if config.email_enabled and owner.email:
        try:
            send_email(config, to_address=owner.email, subject=subject_line, body=body)
            delivered = True
        except Exception:
            logger.exception("Failed to email expiry notice for cert %s to %s", cert.id, owner.email)

    if config.telegram_enabled and owner.telegram_chat_id:
        try:
            send_telegram(config, chat_id=owner.telegram_chat_id, text=f"{subject_line}\n\n{body}")
            delivered = True
        except Exception:
            logger.exception(
                "Failed to send Telegram expiry notice for cert %s to chat %s",
                cert.id,
                owner.telegram_chat_id,
            )

    return delivered
