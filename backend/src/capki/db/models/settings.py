import datetime as dt
import enum

from sqlalchemy import JSON, Boolean, Enum, ForeignKey, Integer, LargeBinary, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from capki.db.base import Base, UTCDateTime


class TlsSource(str, enum.Enum):
    SELF_SIGNED = "self_signed"
    UPLOADED = "uploaded"
    ISSUED_BY_INTERMEDIATE = "issued_by_intermediate"


class TlsListenerConfig(Base):
    """Singleton row (id=1) describing the web server's own TLS cert/key —
    separate from any CA managed by the app."""

    __tablename__ = "tls_listener_config"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    source: Mapped[TlsSource] = mapped_column(Enum(TlsSource, native_enum=False))
    certificate_pem: Mapped[str] = mapped_column(Text)
    private_key_encrypted: Mapped[bytes] = mapped_column(LargeBinary)
    key_wrap_meta: Mapped[dict] = mapped_column(JSON)
    not_before: Mapped[dt.datetime] = mapped_column(UTCDateTime())
    not_after: Mapped[dt.datetime] = mapped_column(UTCDateTime())
    updated_at: Mapped[dt.datetime] = mapped_column(UTCDateTime())


class SamlConfig(Base):
    """Singleton row (id=1) holding the SAML SP <-> Entra ID configuration."""

    __tablename__ = "saml_config"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    idp_entity_id: Mapped[str | None] = mapped_column(String(500), nullable=True)
    idp_sso_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    idp_slo_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    idp_x509_cert: Mapped[str | None] = mapped_column(Text, nullable=True)
    sp_entity_id: Mapped[str | None] = mapped_column(String(500), nullable=True)
    attribute_map: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    group_role_map: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    updated_at: Mapped[dt.datetime] = mapped_column(UTCDateTime())


class NotificationConfig(Base):
    """Singleton row (id=1) holding email/Telegram delivery settings for
    certificate-expiry notifications. `smtp_password`/`telegram_bot_token`
    are stored envelope-encrypted with the app master key (see
    core/crypto/envelope.py), same as the CA/TLS private keys."""

    __tablename__ = "notification_config"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    expiry_warning_days: Mapped[int] = mapped_column(Integer, default=30)

    email_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    smtp_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    smtp_port: Mapped[int] = mapped_column(Integer, default=587)
    smtp_username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    smtp_password_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    smtp_password_wrap_meta: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    smtp_use_tls: Mapped[bool] = mapped_column(Boolean, default=True)
    smtp_from_address: Mapped[str | None] = mapped_column(String(255), nullable=True)

    telegram_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    telegram_bot_token_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    telegram_bot_token_wrap_meta: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    updated_at: Mapped[dt.datetime] = mapped_column(UTCDateTime())


class LogForwardingConfig(Base):
    """Singleton row (id=1) holding external log-forwarding settings —
    application logs and/or audit-log entries mirrored out to a Splunk/Cribl
    HTTP Event Collector and/or a syslog receiver, as JSON. `hec_token` is
    stored envelope-encrypted with the app master key (see
    core/crypto/envelope.py), same as the SMTP password / Telegram bot
    token. HEC and syslog are independently enabled and independently
    choose which stream(s) they receive."""

    __tablename__ = "log_forwarding_config"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)

    app_log_min_level: Mapped[str] = mapped_column(String(16), default="WARNING")

    hec_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    hec_send_app_logs: Mapped[bool] = mapped_column(Boolean, default=True)
    hec_send_audit_logs: Mapped[bool] = mapped_column(Boolean, default=True)
    hec_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    hec_token_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    hec_token_wrap_meta: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    hec_source: Mapped[str | None] = mapped_column(String(255), nullable=True)
    hec_sourcetype: Mapped[str | None] = mapped_column(String(255), nullable=True)
    hec_index: Mapped[str | None] = mapped_column(String(255), nullable=True)
    hec_verify_tls: Mapped[bool] = mapped_column(Boolean, default=True)

    syslog_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    syslog_send_app_logs: Mapped[bool] = mapped_column(Boolean, default=True)
    syslog_send_audit_logs: Mapped[bool] = mapped_column(Boolean, default=True)
    syslog_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    syslog_port: Mapped[int] = mapped_column(Integer, default=514)
    syslog_protocol: Mapped[str] = mapped_column(String(16), default="udp")  # udp | tcp | tcp_tls
    syslog_facility: Mapped[int] = mapped_column(Integer, default=16)  # local0

    updated_at: Mapped[dt.datetime] = mapped_column(UTCDateTime())


class AppSetting(Base):
    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[str] = mapped_column(Text)
    updated_at: Mapped[dt.datetime] = mapped_column(UTCDateTime())
    updated_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
