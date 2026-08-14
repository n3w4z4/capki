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


class AppSetting(Base):
    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[str] = mapped_column(Text)
    updated_at: Mapped[dt.datetime] = mapped_column(UTCDateTime())
    updated_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
