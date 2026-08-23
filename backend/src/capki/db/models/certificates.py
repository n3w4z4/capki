import datetime as dt
import enum

from sqlalchemy import JSON, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from capki.db.base import Base, TimestampMixin, UTCDateTime


class CertificateStatus(str, enum.Enum):
    VALID = "valid"
    REVOKED = "revoked"
    EXPIRED = "expired"


class IssuedVia(str, enum.Enum):
    UI = "ui"
    API = "api"


class Certificate(TimestampMixin, Base):
    __tablename__ = "certificates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ca_id: Mapped[int] = mapped_column(ForeignKey("certificate_authorities.id"), index=True)
    serial_hex: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    profile_code: Mapped[str] = mapped_column(ForeignKey("cert_profiles.code"))
    subject_dn: Mapped[str] = mapped_column(String(500))
    sans: Mapped[list[str]] = mapped_column(JSON, default=list)
    certificate_pem: Mapped[str] = mapped_column(Text)
    csr_pem: Mapped[str] = mapped_column(Text)
    public_key_fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True)
    not_before: Mapped[dt.datetime] = mapped_column(UTCDateTime())
    not_after: Mapped[dt.datetime] = mapped_column(UTCDateTime())
    status: Mapped[CertificateStatus] = mapped_column(
        Enum(CertificateStatus, native_enum=False), default=CertificateStatus.VALID
    )
    requested_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    issued_via: Mapped[IssuedVia] = mapped_column(Enum(IssuedVia, native_enum=False))
    api_token_id: Mapped[int | None] = mapped_column(ForeignKey("api_tokens.id"), nullable=True)
    expiry_notified_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime(), nullable=True)


class Revocation(Base):
    __tablename__ = "revocations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    certificate_id: Mapped[int] = mapped_column(ForeignKey("certificates.id"), unique=True)
    revoked_at: Mapped[dt.datetime] = mapped_column(UTCDateTime())
    reason: Mapped[str] = mapped_column(String(32))
    revoked_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)


class CrlIssuance(Base):
    __tablename__ = "crl_issuances"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ca_id: Mapped[int] = mapped_column(ForeignKey("certificate_authorities.id"), index=True)
    crl_number: Mapped[int] = mapped_column(Integer)
    crl_pem: Mapped[str] = mapped_column(Text)
    this_update: Mapped[dt.datetime] = mapped_column(UTCDateTime())
    next_update: Mapped[dt.datetime] = mapped_column(UTCDateTime())
    created_at: Mapped[dt.datetime] = mapped_column(UTCDateTime())
