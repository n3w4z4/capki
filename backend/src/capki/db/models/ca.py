import datetime as dt
import enum

from sqlalchemy import JSON, Enum, ForeignKey, Integer, LargeBinary, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from capki.db.base import Base, TimestampMixin, UTCDateTime


class CaType(str, enum.Enum):
    ROOT = "root"
    INTERMEDIATE = "intermediate"


class CaStatus(str, enum.Enum):
    PENDING = "pending"
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    SUPERSEDED = "superseded"


class CertificateAuthority(TimestampMixin, Base):
    __tablename__ = "certificate_authorities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    type: Mapped[CaType] = mapped_column(Enum(CaType, native_enum=False))
    name: Mapped[str] = mapped_column(String(255))
    subject_dn: Mapped[str] = mapped_column(String(500))
    certificate_pem: Mapped[str | None] = mapped_column(Text, nullable=True)
    private_key_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    key_wrap_meta: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    public_key_fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True)
    not_before: Mapped[dt.datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    not_after: Mapped[dt.datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    parent_ca_id: Mapped[int | None] = mapped_column(
        ForeignKey("certificate_authorities.id"), nullable=True
    )
    status: Mapped[CaStatus] = mapped_column(Enum(CaStatus, native_enum=False), default=CaStatus.PENDING)
    crl_number: Mapped[int] = mapped_column(Integer, default=0)
