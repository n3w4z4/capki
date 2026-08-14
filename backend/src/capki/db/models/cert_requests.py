import datetime as dt
import enum

from sqlalchemy import Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from capki.db.base import Base, TimestampMixin, UTCDateTime


class CertRequestStatus(str, enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class CertificateRequest(TimestampMixin, Base):
    """A CSR submitted by a `requester`-role user, awaiting an
    operator/admin's approval (cert:approve) before it's actually signed.
    See services/cert_request_service.py."""

    __tablename__ = "certificate_requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    csr_pem: Mapped[str] = mapped_column(Text)
    profile_code: Mapped[str] = mapped_column(ForeignKey("cert_profiles.code"))
    requested_by_user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    status: Mapped[CertRequestStatus] = mapped_column(
        Enum(CertRequestStatus, native_enum=False), default=CertRequestStatus.PENDING, index=True
    )
    reviewed_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    reviewed_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    rejection_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)
    certificate_id: Mapped[int | None] = mapped_column(ForeignKey("certificates.id"), nullable=True)
