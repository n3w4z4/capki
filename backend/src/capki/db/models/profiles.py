from sqlalchemy import JSON, Boolean, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from capki.db.base import Base


class CertProfile(Base):
    __tablename__ = "cert_profiles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code: Mapped[str] = mapped_column(String(32), unique=True)
    display_name: Mapped[str] = mapped_column(String(128))
    key_usage: Mapped[list[str]] = mapped_column(JSON)
    extended_key_usage: Mapped[list[str]] = mapped_column(JSON)
    basic_constraints: Mapped[str] = mapped_column(String(64), default="CA:FALSE")
    max_validity_days: Mapped[int] = mapped_column(Integer)
    allowed_san_types: Mapped[list[str]] = mapped_column(JSON)
    requires_email: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
