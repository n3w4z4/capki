import datetime as dt
import enum

from sqlalchemy import Boolean, Enum, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from capki.db.base import Base, TimestampMixin, UTCDateTime
from capki.db.models.rbac import UserRole


class AuthSource(str, enum.Enum):
    LOCAL = "local"
    SAML = "saml"


class User(TimestampMixin, Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    auth_source: Mapped[AuthSource] = mapped_column(
        Enum(AuthSource, native_enum=False), default=AuthSource.LOCAL
    )
    saml_name_id: Mapped[str | None] = mapped_column(String(255), unique=True, nullable=True)
    full_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_login_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime(), nullable=True)

    user_roles: Mapped[list[UserRole]] = relationship(back_populates="user", cascade="all, delete-orphan")


class Session(Base):
    """Server-side session; primary key is the SHA-256 hash of the opaque
    cookie value handed to the client — the raw value is never stored."""

    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    created_at: Mapped[dt.datetime] = mapped_column(UTCDateTime())
    expires_at: Mapped[dt.datetime] = mapped_column(UTCDateTime())
    last_seen_at: Mapped[dt.datetime] = mapped_column(UTCDateTime())
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)
    revoked_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime(), nullable=True)
