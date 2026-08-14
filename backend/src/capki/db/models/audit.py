import datetime as dt
import enum

from sqlalchemy import JSON, Boolean, Enum, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from capki.db.base import Base, UTCDateTime


class ActorType(str, enum.Enum):
    USER = "user"
    TOKEN = "token"
    SYSTEM = "system"


class AuditLogEntry(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[dt.datetime] = mapped_column(UTCDateTime(), index=True)
    actor_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    actor_token_id: Mapped[int | None] = mapped_column(ForeignKey("api_tokens.id"), nullable=True)
    actor_type: Mapped[ActorType] = mapped_column(Enum(ActorType, native_enum=False))
    action: Mapped[str] = mapped_column(String(64), index=True)
    target_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    detail: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, default=True)
