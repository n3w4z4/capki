from sqlalchemy.orm import Session

from capki.db.base import utcnow
from capki.db.models.audit import ActorType, AuditLogEntry


def log_action(
    db: Session,
    *,
    actor_type: ActorType,
    action: str,
    actor_user_id: int | None = None,
    actor_token_id: int | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    detail: dict | None = None,
    ip_address: str | None = None,
    success: bool = True,
) -> None:
    entry = AuditLogEntry(
        timestamp=utcnow(),
        actor_user_id=actor_user_id,
        actor_token_id=actor_token_id,
        actor_type=actor_type,
        action=action,
        target_type=target_type,
        target_id=target_id,
        detail=detail,
        ip_address=ip_address,
        success=success,
    )
    db.add(entry)
    db.commit()


def list_recent(db: Session, limit: int = 100) -> list[AuditLogEntry]:
    return db.query(AuditLogEntry).order_by(AuditLogEntry.id.desc()).limit(limit).all()
