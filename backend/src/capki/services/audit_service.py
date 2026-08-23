import contextvars

from sqlalchemy.orm import Session

from capki.db.base import utcnow
from capki.db.models.audit import ActorType, AuditLogEntry
from capki.services import log_forwarding_service

# Set once per HTTP request by main.py's middleware, so every log_action()
# call gets the requester's IP without every one of ~25 call sites having to
# thread it through explicitly. Falls back to None outside a request
# context (e.g. scheduler jobs), which is correct — there's no requester.
_request_ip: contextvars.ContextVar[str | None] = contextvars.ContextVar("_request_ip", default=None)


def set_request_ip(ip: str | None) -> contextvars.Token:
    return _request_ip.set(ip)


def reset_request_ip(token: contextvars.Token) -> None:
    _request_ip.reset(token)


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
    if ip_address is None:
        ip_address = _request_ip.get()

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

    try:
        log_forwarding_service.enqueue_audit_event(
            timestamp=entry.timestamp,
            actor_type=actor_type.value,
            actor_user_id=actor_user_id,
            actor_token_id=actor_token_id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            detail=detail,
            ip_address=ip_address,
            success=success,
        )
    except Exception:
        pass  # forwarding must never break the actual audit write


def list_recent(db: Session, limit: int = 100) -> list[AuditLogEntry]:
    return db.query(AuditLogEntry).order_by(AuditLogEntry.id.desc()).limit(limit).all()
