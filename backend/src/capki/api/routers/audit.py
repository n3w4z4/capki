from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from capki.api.deps import require_permission
from capki.core.rbac.context import AuthContext
from capki.core.rbac.permissions import AUDIT_READ
from capki.db.models.users import User
from capki.db.session import get_db
from capki.services import audit_service

router = APIRouter(prefix="/audit-log", tags=["audit"])


class AuditLogEntrySummary(BaseModel):
    id: int
    timestamp: str
    actor_type: str
    actor_username: str | None
    action: str
    target_type: str | None
    target_id: str | None
    success: bool
    detail: dict | None


@router.get("", response_model=list[AuditLogEntrySummary])
def list_audit_log(
    limit: int = Query(default=100, le=500),
    db: Session = Depends(get_db),
    _actor: AuthContext = Depends(require_permission(AUDIT_READ)),
):
    entries = audit_service.list_recent(db, limit=limit)

    user_ids = {e.actor_user_id for e in entries if e.actor_user_id is not None}
    usernames: dict[int, str] = {}
    if user_ids:
        usernames = {
            u.id: u.username for u in db.query(User).filter(User.id.in_(user_ids)).all()
        }

    return [
        AuditLogEntrySummary(
            id=e.id,
            timestamp=e.timestamp.isoformat(),
            actor_type=e.actor_type.value,
            actor_username=usernames.get(e.actor_user_id) if e.actor_user_id else None,
            action=e.action,
            target_type=e.target_type,
            target_id=e.target_id,
            success=e.success,
            detail=e.detail,
        )
        for e in entries
    ]
