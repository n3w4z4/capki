import re

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from capki.api.deps import require_permission
from capki.core.rbac.context import AuthContext
from capki.core.rbac.permissions import AUDIT_READ
from capki.db.models.certificates import Certificate
from capki.db.models.users import User
from capki.db.session import get_db
from capki.services import audit_service

router = APIRouter(prefix="/audit-log", tags=["audit"])

_CN_PATTERN = re.compile(r"CN=([^,]+)")


class AuditLogEntrySummary(BaseModel):
    id: int
    timestamp: str
    actor_type: str
    actor_username: str | None
    action: str
    target_type: str | None
    target_id: str | None
    target_label: str | None
    success: bool
    detail: dict | None
    ip_address: str | None


@router.get("", response_model=list[AuditLogEntrySummary])
def list_audit_log(
    limit: int = Query(default=100, le=500),
    db: Session = Depends(get_db),
    _actor: AuthContext = Depends(require_permission(AUDIT_READ)),
):
    entries = audit_service.list_recent(db, limit=limit)

    def _target_int_ids(target_type: str) -> set[int]:
        return {
            int(e.target_id)
            for e in entries
            if e.target_type == target_type and e.target_id is not None and e.target_id.isdigit()
        }

    user_ids = {e.actor_user_id for e in entries if e.actor_user_id is not None}
    user_ids |= _target_int_ids("user")
    usernames: dict[int, str] = {}
    if user_ids:
        usernames = {u.id: u.username for u in db.query(User).filter(User.id.in_(user_ids)).all()}

    cert_ids = _target_int_ids("certificate")
    cert_names: dict[int, str] = {}
    if cert_ids:
        for cert_id, subject_dn in (
            db.query(Certificate.id, Certificate.subject_dn).filter(Certificate.id.in_(cert_ids)).all()
        ):
            match = _CN_PATTERN.search(subject_dn)
            cert_names[cert_id] = match.group(1) if match else subject_dn

    def _target_label(target_type: str | None, target_id: str | None) -> str | None:
        if target_type is None or target_id is None or not target_id.isdigit():
            return None
        tid = int(target_id)
        if target_type == "user":
            return usernames.get(tid)
        if target_type == "certificate":
            return cert_names.get(tid)
        return None

    return [
        AuditLogEntrySummary(
            id=e.id,
            timestamp=e.timestamp.isoformat(),
            actor_type=e.actor_type.value,
            actor_username=usernames.get(e.actor_user_id) if e.actor_user_id else None,
            action=e.action,
            target_type=e.target_type,
            target_id=e.target_id,
            target_label=_target_label(e.target_type, e.target_id),
            success=e.success,
            detail=e.detail,
            ip_address=e.ip_address,
        )
        for e in entries
    ]
