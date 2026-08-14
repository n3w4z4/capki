import datetime as dt
import hashlib
import secrets

from sqlalchemy.orm import Session as DbSession

from capki.config import settings
from capki.db.base import utcnow
from capki.db.models.users import Session as SessionModel


def _hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def create_session(
    db: DbSession, user_id: int, ip_address: str | None, user_agent: str | None
) -> tuple[str, dt.datetime]:
    raw_token = secrets.token_urlsafe(32)
    now = utcnow()
    expires_at = now + dt.timedelta(minutes=settings.session_idle_timeout_minutes)

    session = SessionModel(
        id=_hash_token(raw_token),
        user_id=user_id,
        created_at=now,
        expires_at=expires_at,
        last_seen_at=now,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    db.add(session)
    db.commit()
    return raw_token, expires_at


def get_valid_session(db: DbSession, raw_token: str) -> SessionModel | None:
    """Looks up the session for a raw cookie value, enforcing the sliding
    idle timeout and the absolute session lifetime, and extends the sliding
    window on every successful lookup. Returns None (without raising) for
    anything invalid/expired/revoked, matching how callers use this in an
    auth dependency."""
    session = db.get(SessionModel, _hash_token(raw_token))
    if session is None or session.revoked_at is not None:
        return None

    now = utcnow()
    absolute_deadline = session.created_at + dt.timedelta(
        minutes=settings.session_absolute_timeout_minutes
    )
    if now >= session.expires_at or now >= absolute_deadline:
        return None

    session.last_seen_at = now
    session.expires_at = min(
        now + dt.timedelta(minutes=settings.session_idle_timeout_minutes), absolute_deadline
    )
    db.commit()
    return session


def revoke_session(db: DbSession, raw_token: str) -> None:
    session = db.get(SessionModel, _hash_token(raw_token))
    if session is not None and session.revoked_at is None:
        session.revoked_at = utcnow()
        db.commit()


def revoke_all_sessions_for_user(db: DbSession, user_id: int) -> None:
    now = utcnow()
    db.query(SessionModel).filter(
        SessionModel.user_id == user_id, SessionModel.revoked_at.is_(None)
    ).update({"revoked_at": now})
    db.commit()
