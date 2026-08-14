"""API bearer tokens for the automation path (`POST /certificates` etc. with
`Authorization: Bearer catk_...`). Only a SHA-256 hash of the token is ever
stored; the raw value is returned once, at creation time, and never again.
"""

import hashlib
import secrets

from sqlalchemy.orm import Session

from capki.db.base import utcnow
from capki.db.models.audit import ActorType
from capki.db.models.tokens import ApiToken
from capki.db.models.users import User
from capki.services.audit_service import log_action

TOKEN_PREFIX = "catk_"
_SECRET_LEN_BYTES = 32
_LOOKUP_PREFIX_LEN = 12  # chars of the secret (after "catk_") used for fast DB lookup


class TokenError(Exception):
    """Raised for token-lifecycle preconditions the API layer maps to HTTP
    status codes (e.g. not_found -> 404, forbidden -> 403)."""


def _hash(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def create_token(
    db: Session, *, user_id: int, name: str, expires_at=None
) -> tuple[ApiToken, str]:
    secret = secrets.token_urlsafe(_SECRET_LEN_BYTES)
    raw_token = f"{TOKEN_PREFIX}{secret}"

    token = ApiToken(
        user_id=user_id,
        name=name,
        token_prefix=secret[:_LOOKUP_PREFIX_LEN],
        token_hash=_hash(raw_token),
        created_at=utcnow(),
        expires_at=expires_at,
    )
    db.add(token)
    db.commit()

    log_action(
        db,
        actor_type=ActorType.USER,
        actor_user_id=user_id,
        action="token.create",
        target_type="api_token",
        target_id=str(token.id),
        detail={"name": name},
    )
    return token, raw_token


def authenticate_token(db: Session, raw_token: str) -> tuple[User, ApiToken] | None:
    if not raw_token.startswith(TOKEN_PREFIX):
        return None
    secret = raw_token[len(TOKEN_PREFIX) :]
    prefix = secret[:_LOOKUP_PREFIX_LEN]

    candidates = db.query(ApiToken).filter(ApiToken.token_prefix == prefix).all()
    token_hash = _hash(raw_token)
    token = next((t for t in candidates if t.token_hash == token_hash), None)
    if token is None:
        return None
    if token.revoked_at is not None:
        return None
    if token.expires_at is not None and utcnow() >= token.expires_at:
        return None

    user = db.get(User, token.user_id)
    if user is None or not user.is_active:
        return None

    token.last_used_at = utcnow()
    db.commit()
    return user, token


def revoke_token(db: Session, *, token_id: int, actor_user_id: int, is_admin: bool) -> ApiToken:
    token = db.get(ApiToken, token_id)
    if token is None:
        raise TokenError("not_found")
    if token.user_id != actor_user_id and not is_admin:
        raise TokenError("forbidden")
    if token.revoked_at is None:
        token.revoked_at = utcnow()
        token.revoked_by_user_id = actor_user_id
        db.commit()
        log_action(
            db,
            actor_type=ActorType.USER,
            actor_user_id=actor_user_id,
            action="token.revoke",
            target_type="api_token",
            target_id=str(token.id),
        )
    return token
