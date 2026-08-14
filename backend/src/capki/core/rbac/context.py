from dataclasses import dataclass

from sqlalchemy.orm import Session as DbSession

from capki.db.models.rbac import UserRole
from capki.db.models.users import User


@dataclass(frozen=True)
class AuthContext:
    user_id: int
    username: str
    role: str | None
    permissions: frozenset[str]
    auth_method: str  # "session" | "token"
    token_id: int | None = None


def load_auth_context_for_user(
    db: DbSession, user: User, auth_method: str, token_id: int | None = None
) -> AuthContext:
    """Resolves permissions from the role_permissions table (not a hardcoded
    per-role branch), so a future permissions editor needs no code change
    here — only new rows. A token-authenticated request runs with exactly
    the owning user's role/permissions (no separate per-token scoping)."""
    user_role = db.query(UserRole).filter(UserRole.user_id == user.id).first()
    if user_role is None:
        return AuthContext(
            user_id=user.id,
            username=user.username,
            role=None,
            permissions=frozenset(),
            auth_method=auth_method,
            token_id=token_id,
        )

    role = user_role.role
    permissions = frozenset(rp.permission.code for rp in role.role_permissions)
    return AuthContext(
        user_id=user.id,
        username=user.username,
        role=role.name,
        permissions=permissions,
        auth_method=auth_method,
        token_id=token_id,
    )
