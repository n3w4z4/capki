import logging

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from capki.config import settings
from capki.core.rbac.permissions import ROLE_ADMIN
from capki.core.security.passwords import hash_password, verify_password
from capki.core.security.sessions import revoke_all_sessions_for_user
from capki.db.models.audit import ActorType
from capki.db.models.rbac import Role, UserRole
from capki.db.models.users import AuthSource, User
from capki.services.audit_service import log_action

logger = logging.getLogger(__name__)


def authenticate_local(db: Session, username: str, password: str) -> User | None:
    user = db.query(User).filter(User.username == username, User.is_active.is_(True)).first()
    if user is None or user.auth_source != AuthSource.LOCAL or user.password_hash is None:
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user


def _resolve_initial_admin_password() -> str | None:
    if settings.initial_admin_password_file is not None and settings.initial_admin_password_file.exists():
        return settings.initial_admin_password_file.read_text().strip()
    return settings.initial_admin_password


def bootstrap_initial_admin(db: Session) -> None:
    """Idempotent: safe to call on every startup. Creates the first Admin
    user from INITIAL_ADMIN_USERNAME/PASSWORD(_FILE) if configured and no
    such user already exists."""
    if not settings.initial_admin_username:
        return

    existing = db.query(User).filter(User.username == settings.initial_admin_username).first()
    if existing is not None:
        return

    password = _resolve_initial_admin_password()
    if not password:
        logger.warning(
            "INITIAL_ADMIN_USERNAME is set but no INITIAL_ADMIN_PASSWORD/_FILE was provided — "
            "skipping initial admin bootstrap."
        )
        return

    admin_role = db.query(Role).filter(Role.name == ROLE_ADMIN).first()
    if admin_role is None:
        logger.error("Cannot bootstrap initial admin: 'admin' role not found — did migrations run?")
        return

    user = User(
        username=settings.initial_admin_username,
        email=f"{settings.initial_admin_username}@{settings.app_hostname}",
        password_hash=hash_password(password),
        auth_source=AuthSource.LOCAL,
        is_active=True,
    )
    db.add(user)
    db.flush()
    db.add(UserRole(user_id=user.id, role_id=admin_role.id))
    db.commit()

    logger.info("Bootstrapped initial admin user %r", user.username)
    log_action(
        db,
        actor_type=ActorType.SYSTEM,
        action="user.bootstrap_admin",
        target_type="user",
        target_id=str(user.id),
    )


class SamlProvisioningError(Exception):
    """Raised when a SAML response can't be turned into a usable local
    account (e.g. no App Role claim maps to a known role)."""


def _find_or_create_saml_user(db: Session, *, name_id: str, email: str) -> User:
    user = db.query(User).filter(User.saml_name_id == name_id).first()
    if user is not None:
        return user

    base_username = email.split("@")[0]
    for attempt in range(5):
        username = base_username if attempt == 0 else f"{base_username}{attempt}"
        user = User(
            username=username,
            email=email,
            auth_source=AuthSource.SAML,
            saml_name_id=name_id,
            is_active=True,
        )
        db.add(user)
        try:
            db.flush()
        except IntegrityError:
            db.rollback()
            continue
        return user

    raise SamlProvisioningError("username_allocation_failed")


def sync_saml_user(db: Session, *, name_id: str, email: str, role_name: str) -> User:
    """Finds or creates the local account for a successful SAML login, and
    keeps its role in sync with the Entra App Role claim on every login."""
    role = db.query(Role).filter(Role.name == role_name).first()
    if role is None:
        raise SamlProvisioningError(f"unknown_role:{role_name}")

    user = _find_or_create_saml_user(db, name_id=name_id, email=email)

    user_role = db.query(UserRole).filter(UserRole.user_id == user.id).first()
    if user_role is None:
        db.add(UserRole(user_id=user.id, role_id=role.id))
    elif user_role.role_id != role.id:
        user_role.role_id = role.id

    db.commit()
    return user


class UserManagementError(Exception):
    """Raised for user CRUD preconditions the API layer maps to HTTP status
    codes (e.g. not_found -> 404, cannot_deactivate_self -> 400)."""


def list_roles(db: Session) -> list[Role]:
    return db.query(Role).order_by(Role.name).all()


def get_role_name(db: Session, user_id: int) -> str | None:
    ur = db.query(UserRole).filter(UserRole.user_id == user_id).first()
    return ur.role.name if ur else None


def list_users(db: Session) -> list[tuple[User, str | None]]:
    users = db.query(User).order_by(User.id).all()
    role_by_user_id = {ur.user_id: ur.role.name for ur in db.query(UserRole).all()}
    return [(u, role_by_user_id.get(u.id)) for u in users]


def create_local_user(
    db: Session, *, username: str, email: str, password: str, role_name: str, actor_user_id: int
) -> User:
    role = db.query(Role).filter(Role.name == role_name).first()
    if role is None:
        raise UserManagementError("unknown_role")
    if db.query(User).filter((User.username == username) | (User.email == email)).first() is not None:
        raise UserManagementError("username_or_email_taken")

    user = User(
        username=username,
        email=email,
        password_hash=hash_password(password),
        auth_source=AuthSource.LOCAL,
        is_active=True,
    )
    db.add(user)
    db.flush()
    db.add(UserRole(user_id=user.id, role_id=role.id))
    db.commit()

    log_action(
        db,
        actor_type=ActorType.USER,
        actor_user_id=actor_user_id,
        action="user.create",
        target_type="user",
        target_id=str(user.id),
        detail={"role": role_name},
    )
    return user


def update_user(
    db: Session,
    *,
    user_id: int,
    actor_user_id: int,
    role_name: str | None = None,
    is_active: bool | None = None,
    new_password: str | None = None,
    telegram_chat_id: str | None = None,
) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise UserManagementError("not_found")
    if is_active is False and user_id == actor_user_id:
        raise UserManagementError("cannot_deactivate_self")

    if role_name is not None:
        role = db.query(Role).filter(Role.name == role_name).first()
        if role is None:
            raise UserManagementError("unknown_role")
        user_role = db.query(UserRole).filter(UserRole.user_id == user.id).first()
        if user_role is None:
            db.add(UserRole(user_id=user.id, role_id=role.id))
        else:
            user_role.role_id = role.id

    if is_active is not None:
        user.is_active = is_active
        if not is_active:
            revoke_all_sessions_for_user(db, user.id)

    if new_password is not None:
        if user.auth_source != AuthSource.LOCAL:
            raise UserManagementError("not_a_local_user")
        user.password_hash = hash_password(new_password)

    if telegram_chat_id is not None:
        user.telegram_chat_id = telegram_chat_id or None

    db.commit()

    detail: dict[str, object] = {}
    if role_name is not None:
        detail["role"] = role_name
    if is_active is not None:
        detail["is_active"] = is_active
    if new_password is not None:
        detail["password_reset"] = True
    if telegram_chat_id is not None:
        detail["telegram_chat_id_changed"] = True

    log_action(
        db,
        actor_type=ActorType.USER,
        actor_user_id=actor_user_id,
        action="user.update",
        target_type="user",
        target_id=str(user.id),
        detail=detail or None,
    )
    return user


def deactivate_user(db: Session, *, user_id: int, actor_user_id: int) -> User:
    return update_user(db, user_id=user_id, actor_user_id=actor_user_id, is_active=False)
