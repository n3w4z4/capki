from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from capki.api.deps import require_permission
from capki.core.rbac.context import AuthContext
from capki.core.rbac.permissions import USER_MANAGE, USER_READ
from capki.db.models.users import User
from capki.db.session import get_db
from capki.services import user_service

router = APIRouter(prefix="/users", tags=["users"])


class UserSummary(BaseModel):
    id: int
    username: str
    email: str
    auth_source: str
    role: str | None
    is_active: bool

    @classmethod
    def from_model(cls, user: User, role_name: str | None) -> "UserSummary":
        return cls(
            id=user.id,
            username=user.username,
            email=user.email,
            auth_source=user.auth_source.value,
            role=role_name,
            is_active=user.is_active,
        )


class RoleSummary(BaseModel):
    name: str
    description: str | None


class CreateUserRequest(BaseModel):
    username: str
    email: str
    password: str
    role: str


class UpdateUserRequest(BaseModel):
    role: str | None = None
    is_active: bool | None = None
    new_password: str | None = None


_ERROR_STATUS = {
    "not_found": status.HTTP_404_NOT_FOUND,
    "unknown_role": status.HTTP_400_BAD_REQUEST,
    "username_or_email_taken": status.HTTP_409_CONFLICT,
    "cannot_deactivate_self": status.HTTP_400_BAD_REQUEST,
    "not_a_local_user": status.HTTP_400_BAD_REQUEST,
}


def _raise_for(exc: user_service.UserManagementError) -> None:
    raise HTTPException(status_code=_ERROR_STATUS.get(str(exc), status.HTTP_400_BAD_REQUEST), detail=str(exc))


@router.get("/roles", response_model=list[RoleSummary])
def list_roles(
    db: Session = Depends(get_db), _actor: AuthContext = Depends(require_permission(USER_READ))
):
    return [RoleSummary(name=r.name, description=r.description) for r in user_service.list_roles(db)]


@router.get("", response_model=list[UserSummary])
def list_users(
    db: Session = Depends(get_db), _actor: AuthContext = Depends(require_permission(USER_READ))
):
    return [UserSummary.from_model(u, role) for u, role in user_service.list_users(db)]


@router.post("", response_model=UserSummary, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: CreateUserRequest,
    db: Session = Depends(get_db),
    actor: AuthContext = Depends(require_permission(USER_MANAGE)),
):
    try:
        user = user_service.create_local_user(
            db,
            username=payload.username,
            email=payload.email,
            password=payload.password,
            role_name=payload.role,
            actor_user_id=actor.user_id,
        )
    except user_service.UserManagementError as exc:
        _raise_for(exc)
    return UserSummary.from_model(user, payload.role)


@router.patch("/{user_id}", response_model=UserSummary)
def update_user(
    user_id: int,
    payload: UpdateUserRequest,
    db: Session = Depends(get_db),
    actor: AuthContext = Depends(require_permission(USER_MANAGE)),
):
    try:
        user = user_service.update_user(
            db,
            user_id=user_id,
            actor_user_id=actor.user_id,
            role_name=payload.role,
            is_active=payload.is_active,
            new_password=payload.new_password,
        )
    except user_service.UserManagementError as exc:
        _raise_for(exc)
    role_name = user_service.get_role_name(db, user.id)
    return UserSummary.from_model(user, role_name)


@router.delete("/{user_id}", response_model=UserSummary)
def deactivate_user(
    user_id: int,
    db: Session = Depends(get_db),
    actor: AuthContext = Depends(require_permission(USER_MANAGE)),
):
    try:
        user = user_service.deactivate_user(db, user_id=user_id, actor_user_id=actor.user_id)
    except user_service.UserManagementError as exc:
        _raise_for(exc)
    role_name = user_service.get_role_name(db, user.id)
    return UserSummary.from_model(user, role_name)
