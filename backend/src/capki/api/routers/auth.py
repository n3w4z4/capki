from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from capki.api.deps import get_current_actor
from capki.config import settings
from capki.core.rbac.context import AuthContext, load_auth_context_for_user
from capki.core.security.sessions import create_session, revoke_session
from capki.db.models.audit import ActorType
from capki.db.models.users import User
from capki.db.session import get_db
from capki.services.audit_service import log_action
from capki.services.user_service import authenticate_local

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


class MeResponse(BaseModel):
    username: str
    role: str | None
    permissions: list[str]
    auth_method: str


def _set_session_cookie(response: Response, raw_token: str) -> None:
    response.set_cookie(
        key=settings.session_cookie_name,
        value=raw_token,
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite="lax",
        max_age=settings.session_idle_timeout_minutes * 60,
        path="/",
    )


@router.post("/login", response_model=MeResponse)
def login(payload: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    user = authenticate_local(db, payload.username, payload.password)
    if user is None:
        log_action(
            db,
            actor_type=ActorType.SYSTEM,
            action="auth.login_failed",
            target_type="user",
            target_id=payload.username,
            ip_address=request.client.host if request.client else None,
            success=False,
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid_credentials")

    raw_token, _expires_at = create_session(
        db,
        user_id=user.id,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    _set_session_cookie(response, raw_token)

    context = load_auth_context_for_user(db, user, auth_method="session")
    log_action(
        db,
        actor_type=ActorType.USER,
        actor_user_id=user.id,
        action="auth.login",
        target_type="user",
        target_id=str(user.id),
        ip_address=request.client.host if request.client else None,
    )
    return MeResponse(
        username=context.username,
        role=context.role,
        permissions=sorted(context.permissions),
        auth_method=context.auth_method,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, response: Response, db: Session = Depends(get_db)) -> None:
    raw_token = request.cookies.get(settings.session_cookie_name)
    if raw_token:
        revoke_session(db, raw_token)
    response.delete_cookie(settings.session_cookie_name, path="/")


@router.get("/me", response_model=MeResponse)
def me(actor: AuthContext = Depends(get_current_actor)):
    return MeResponse(
        username=actor.username,
        role=actor.role,
        permissions=sorted(actor.permissions),
        auth_method=actor.auth_method,
    )
