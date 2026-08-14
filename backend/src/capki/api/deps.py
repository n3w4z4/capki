from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from capki.config import settings
from capki.core.rbac.context import AuthContext, load_auth_context_for_user
from capki.core.security.sessions import get_valid_session
from capki.db.models.users import User
from capki.db.session import get_db
from capki.services.token_service import authenticate_token


def get_current_actor(request: Request, db: Session = Depends(get_db)) -> AuthContext:
    auth_header = request.headers.get("authorization")
    if auth_header and auth_header.lower().startswith("bearer "):
        raw_token = auth_header[len("bearer ") :].strip()
        result = authenticate_token(db, raw_token)
        if result is not None:
            user, token = result
            return load_auth_context_for_user(db, user, auth_method="token", token_id=token.id)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid_token")

    session_cookie = request.cookies.get(settings.session_cookie_name)
    if session_cookie:
        session = get_valid_session(db, session_cookie)
        if session is not None:
            user = db.get(User, session.user_id)
            if user is not None and user.is_active:
                return load_auth_context_for_user(db, user, auth_method="session")

    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="not_authenticated")


def require_permission(code: str):
    def _dep(actor: AuthContext = Depends(get_current_actor)) -> AuthContext:
        if code not in actor.permissions:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="insufficient_permission")
        return actor

    return _dep
