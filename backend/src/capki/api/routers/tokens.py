import datetime as dt

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from capki.api.deps import require_permission
from capki.core.rbac.context import AuthContext
from capki.core.rbac.permissions import TOKEN_MANAGE_ALL, TOKEN_MANAGE_OWN, TOKEN_READ_OWN
from capki.db.models.tokens import ApiToken
from capki.db.session import get_db
from capki.services import token_service

router = APIRouter(prefix="/tokens", tags=["tokens"])


class TokenSummary(BaseModel):
    id: int
    name: str
    token_prefix: str
    created_at: str
    expires_at: str | None
    last_used_at: str | None
    revoked_at: str | None

    @classmethod
    def from_model(cls, token: ApiToken) -> "TokenSummary":
        return cls(
            id=token.id,
            name=token.name,
            token_prefix=token.token_prefix,
            created_at=token.created_at.isoformat(),
            expires_at=token.expires_at.isoformat() if token.expires_at else None,
            last_used_at=token.last_used_at.isoformat() if token.last_used_at else None,
            revoked_at=token.revoked_at.isoformat() if token.revoked_at else None,
        )


class CreateTokenRequest(BaseModel):
    name: str
    expires_at: dt.datetime | None = None


class CreateTokenResponse(TokenSummary):
    token: str


@router.get("", response_model=list[TokenSummary])
def list_own_tokens(
    db: Session = Depends(get_db), actor: AuthContext = Depends(require_permission(TOKEN_READ_OWN))
):
    tokens = (
        db.query(ApiToken).filter(ApiToken.user_id == actor.user_id).order_by(ApiToken.id.desc()).all()
    )
    return [TokenSummary.from_model(t) for t in tokens]


@router.post("", response_model=CreateTokenResponse, status_code=status.HTTP_201_CREATED)
def create_token(
    payload: CreateTokenRequest,
    db: Session = Depends(get_db),
    actor: AuthContext = Depends(require_permission(TOKEN_MANAGE_OWN)),
):
    token, raw_token = token_service.create_token(
        db, user_id=actor.user_id, name=payload.name, expires_at=payload.expires_at
    )
    summary = TokenSummary.from_model(token)
    return CreateTokenResponse(**summary.model_dump(), token=raw_token)


@router.delete("/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_token(
    token_id: int,
    db: Session = Depends(get_db),
    actor: AuthContext = Depends(require_permission(TOKEN_MANAGE_OWN)),
) -> None:
    try:
        token_service.revoke_token(
            db,
            token_id=token_id,
            actor_user_id=actor.user_id,
            is_admin=TOKEN_MANAGE_ALL in actor.permissions,
        )
    except token_service.TokenError as exc:
        code = status.HTTP_404_NOT_FOUND if str(exc) == "not_found" else status.HTTP_403_FORBIDDEN
        raise HTTPException(status_code=code, detail=str(exc)) from exc
