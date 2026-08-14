from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import PlainTextResponse, RedirectResponse
from sqlalchemy.orm import Session

from capki.config import settings as app_settings
from capki.core.rbac.context import load_auth_context_for_user
from capki.core.security.sessions import create_session
from capki.db.models.audit import ActorType
from capki.db.session import get_db
from capki.saml import sp
from capki.saml.attribute_map import resolve_email, resolve_role
from capki.services import settings_service, user_service
from capki.services.audit_service import log_action

router = APIRouter(prefix="/auth/saml", tags=["saml"])


def _set_session_cookie(response: Response, raw_token: str) -> None:
    response.set_cookie(
        key=app_settings.session_cookie_name,
        value=raw_token,
        httponly=True,
        secure=app_settings.session_cookie_secure,
        samesite="lax",
        max_age=app_settings.session_idle_timeout_minutes * 60,
        path="/",
    )


@router.get("/status")
def saml_status(db: Session = Depends(get_db)) -> dict[str, bool]:
    """Public: lets the (pre-auth) login page know whether to show a 'Sign
    in with SSO' option, without exposing any IdP configuration details."""
    return {"enabled": settings_service.get_saml_config(db).enabled}


@router.get("/metadata")
def metadata(db: Session = Depends(get_db)) -> PlainTextResponse:
    config = settings_service.get_saml_config(db)
    xml, errors = sp.build_sp_metadata(config)
    if errors:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"invalid_sp_settings:{errors}"
        )
    return PlainTextResponse(xml, media_type="application/xml")


@router.get("/login")
async def login(request: Request, db: Session = Depends(get_db)) -> RedirectResponse:
    config = settings_service.get_saml_config(db)
    if not config.enabled:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="saml_not_configured")

    request_data = await sp.build_request_data(request)
    auth = sp.make_auth(request_data, config)
    return RedirectResponse(auth.login(), status_code=status.HTTP_302_FOUND)


@router.post("/acs")
async def acs(request: Request, db: Session = Depends(get_db)) -> RedirectResponse:
    config = settings_service.get_saml_config(db)
    if not config.enabled:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="saml_not_configured")

    request_data = await sp.build_request_data(request)
    auth = sp.make_auth(request_data, config)
    try:
        auth.process_response()
    except Exception as exc:
        # A real IdP always sends well-formed XML; a parse failure here means
        # malformed, truncated, or tampered input — reject cleanly rather
        # than letting it surface as an unhandled 500.
        log_action(
            db,
            actor_type=ActorType.SYSTEM,
            action="auth.saml_login_failed",
            detail={"reason": f"unparseable_response:{exc}"},
            success=False,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="malformed_saml_response"
        ) from exc

    errors = auth.get_errors()
    if errors or not auth.is_authenticated():
        log_action(
            db,
            actor_type=ActorType.SYSTEM,
            action="auth.saml_login_failed",
            detail={"errors": errors, "reason": auth.get_last_error_reason()},
            success=False,
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="saml_authentication_failed")

    name_id = auth.get_nameid()
    attributes = auth.get_attributes()
    role_name = resolve_role(attributes, config.group_role_map)
    if role_name is None:
        log_action(
            db,
            actor_type=ActorType.SYSTEM,
            action="auth.saml_login_failed",
            target_id=name_id,
            detail={"reason": "no_role_claim_mapped"},
            success=False,
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="no_role_assigned")

    email = resolve_email(attributes, name_id)
    try:
        user = user_service.sync_saml_user(db, name_id=name_id, email=email, role_name=role_name)
    except user_service.SamlProvisioningError as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc

    raw_token, _expires_at = create_session(
        db,
        user_id=user.id,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )

    context = load_auth_context_for_user(db, user, auth_method="session")
    log_action(
        db,
        actor_type=ActorType.USER,
        actor_user_id=user.id,
        action="auth.saml_login",
        target_type="user",
        target_id=str(user.id),
        detail={"role": context.role},
    )

    redirect = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    _set_session_cookie(redirect, raw_token)
    return redirect
