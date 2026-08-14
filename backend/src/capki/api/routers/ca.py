from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from capki.api.deps import require_permission
from capki.core.crypto.key_vault import key_vault
from capki.core.rbac.context import AuthContext
from capki.core.rbac.permissions import CA_LOCK_ROOT, CA_MANAGE, CA_READ, CA_UNLOCK_ROOT
from capki.db.models.audit import ActorType
from capki.db.models.ca import CertificateAuthority
from capki.db.models.certificates import CrlIssuance
from capki.db.session import get_db
from capki.services import ca_service
from capki.services.audit_service import log_action

router = APIRouter(prefix="/ca", tags=["ca"])


class CaSummary(BaseModel):
    id: int
    type: str
    name: str
    subject_dn: str
    status: str
    not_before: str | None
    not_after: str | None

    @classmethod
    def from_model(cls, ca: CertificateAuthority) -> "CaSummary":
        return cls(
            id=ca.id,
            type=ca.type.value,
            name=ca.name,
            subject_dn=ca.subject_dn,
            status=ca.status.value,
            not_before=ca.not_before.isoformat() if ca.not_before else None,
            not_after=ca.not_after.isoformat() if ca.not_after else None,
        )


class InitRootRequest(BaseModel):
    common_name: str
    organization_name: str | None = None
    passphrase: str = Field(min_length=12)


class InitIntermediateRequest(BaseModel):
    common_name: str
    organization_name: str | None = None


class UnlockRootRequest(BaseModel):
    passphrase: str


class RootStatusResponse(BaseModel):
    initialized: bool
    unlocked: bool


_ERROR_STATUS = {
    "root_locked": status.HTTP_423_LOCKED,
}


def _raise_for(exc: ca_service.CaError) -> None:
    raise HTTPException(status_code=_ERROR_STATUS.get(str(exc), status.HTTP_409_CONFLICT), detail=str(exc))


@router.get("", response_model=list[CaSummary])
def list_cas(db: Session = Depends(get_db), _actor: AuthContext = Depends(require_permission(CA_READ))):
    cas = db.query(CertificateAuthority).order_by(CertificateAuthority.id).all()
    return [CaSummary.from_model(ca) for ca in cas]


@router.get("/root/status", response_model=RootStatusResponse)
def root_status(
    db: Session = Depends(get_db), _actor: AuthContext = Depends(require_permission(CA_READ))
):
    root = ca_service.get_root(db)
    return RootStatusResponse(initialized=root is not None, unlocked=key_vault.is_root_unlocked())


@router.post("/root/init", response_model=CaSummary, status_code=status.HTTP_201_CREATED)
def init_root(
    payload: InitRootRequest,
    db: Session = Depends(get_db),
    actor: AuthContext = Depends(require_permission(CA_MANAGE)),
):
    try:
        ca = ca_service.init_root(
            db,
            common_name=payload.common_name,
            organization_name=payload.organization_name,
            passphrase=payload.passphrase,
            actor_user_id=actor.user_id,
        )
    except ca_service.CaError as exc:
        _raise_for(exc)
    return CaSummary.from_model(ca)


@router.post("/intermediate/init", response_model=CaSummary, status_code=status.HTTP_201_CREATED)
def init_intermediate(
    payload: InitIntermediateRequest,
    db: Session = Depends(get_db),
    actor: AuthContext = Depends(require_permission(CA_MANAGE)),
):
    try:
        ca = ca_service.init_intermediate(
            db,
            common_name=payload.common_name,
            organization_name=payload.organization_name,
            actor_user_id=actor.user_id,
        )
    except ca_service.CaError as exc:
        _raise_for(exc)
    return CaSummary.from_model(ca)


@router.post("/root/unlock", response_model=RootStatusResponse)
def unlock_root(
    payload: UnlockRootRequest,
    db: Session = Depends(get_db),
    actor: AuthContext = Depends(require_permission(CA_UNLOCK_ROOT)),
):
    ok = key_vault.unlock_root(db, payload.passphrase)
    log_action(db, actor_type=ActorType.USER, actor_user_id=actor.user_id, action="ca.root_unlock", success=ok)
    if not ok:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid_passphrase")
    return RootStatusResponse(initialized=True, unlocked=True)


@router.post("/root/lock", response_model=RootStatusResponse)
def lock_root(
    db: Session = Depends(get_db), actor: AuthContext = Depends(require_permission(CA_LOCK_ROOT))
):
    key_vault.lock_root()
    log_action(db, actor_type=ActorType.USER, actor_user_id=actor.user_id, action="ca.root_lock")
    return RootStatusResponse(initialized=True, unlocked=False)


@router.get("/{ca_id}/certificate.pem")
def get_ca_certificate(ca_id: int, db: Session = Depends(get_db)) -> PlainTextResponse:
    ca = db.get(CertificateAuthority, ca_id)
    if ca is None or ca.certificate_pem is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return PlainTextResponse(ca.certificate_pem, media_type="application/x-pem-file")


@router.get("/{ca_id}/crl")
def get_ca_crl(ca_id: int, db: Session = Depends(get_db)) -> PlainTextResponse:
    latest = (
        db.query(CrlIssuance)
        .filter(CrlIssuance.ca_id == ca_id)
        .order_by(CrlIssuance.crl_number.desc())
        .first()
    )
    if latest is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return PlainTextResponse(latest.crl_pem, media_type="application/pkix-crl")
