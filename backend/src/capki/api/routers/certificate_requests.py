from cryptography import x509
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from capki.api.deps import require_permission
from capki.core.crypto import ca_engine
from capki.core.rbac.context import AuthContext
from capki.core.rbac.permissions import CERT_APPROVE, CERT_READ, CERT_REQUEST
from capki.db.models.cert_requests import CertificateRequest
from capki.db.models.users import User
from capki.db.session import get_db
from capki.services import cert_request_service, cert_service

router = APIRouter(prefix="/certificate-requests", tags=["certificate-requests"])


class CertRequestSummary(BaseModel):
    id: int
    subject_dn: str
    profile_code: str
    status: str
    requested_by_user_id: int
    requested_by_username: str | None
    created_at: str
    reviewed_at: str | None
    rejection_reason: str | None
    certificate_id: int | None

    @classmethod
    def from_model(cls, req: CertificateRequest, requested_by_username: str | None = None) -> "CertRequestSummary":
        try:
            csr = x509.load_pem_x509_csr(req.csr_pem.encode("ascii"))
            subject_dn = ca_engine.name_to_string(csr.subject)
        except ValueError:
            subject_dn = "(unparseable CSR)"
        return cls(
            id=req.id,
            subject_dn=subject_dn,
            profile_code=req.profile_code,
            status=req.status.value,
            requested_by_user_id=req.requested_by_user_id,
            requested_by_username=requested_by_username,
            created_at=req.created_at.isoformat(),
            reviewed_at=req.reviewed_at.isoformat() if req.reviewed_at else None,
            rejection_reason=req.rejection_reason,
            certificate_id=req.certificate_id,
        )


def _summaries_with_usernames(db: Session, requests: list[CertificateRequest]) -> list[CertRequestSummary]:
    user_ids = {r.requested_by_user_id for r in requests}
    usernames = {u.id: u.username for u in db.query(User).filter(User.id.in_(user_ids)).all()} if user_ids else {}
    return [CertRequestSummary.from_model(r, usernames.get(r.requested_by_user_id)) for r in requests]


class SubmitRequestPayload(BaseModel):
    csr_pem: str
    profile_code: str


class RejectRequestPayload(BaseModel):
    reason: str


class ApproveRequestPayload(BaseModel):
    validity_days: int | None = None


_ERROR_STATUS = {
    "not_found": status.HTTP_404_NOT_FOUND,
    "not_pending": status.HTTP_409_CONFLICT,
    "not_approved": status.HTTP_409_CONFLICT,
    "forbidden": status.HTTP_403_FORBIDDEN,
    "unknown_profile": status.HTTP_400_BAD_REQUEST,
    "invalid_csr": status.HTTP_400_BAD_REQUEST,
    "invalid_csr_signature": status.HTTP_400_BAD_REQUEST,
    "weak_rsa_key": status.HTTP_400_BAD_REQUEST,
    "unsupported_ec_curve": status.HTTP_400_BAD_REQUEST,
    "unsupported_key_type": status.HTTP_400_BAD_REQUEST,
    "email_required": status.HTTP_400_BAD_REQUEST,
}


def _raise_for(exc: Exception) -> None:
    code = str(exc).split(":")[0]
    raise HTTPException(status_code=_ERROR_STATUS.get(code, status.HTTP_400_BAD_REQUEST), detail=str(exc))


@router.post("", response_model=CertRequestSummary, status_code=status.HTTP_201_CREATED)
def submit_request(
    payload: SubmitRequestPayload,
    db: Session = Depends(get_db),
    actor: AuthContext = Depends(require_permission(CERT_REQUEST)),
):
    try:
        req = cert_request_service.submit_request(
            db,
            csr_pem=payload.csr_pem,
            profile_code=payload.profile_code,
            requested_by_user_id=actor.user_id,
        )
    except cert_service.CertIssuanceError as exc:
        _raise_for(exc)
    return _summaries_with_usernames(db, [req])[0]


@router.get("/mine", response_model=list[CertRequestSummary])
def list_mine(
    db: Session = Depends(get_db), actor: AuthContext = Depends(require_permission(CERT_REQUEST))
):
    return _summaries_with_usernames(db, cert_request_service.list_own_requests(db, actor.user_id))


@router.get("/pending", response_model=list[CertRequestSummary])
def list_pending(
    db: Session = Depends(get_db), _actor: AuthContext = Depends(require_permission(CERT_APPROVE))
):
    return _summaries_with_usernames(db, cert_request_service.list_pending_requests(db))


@router.post("/{request_id}/approve", response_model=CertRequestSummary)
def approve(
    request_id: int,
    payload: ApproveRequestPayload,
    db: Session = Depends(get_db),
    actor: AuthContext = Depends(require_permission(CERT_APPROVE)),
):
    try:
        req = cert_request_service.approve_request(
            db, request_id=request_id, reviewer_user_id=actor.user_id, validity_days=payload.validity_days
        )
    except (cert_request_service.CertRequestError, cert_service.CertIssuanceError) as exc:
        _raise_for(exc)
    return _summaries_with_usernames(db, [req])[0]


@router.post("/{request_id}/reject", response_model=CertRequestSummary)
def reject(
    request_id: int,
    payload: RejectRequestPayload,
    db: Session = Depends(get_db),
    actor: AuthContext = Depends(require_permission(CERT_APPROVE)),
):
    try:
        req = cert_request_service.reject_request(
            db, request_id=request_id, reviewer_user_id=actor.user_id, reason=payload.reason
        )
    except cert_request_service.CertRequestError as exc:
        _raise_for(exc)
    return _summaries_with_usernames(db, [req])[0]


@router.get("/{request_id}/certificate.pem")
def get_request_certificate_pem(
    request_id: int,
    db: Session = Depends(get_db),
    actor: AuthContext = Depends(require_permission(CERT_REQUEST)),
) -> PlainTextResponse:
    try:
        cert = cert_request_service.get_owned_certificate(
            db, request_id=request_id, actor_user_id=actor.user_id, is_privileged=CERT_READ in actor.permissions
        )
    except cert_request_service.CertRequestError as exc:
        _raise_for(exc)
    return PlainTextResponse(cert.certificate_pem, media_type="application/x-pem-file")


@router.get("/{request_id}/chain.pem")
def get_request_chain_pem(
    request_id: int,
    db: Session = Depends(get_db),
    actor: AuthContext = Depends(require_permission(CERT_REQUEST)),
) -> PlainTextResponse:
    try:
        cert = cert_request_service.get_owned_certificate(
            db, request_id=request_id, actor_user_id=actor.user_id, is_privileged=CERT_READ in actor.permissions
        )
    except cert_request_service.CertRequestError as exc:
        _raise_for(exc)
    return PlainTextResponse(cert_service.build_chain_pem(db, cert), media_type="application/x-pem-file")
