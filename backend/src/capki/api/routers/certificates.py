from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from capki.api.deps import require_permission
from capki.core.rbac.context import AuthContext
from capki.core.rbac.permissions import CERT_ISSUE, CERT_READ, CERT_REVOKE
from capki.db.base import utcnow
from capki.db.models.certificates import Certificate, IssuedVia
from capki.db.session import get_db
from capki.services import cert_service, revocation_service

router = APIRouter(prefix="/certificates", tags=["certificates"])


class CertificateSummary(BaseModel):
    id: int
    serial_hex: str
    profile_code: str
    subject_dn: str
    sans: list[str]
    status: str
    not_before: str
    not_after: str
    issued_via: str
    requested_by_user_id: int | None

    @classmethod
    def from_model(cls, cert: Certificate) -> "CertificateSummary":
        return cls(
            id=cert.id,
            serial_hex=cert.serial_hex,
            profile_code=cert.profile_code,
            subject_dn=cert.subject_dn,
            sans=cert.sans,
            status=cert.status.value,
            not_before=cert.not_before.isoformat(),
            not_after=cert.not_after.isoformat(),
            issued_via=cert.issued_via.value,
            requested_by_user_id=cert.requested_by_user_id,
        )


class IssueCertificateRequest(BaseModel):
    csr_pem: str
    profile_code: str
    validity_days: int | None = None


class IssueCertificateResponse(CertificateSummary):
    certificate_pem: str
    chain_pem: str


class RevokeCertificateRequest(BaseModel):
    reason: str = "unspecified"


_ERROR_STATUS = {
    "intermediate_not_ready": status.HTTP_503_SERVICE_UNAVAILABLE,
    "unknown_profile": status.HTTP_400_BAD_REQUEST,
    "invalid_csr": status.HTTP_400_BAD_REQUEST,
    "invalid_csr_signature": status.HTTP_400_BAD_REQUEST,
    "weak_rsa_key": status.HTTP_400_BAD_REQUEST,
    "unsupported_ec_curve": status.HTTP_400_BAD_REQUEST,
    "unsupported_key_type": status.HTTP_400_BAD_REQUEST,
    "email_required": status.HTTP_400_BAD_REQUEST,
    "validity_exceeds_profile_max": status.HTTP_400_BAD_REQUEST,
    "certificate_not_found": status.HTTP_404_NOT_FOUND,
    "already_revoked": status.HTTP_409_CONFLICT,
    "invalid_reason": status.HTTP_400_BAD_REQUEST,
}


@router.get("", response_model=list[CertificateSummary])
def list_certificates(
    q: str | None = Query(default=None, description="Case-insensitive substring match on subject DN"),
    status_filter: str | None = Query(default=None, alias="status"),
    profile_code: str | None = Query(default=None),
    issued_via: str | None = Query(default=None),
    valid: bool | None = Query(
        default=None, description="Filter by expiration: true = not_after in the future, false = expired"
    ),
    limit: int = Query(default=50, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _actor: AuthContext = Depends(require_permission(CERT_READ)),
):
    query = db.query(Certificate)
    if q:
        query = query.filter(Certificate.subject_dn.ilike(f"%{q}%"))
    if status_filter:
        query = query.filter(Certificate.status == status_filter)
    if profile_code:
        query = query.filter(Certificate.profile_code == profile_code)
    if issued_via:
        query = query.filter(Certificate.issued_via == issued_via)
    if valid is not None:
        now = utcnow()
        query = query.filter(Certificate.not_after > now if valid else Certificate.not_after <= now)
    certs = query.order_by(Certificate.id.desc()).offset(offset).limit(limit).all()
    return [CertificateSummary.from_model(c) for c in certs]


@router.get("/{cert_id}", response_model=CertificateSummary)
def get_certificate(
    cert_id: int,
    db: Session = Depends(get_db),
    _actor: AuthContext = Depends(require_permission(CERT_READ)),
):
    cert = db.get(Certificate, cert_id)
    if cert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return CertificateSummary.from_model(cert)


@router.get("/{cert_id}/pem")
def get_certificate_pem(
    cert_id: int,
    db: Session = Depends(get_db),
    _actor: AuthContext = Depends(require_permission(CERT_READ)),
) -> PlainTextResponse:
    cert = db.get(Certificate, cert_id)
    if cert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return PlainTextResponse(cert.certificate_pem, media_type="application/x-pem-file")


@router.get("/{cert_id}/chain.pem")
def get_certificate_chain_pem(
    cert_id: int,
    db: Session = Depends(get_db),
    _actor: AuthContext = Depends(require_permission(CERT_READ)),
) -> PlainTextResponse:
    cert = db.get(Certificate, cert_id)
    if cert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return PlainTextResponse(cert_service.build_chain_pem(db, cert), media_type="application/x-pem-file")


@router.post("", response_model=IssueCertificateResponse, status_code=status.HTTP_201_CREATED)
def issue_certificate(
    payload: IssueCertificateRequest,
    db: Session = Depends(get_db),
    actor: AuthContext = Depends(require_permission(CERT_ISSUE)),
):
    try:
        cert = cert_service.issue_certificate(
            db,
            csr_pem=payload.csr_pem,
            profile_code=payload.profile_code,
            requested_by_user_id=actor.user_id,
            issued_via=IssuedVia.UI if actor.auth_method == "session" else IssuedVia.API,
            api_token_id=actor.token_id,
            validity_days=payload.validity_days,
        )
    except cert_service.CertIssuanceError as exc:
        raise HTTPException(
            status_code=_ERROR_STATUS.get(str(exc), status.HTTP_400_BAD_REQUEST), detail=str(exc)
        ) from exc

    summary = CertificateSummary.from_model(cert)
    return IssueCertificateResponse(
        **summary.model_dump(), certificate_pem=cert.certificate_pem, chain_pem=cert_service.build_chain_pem(db, cert)
    )


@router.post("/{cert_id}/revoke", response_model=CertificateSummary)
def revoke_certificate(
    cert_id: int,
    payload: RevokeCertificateRequest,
    db: Session = Depends(get_db),
    actor: AuthContext = Depends(require_permission(CERT_REVOKE)),
):
    try:
        cert = revocation_service.revoke_certificate(
            db, cert_id=cert_id, reason=payload.reason, revoked_by_user_id=actor.user_id
        )
    except revocation_service.RevocationError as exc:
        raise HTTPException(
            status_code=_ERROR_STATUS.get(str(exc), status.HTTP_400_BAD_REQUEST), detail=str(exc)
        ) from exc
    return CertificateSummary.from_model(cert)
