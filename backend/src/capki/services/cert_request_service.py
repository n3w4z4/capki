"""Certificate request / approval workflow for the `requester` role: submit
a CSR for review, an operator/admin approves (which actually signs it via
cert_service.issue_certificate) or rejects it.
"""

from sqlalchemy.orm import Session

from capki.db.base import utcnow
from capki.db.models.audit import ActorType
from capki.db.models.cert_requests import CertificateRequest, CertRequestStatus
from capki.db.models.certificates import Certificate, IssuedVia
from capki.services import cert_service
from capki.services.audit_service import log_action


class CertRequestError(Exception):
    """Raised for request-workflow preconditions the API layer maps to HTTP
    status codes (e.g. not_found -> 404, not_pending -> 409, forbidden -> 403)."""


def submit_request(
    db: Session, *, csr_pem: str, profile_code: str, requested_by_user_id: int
) -> CertificateRequest:
    profile = cert_service.get_profile_or_raise(db, profile_code)
    # Validate now so the requester gets fast feedback; re-validated again
    # at approval time in case the profile changed in between.
    cert_service.validate_csr_for_profile(csr_pem, profile)

    row = CertificateRequest(
        csr_pem=csr_pem,
        profile_code=profile.code,
        requested_by_user_id=requested_by_user_id,
        status=CertRequestStatus.PENDING,
    )
    db.add(row)
    db.commit()

    log_action(
        db,
        actor_type=ActorType.USER,
        actor_user_id=requested_by_user_id,
        action="certrequest.submit",
        target_type="certificate_request",
        target_id=str(row.id),
        detail={"profile": profile.code},
    )
    return row


def list_own_requests(db: Session, user_id: int) -> list[CertificateRequest]:
    return (
        db.query(CertificateRequest)
        .filter(CertificateRequest.requested_by_user_id == user_id)
        .order_by(CertificateRequest.id.desc())
        .all()
    )


def list_pending_requests(db: Session) -> list[CertificateRequest]:
    return (
        db.query(CertificateRequest)
        .filter(CertificateRequest.status == CertRequestStatus.PENDING)
        .order_by(CertificateRequest.id.asc())
        .all()
    )


def _get_pending_or_raise(db: Session, request_id: int) -> CertificateRequest:
    req = db.get(CertificateRequest, request_id)
    if req is None:
        raise CertRequestError("not_found")
    if req.status != CertRequestStatus.PENDING:
        raise CertRequestError("not_pending")
    return req


def approve_request(
    db: Session, *, request_id: int, reviewer_user_id: int, validity_days: int | None = None
) -> CertificateRequest:
    req = _get_pending_or_raise(db, request_id)

    try:
        cert = cert_service.issue_certificate(
            db,
            csr_pem=req.csr_pem,
            profile_code=req.profile_code,
            requested_by_user_id=req.requested_by_user_id,
            issued_via=IssuedVia.UI,
            validity_days=validity_days,
        )
    except cert_service.CertIssuanceError as exc:
        raise CertRequestError(f"issuance_failed:{exc}") from exc

    req.status = CertRequestStatus.APPROVED
    req.reviewed_by_user_id = reviewer_user_id
    req.reviewed_at = utcnow()
    req.certificate_id = cert.id
    db.commit()

    log_action(
        db,
        actor_type=ActorType.USER,
        actor_user_id=reviewer_user_id,
        action="certrequest.approve",
        target_type="certificate_request",
        target_id=str(req.id),
        detail={"certificate_id": cert.id},
    )
    return req


def reject_request(
    db: Session, *, request_id: int, reviewer_user_id: int, reason: str
) -> CertificateRequest:
    req = _get_pending_or_raise(db, request_id)

    req.status = CertRequestStatus.REJECTED
    req.reviewed_by_user_id = reviewer_user_id
    req.reviewed_at = utcnow()
    req.rejection_reason = reason
    db.commit()

    log_action(
        db,
        actor_type=ActorType.USER,
        actor_user_id=reviewer_user_id,
        action="certrequest.reject",
        target_type="certificate_request",
        target_id=str(req.id),
        detail={"reason": reason},
    )
    return req


def get_owned_certificate(db: Session, *, request_id: int, actor_user_id: int, is_privileged: bool) -> Certificate:
    """Returns the Certificate resulting from an approved request, if the
    caller owns the request (or holds cert:read)."""
    req = db.get(CertificateRequest, request_id)
    if req is None:
        raise CertRequestError("not_found")
    if req.requested_by_user_id != actor_user_id and not is_privileged:
        raise CertRequestError("forbidden")
    if req.status != CertRequestStatus.APPROVED or req.certificate_id is None:
        raise CertRequestError("not_approved")

    cert = db.get(Certificate, req.certificate_id)
    if cert is None:
        raise CertRequestError("not_found")
    return cert
