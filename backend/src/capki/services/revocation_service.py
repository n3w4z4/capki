from cryptography import x509
from cryptography.hazmat.primitives import serialization
from sqlalchemy.orm import Session

from capki.core.crypto import crl as crl_engine
from capki.core.crypto.key_vault import key_vault
from capki.db.base import utcnow
from capki.db.models.audit import ActorType
from capki.db.models.ca import CaType, CertificateAuthority
from capki.db.models.certificates import Certificate, CertificateStatus, CrlIssuance, Revocation
from capki.services.audit_service import log_action


class RevocationError(Exception):
    """Raised for revocation preconditions the API layer maps to HTTP status
    codes (e.g. certificate_not_found -> 404, already_revoked -> 409)."""


def _issuer_key_for(ca: CertificateAuthority):
    return key_vault.root_key if ca.type == CaType.ROOT else key_vault.intermediate_key


def refresh_crl(db: Session, ca: CertificateAuthority) -> CrlIssuance | None:
    """Rebuilds and persists the CRL for `ca`. Returns None (without
    raising) if the issuing key isn't currently available — e.g. a locked
    root — so periodic refresh can just skip that CA this cycle."""
    issuer_key = _issuer_key_for(ca)
    if issuer_key is None or ca.certificate_pem is None:
        return None

    issuer_cert = x509.load_pem_x509_certificate(ca.certificate_pem.encode("ascii"))
    crl = crl_engine.build_crl(db, ca, issuer_key, issuer_cert)

    issuance = CrlIssuance(
        ca_id=ca.id,
        crl_number=ca.crl_number,
        crl_pem=crl.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        this_update=crl.last_update_utc,
        next_update=crl.next_update_utc,
        created_at=utcnow(),
    )
    db.add(ca)  # crl_number was incremented in build_crl
    db.add(issuance)
    db.commit()
    return issuance


def revoke_certificate(
    db: Session, *, cert_id: int, reason: str, revoked_by_user_id: int | None
) -> Certificate:
    cert = db.get(Certificate, cert_id)
    if cert is None:
        raise RevocationError("certificate_not_found")
    if cert.status == CertificateStatus.REVOKED:
        raise RevocationError("already_revoked")
    if reason not in crl_engine.REASON_FLAGS:
        raise RevocationError("invalid_reason")

    cert.status = CertificateStatus.REVOKED
    db.add(
        Revocation(
            certificate_id=cert.id, revoked_at=utcnow(), reason=reason, revoked_by_user_id=revoked_by_user_id
        )
    )
    db.commit()

    ca = db.get(CertificateAuthority, cert.ca_id)
    refresh_crl(db, ca)  # best-effort: if the issuer key is unavailable, the periodic job catches up

    log_action(
        db,
        actor_type=ActorType.USER,
        actor_user_id=revoked_by_user_id,
        action="cert.revoke",
        target_type="certificate",
        target_id=str(cert.id),
        detail={"reason": reason},
    )
    return cert
