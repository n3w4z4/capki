"""Leaf certificate issuance: CSR validation, profile application, random
serial allocation with a DB-unique retry loop (mirrors the legacy `openssl
rand -hex 16` pattern rather than a monotonic counter), and persistence.

CSR/profile validation is split out into `validate_csr_for_profile` so
`cert_request_service.submit_request` can run the same checks up front (fast
feedback for a requester) without duplicating logic — the actual signing
still only happens at issuance/approval time.
"""

import secrets

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from capki.config import settings
from capki.core.crypto import ca_engine
from capki.core.crypto.key_vault import key_vault
from capki.db.models.audit import ActorType
from capki.db.models.ca import CertificateAuthority
from capki.db.models.certificates import Certificate, CertificateStatus, IssuedVia
from capki.db.models.profiles import CertProfile
from capki.services import revocation_service
from capki.services.audit_service import log_action
from capki.services.ca_service import get_active_intermediate, get_root

MIN_RSA_KEY_SIZE = 2048
ALLOWED_EC_CURVES = (ec.SECP256R1, ec.SECP384R1)
MAX_SERIAL_ALLOCATION_ATTEMPTS = 5


class CertIssuanceError(Exception):
    """Raised for issuance preconditions the API layer maps to HTTP status
    codes (e.g. intermediate_not_ready -> 503, invalid_csr -> 400)."""


def _base_url() -> str:
    return f"https://{settings.app_hostname}/api/v1"


def validate_public_key(public_key) -> None:
    if isinstance(public_key, rsa.RSAPublicKey):
        if public_key.key_size < MIN_RSA_KEY_SIZE:
            raise CertIssuanceError("weak_rsa_key")
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        if not isinstance(public_key.curve, ALLOWED_EC_CURVES):
            raise CertIssuanceError("unsupported_ec_curve")
    else:
        raise CertIssuanceError("unsupported_key_type")


def validate_sans(sans: list[x509.GeneralName], allowed_types: list[str]) -> list[str]:
    san_strings = []
    for gn in sans:
        type_name = ca_engine.san_type_name(gn)
        if type_name is None or type_name not in allowed_types:
            label = type_name or type(gn).__name__
            raise CertIssuanceError(f"san_type_not_allowed:{label}")
        san_strings.append(f"{type_name}:{gn.value}")
    return san_strings


def get_profile_or_raise(db: Session, profile_code: str) -> CertProfile:
    profile = db.query(CertProfile).filter_by(code=profile_code, is_active=True).first()
    if profile is None:
        raise CertIssuanceError("unknown_profile")
    return profile


def validate_csr_for_profile(
    csr_pem: str, profile: CertProfile
) -> tuple[x509.CertificateSigningRequest, list[x509.GeneralName], list[str]]:
    """Loads and validates a CSR against a profile's constraints (signature,
    key strength, allowed SAN types, required email). Raises
    CertIssuanceError on any violation; does not touch the DB or sign
    anything."""
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode("ascii"))
    except ValueError as exc:
        raise CertIssuanceError("invalid_csr") from exc
    if not csr.is_signature_valid:
        raise CertIssuanceError("invalid_csr_signature")

    validate_public_key(csr.public_key())

    sans = ca_engine.extract_csr_sans(csr)
    san_strings = validate_sans(sans, profile.allowed_san_types)
    if profile.requires_email and not any(s.startswith("email:") for s in san_strings):
        raise CertIssuanceError("email_required")

    return csr, sans, san_strings


def build_chain_pem(db: Session, cert: Certificate) -> str:
    """leaf + intermediate + root, in that order."""
    intermediate = db.get(CertificateAuthority, cert.ca_id)
    root = get_root(db)
    parts = [cert.certificate_pem]
    if intermediate is not None and intermediate.certificate_pem:
        parts.append(intermediate.certificate_pem)
    if root is not None and root.certificate_pem:
        parts.append(root.certificate_pem)
    return "\n".join(parts)


def issue_certificate(
    db: Session,
    *,
    csr_pem: str,
    profile_code: str,
    requested_by_user_id: int | None,
    issued_via: IssuedVia,
    api_token_id: int | None = None,
    validity_days: int | None = None,
) -> Certificate:
    if key_vault.intermediate_key is None:
        raise CertIssuanceError("intermediate_not_ready")

    intermediate = get_active_intermediate(db)
    if intermediate is None:
        raise CertIssuanceError("intermediate_not_ready")

    profile = get_profile_or_raise(db, profile_code)
    csr, sans, san_strings = validate_csr_for_profile(csr_pem, profile)

    effective_validity = profile.max_validity_days
    if validity_days is not None:
        if validity_days <= 0 or validity_days > profile.max_validity_days:
            raise CertIssuanceError("validity_exceeds_profile_max")
        effective_validity = validity_days

    intermediate_cert = x509.load_pem_x509_certificate(intermediate.certificate_pem.encode("ascii"))

    for _attempt in range(MAX_SERIAL_ALLOCATION_ATTEMPTS):
        serial_hex = secrets.token_hex(16)
        cert = ca_engine.build_leaf_certificate(
            csr,
            key_vault.intermediate_key,
            intermediate_cert,
            serial_hex,
            effective_validity,
            profile.key_usage,
            profile.extended_key_usage,
            intermediate.id,
            _base_url(),
            sans,
        )
        row = Certificate(
            ca_id=intermediate.id,
            serial_hex=serial_hex,
            profile_code=profile.code,
            subject_dn=ca_engine.name_to_string(csr.subject),
            sans=san_strings,
            certificate_pem=cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
            csr_pem=csr_pem,
            public_key_fingerprint=ca_engine.fingerprint(csr.public_key()),
            not_before=cert.not_valid_before_utc,
            not_after=cert.not_valid_after_utc,
            status=CertificateStatus.VALID,
            requested_by_user_id=requested_by_user_id,
            issued_via=issued_via,
            api_token_id=api_token_id,
        )
        db.add(row)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            continue

        log_action(
            db,
            actor_type=ActorType.USER if requested_by_user_id else ActorType.SYSTEM,
            actor_user_id=requested_by_user_id,
            actor_token_id=api_token_id,
            action="cert.issue",
            target_type="certificate",
            target_id=str(row.id),
            detail={"profile": profile.code, "subject": row.subject_dn},
        )
        return row

    raise CertIssuanceError("serial_allocation_failed")


def renew_certificate(
    db: Session,
    *,
    predecessor_cert_id: int,
    csr_pem: str,
    requested_by_user_id: int | None,
    issued_via: IssuedVia,
    api_token_id: int | None = None,
    validity_days: int | None = None,
) -> tuple[Certificate, bool]:
    """Issues a new certificate reusing the predecessor's profile, then
    best-effort marks the predecessor revoked with reason=superseded — the
    CRL reason code that exists precisely for "replaced, not compromised",
    as opposed to a real revocation. The predecessor's key/CSR is never
    reused; the caller must submit a fresh CSR proving current possession of
    whatever key the replacement will use. If the predecessor is already
    revoked/expired, superseding is skipped (not an error) since there's
    nothing meaningful left to supersede. Returns (new_cert, superseded)."""
    predecessor = db.get(Certificate, predecessor_cert_id)
    if predecessor is None:
        raise CertIssuanceError("predecessor_not_found")

    new_cert = issue_certificate(
        db,
        csr_pem=csr_pem,
        profile_code=predecessor.profile_code,
        requested_by_user_id=requested_by_user_id,
        issued_via=issued_via,
        api_token_id=api_token_id,
        validity_days=validity_days,
    )

    superseded = False
    if predecessor.status == CertificateStatus.VALID:
        try:
            revocation_service.revoke_certificate(
                db, cert_id=predecessor.id, reason="superseded", revoked_by_user_id=requested_by_user_id
            )
            superseded = True
        except revocation_service.RevocationError:
            pass

    return new_cert, superseded
