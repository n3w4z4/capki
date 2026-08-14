from cryptography import x509
from cryptography.hazmat.primitives import serialization
from sqlalchemy.orm import Session

from capki.config import settings
from capki.core.crypto import ca_engine, envelope
from capki.core.crypto.key_vault import ca_aad, key_vault
from capki.core.crypto.master_key import load_or_create_master_key
from capki.db.models.audit import ActorType
from capki.db.models.ca import CaStatus, CaType, CertificateAuthority
from capki.services import revocation_service
from capki.services.audit_service import log_action


class CaError(Exception):
    """Raised for CA-lifecycle preconditions the API layer maps to HTTP
    status codes (e.g. root_locked -> 423, *_already_exists -> 409)."""


def _base_url() -> str:
    return f"https://{settings.app_hostname}/api/v1"


def _private_key_der(private_key) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def get_root(db: Session) -> CertificateAuthority | None:
    return db.query(CertificateAuthority).filter_by(type=CaType.ROOT).first()


def get_active_intermediate(db: Session) -> CertificateAuthority | None:
    return (
        db.query(CertificateAuthority)
        .filter_by(type=CaType.INTERMEDIATE, status=CaStatus.ACTIVE)
        .first()
    )


def init_root(
    db: Session,
    *,
    common_name: str,
    organization_name: str | None,
    passphrase: str,
    actor_user_id: int,
) -> CertificateAuthority:
    if get_root(db) is not None:
        raise CaError("root_already_exists")
    if len(passphrase) < 12:
        raise CaError("passphrase_too_short")

    subject = ca_engine.build_name(common_name, organization_name)
    ca_row = CertificateAuthority(
        type=CaType.ROOT, name=common_name, subject_dn=ca_engine.name_to_string(subject), status=CaStatus.PENDING
    )
    db.add(ca_row)
    db.flush()  # assigns ca_row.id, needed for the cert's self-referential AIA/CRL URLs

    private_key = ca_engine.generate_rsa_key(ca_engine.ROOT_KEY_BITS)
    cert = ca_engine.build_root_certificate(private_key, subject, ca_row.id, _base_url())
    ciphertext, meta = envelope.wrap_with_passphrase(
        _private_key_der(private_key), passphrase, ca_aad(ca_row.id)
    )

    ca_row.certificate_pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    ca_row.private_key_encrypted = ciphertext
    ca_row.key_wrap_meta = meta
    ca_row.public_key_fingerprint = ca_engine.fingerprint(private_key.public_key())
    ca_row.not_before = cert.not_valid_before_utc
    ca_row.not_after = cert.not_valid_after_utc
    ca_row.status = CaStatus.ACTIVE
    db.commit()

    # The admin just chose this passphrase; unlocking now saves them from
    # re-entering it immediately to proceed to intermediate init.
    key_vault.unlock_root(db, passphrase)
    revocation_service.refresh_crl(db, ca_row)  # publish an initial (empty) CRL right away

    log_action(
        db,
        actor_type=ActorType.USER,
        actor_user_id=actor_user_id,
        action="ca.root_init",
        target_type="certificate_authority",
        target_id=str(ca_row.id),
    )
    return ca_row


def init_intermediate(
    db: Session, *, common_name: str, organization_name: str | None, actor_user_id: int
) -> CertificateAuthority:
    root = get_root(db)
    if root is None or root.status != CaStatus.ACTIVE:
        raise CaError("root_not_initialized")
    if not key_vault.is_root_unlocked():
        raise CaError("root_locked")
    if get_active_intermediate(db) is not None:
        raise CaError("intermediate_already_exists")

    subject = ca_engine.build_name(common_name, organization_name)
    ca_row = CertificateAuthority(
        type=CaType.INTERMEDIATE,
        name=common_name,
        subject_dn=ca_engine.name_to_string(subject),
        parent_ca_id=root.id,
        status=CaStatus.PENDING,
    )
    db.add(ca_row)
    db.flush()

    private_key = ca_engine.generate_rsa_key(ca_engine.INTERMEDIATE_KEY_BITS)
    root_cert = x509.load_pem_x509_certificate(root.certificate_pem.encode("ascii"))
    cert = ca_engine.build_intermediate_certificate(
        private_key.public_key(),
        key_vault.root_key,
        root_cert,
        subject,
        root.id,
        _base_url(),
    )
    master_key = load_or_create_master_key()
    ciphertext, meta = envelope.wrap_with_master_key(
        _private_key_der(private_key), master_key, ca_aad(ca_row.id)
    )

    ca_row.certificate_pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    ca_row.private_key_encrypted = ciphertext
    ca_row.key_wrap_meta = meta
    ca_row.public_key_fingerprint = ca_engine.fingerprint(private_key.public_key())
    ca_row.not_before = cert.not_valid_before_utc
    ca_row.not_after = cert.not_valid_after_utc
    ca_row.status = CaStatus.ACTIVE
    db.commit()

    key_vault.load_intermediate(db)
    revocation_service.refresh_crl(db, ca_row)  # publish an initial (empty) CRL right away

    log_action(
        db,
        actor_type=ActorType.USER,
        actor_user_id=actor_user_id,
        action="ca.intermediate_init",
        target_type="certificate_authority",
        target_id=str(ca_row.id),
    )
    return ca_row
