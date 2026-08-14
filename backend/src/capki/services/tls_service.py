"""Replaces the web listener's own TLS cert/key (see
core/crypto/tls_bootstrap.py for the self-signed bootstrap and the
materialize-to-disk step). A replacement here takes effect on the next
process restart, not live — see api/routers/settings.py's `_schedule_restart`.
"""

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from sqlalchemy.orm import Session

from capki.config import settings
from capki.core.crypto import ca_engine, envelope
from capki.core.crypto.master_key import load_or_create_master_key
from capki.core.crypto.tls_bootstrap import TLS_LISTENER_AAD
from capki.db.base import utcnow
from capki.db.models.audit import ActorType
from capki.db.models.certificates import IssuedVia
from capki.db.models.settings import TlsListenerConfig, TlsSource
from capki.services import cert_service
from capki.services.audit_service import log_action
from capki.services.ca_service import get_active_intermediate


class TlsReplaceError(Exception):
    """Raised for TLS-replace preconditions the API layer maps to HTTP
    status codes."""


def get_tls_config(db: Session) -> TlsListenerConfig | None:
    return db.get(TlsListenerConfig, 1)


def replace_with_uploaded(
    db: Session, *, certificate_pem: str, private_key_pem: str, actor_user_id: int
) -> TlsListenerConfig:
    try:
        cert = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
        private_key = serialization.load_pem_private_key(private_key_pem.encode("ascii"), password=None)
    except ValueError as exc:
        raise TlsReplaceError("invalid_pem") from exc

    if not isinstance(private_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        raise TlsReplaceError("unsupported_key_type")

    cert_public_numbers = cert.public_key().public_numbers()
    key_public_numbers = private_key.public_key().public_numbers()
    if cert_public_numbers != key_public_numbers:
        raise TlsReplaceError("cert_key_mismatch")

    key_der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    master_key = load_or_create_master_key()
    ciphertext, meta = envelope.wrap_with_master_key(key_der, master_key, TLS_LISTENER_AAD)

    config = _upsert_tls_config(
        db,
        source=TlsSource.UPLOADED,
        certificate_pem=certificate_pem,
        private_key_encrypted=ciphertext,
        key_wrap_meta=meta,
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
    )

    log_action(db, actor_type=ActorType.USER, actor_user_id=actor_user_id, action="settings.tls_upload")
    return config


def replace_with_intermediate(db: Session, *, actor_user_id: int) -> TlsListenerConfig:
    intermediate = get_active_intermediate(db)
    if intermediate is None:
        raise TlsReplaceError("intermediate_not_ready")

    private_key = ca_engine.generate_rsa_key(2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(ca_engine.build_name(settings.app_hostname, None))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(settings.app_hostname)]), critical=False)
        .sign(private_key, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("ascii")

    try:
        issued = cert_service.issue_certificate(
            db,
            csr_pem=csr_pem,
            profile_code="server",
            requested_by_user_id=actor_user_id,
            issued_via=IssuedVia.UI,
        )
    except cert_service.CertIssuanceError as exc:
        raise TlsReplaceError(f"issuance_failed:{exc}") from exc

    key_der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    master_key = load_or_create_master_key()
    ciphertext, meta = envelope.wrap_with_master_key(key_der, master_key, TLS_LISTENER_AAD)

    config = _upsert_tls_config(
        db,
        source=TlsSource.ISSUED_BY_INTERMEDIATE,
        certificate_pem=issued.certificate_pem,
        private_key_encrypted=ciphertext,
        key_wrap_meta=meta,
        not_before=issued.not_before,
        not_after=issued.not_after,
    )

    log_action(
        db, actor_type=ActorType.USER, actor_user_id=actor_user_id, action="settings.tls_issue_from_intermediate"
    )
    return config


def _upsert_tls_config(db: Session, **fields) -> TlsListenerConfig:
    config = db.get(TlsListenerConfig, 1)
    if config is None:
        config = TlsListenerConfig(id=1, **fields, updated_at=utcnow())
        db.add(config)
    else:
        for key, value in fields.items():
            setattr(config, key, value)
        config.updated_at = utcnow()
    db.commit()
    db.refresh(config)
    return config
