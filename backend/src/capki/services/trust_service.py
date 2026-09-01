"""Manages the `trusted_ca_certs` table — extra CA certificates capki trusts
for its own outbound TLS (see core/net/trust_store.py). Admin-managed from
the Settings tab.
"""

from __future__ import annotations

import urllib.error
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID
from sqlalchemy import select
from sqlalchemy.orm import Session

from capki.core.net import trust_store
from capki.db.base import utcnow
from capki.db.models.audit import ActorType
from capki.db.models.settings import TrustedCaCert
from capki.services.audit_service import log_action

_CERT_DELIMITER = "-----END CERTIFICATE-----"


class TrustStoreError(Exception):
    """Raised for trusted-CA preconditions the API layer maps to HTTP status
    codes: invalid_pem, not_a_ca, duplicate, no_certificates."""


def list_trusted_cas(db: Session) -> list[TrustedCaCert]:
    return db.scalars(
        select(TrustedCaCert).order_by(TrustedCaCert.added_at.desc())
    ).all()


def _split_pem_bundle(pem: str) -> list[str]:
    chunks = [c.strip() for c in pem.split(_CERT_DELIMITER)]
    return [f"{c}\n{_CERT_DELIMITER}\n" for c in chunks if "BEGIN CERTIFICATE" in c]


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
    except x509.ExtensionNotFound:
        return False
    return bool(bc.ca)


def add_trusted_cas(
    db: Session, *, pem: str, label: str | None, actor_user_id: int
) -> list[TrustedCaCert]:
    """Parses `pem` (one certificate, or a bundle/chain), validates each is a
    CA, and stores the ones not already present. Certs already in the store
    (by SHA-256 fingerprint) are skipped silently. Raises if nothing usable
    was supplied."""
    pem_certs = _split_pem_bundle(pem)
    if not pem_certs:
        raise TrustStoreError("no_certificates")

    existing = set(db.scalars(select(TrustedCaCert.sha256_fingerprint)).all())
    added: list[TrustedCaCert] = []

    for cert_pem in pem_certs:
        try:
            cert = x509.load_pem_x509_certificate(cert_pem.encode("ascii"))
        except (ValueError, UnicodeEncodeError) as exc:
            raise TrustStoreError("invalid_pem") from exc

        if not _is_ca(cert):
            raise TrustStoreError("not_a_ca")

        fingerprint = cert.fingerprint(hashes.SHA256()).hex(":")
        if fingerprint in existing:
            continue
        existing.add(fingerprint)

        row = TrustedCaCert(
            label=label or None,
            certificate_pem=cert_pem,
            subject_dn=cert.subject.rfc4514_string(),
            issuer_dn=cert.issuer.rfc4514_string(),
            serial_hex=format(cert.serial_number, "x"),
            sha256_fingerprint=fingerprint,
            not_before=cert.not_valid_before_utc,
            not_after=cert.not_valid_after_utc,
            is_self_signed=cert.subject == cert.issuer,
            enabled=True,
            added_by_user_id=actor_user_id,
            added_at=utcnow(),
        )
        db.add(row)
        added.append(row)

    if not added:
        raise TrustStoreError("duplicate")

    db.commit()
    trust_store.refresh_cache(db)
    for row in added:
        db.refresh(row)
        log_action(
            db,
            actor_type=ActorType.USER,
            actor_user_id=actor_user_id,
            action="settings.trusted_ca_add",
            target_type="trusted_ca",
            target_id=str(row.id),
            detail={"subject": row.subject_dn, "fingerprint": row.sha256_fingerprint},
        )
    return added


def update_trusted_ca(
    db: Session,
    ca_id: int,
    *,
    enabled: bool | None,
    label: str | None,
    actor_user_id: int,
) -> TrustedCaCert | None:
    """Toggles `enabled` and/or updates `label`. Fields left as None are
    unchanged."""
    row = db.get(TrustedCaCert, ca_id)
    if row is None:
        return None
    if enabled is not None:
        row.enabled = enabled
    if label is not None:
        row.label = label or None
    db.commit()
    trust_store.refresh_cache(db)
    db.refresh(row)
    log_action(
        db,
        actor_type=ActorType.USER,
        actor_user_id=actor_user_id,
        action="settings.trusted_ca_update",
        target_type="trusted_ca",
        target_id=str(row.id),
        detail={"enabled": row.enabled},
    )
    return row


def delete_trusted_ca(db: Session, ca_id: int, *, actor_user_id: int) -> bool:
    row = db.get(TrustedCaCert, ca_id)
    if row is None:
        return False
    fingerprint = row.sha256_fingerprint
    subject = row.subject_dn
    db.delete(row)
    db.commit()
    trust_store.refresh_cache(db)
    log_action(
        db,
        actor_type=ActorType.USER,
        actor_user_id=actor_user_id,
        action="settings.trusted_ca_remove",
        target_type="trusted_ca",
        target_id=str(ca_id),
        detail={"subject": subject, "fingerprint": fingerprint},
    )
    return True


def test_url(url: str) -> tuple[bool, str | None]:
    """Connects to `url` using the current trust store (OS + operator CAs).
    Admin-only convenience for confirming a freshly added CA works."""
    if not url.lower().startswith("https://"):
        return False, "url_must_be_https"
    request = urllib.request.Request(url, method="HEAD")
    try:
        with urllib.request.urlopen(request, timeout=10, context=trust_store.build_ssl_context()):
            return True, None
    except urllib.error.HTTPError:
        # Reached the server and completed the TLS handshake — an HTTP
        # status (405 to a HEAD, 404, etc.) still means trust is fine.
        return True, None
    except urllib.error.URLError as exc:
        return False, str(exc.reason)
    except Exception as exc:  # noqa: BLE001 - surface anything else to the admin
        return False, str(exc) or exc.__class__.__name__
