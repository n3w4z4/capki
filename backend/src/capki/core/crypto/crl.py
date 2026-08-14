"""CRL (Certificate Revocation List) generation. Regenerated synchronously
right after every revocation (see services/revocation_service.py), and
periodically via the scheduler to roll `next_update` forward even with no
new revocations.
"""

import datetime as dt

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from sqlalchemy.orm import Session

from capki.core.crypto.ca_engine import INTERMEDIATE_CRL_DAYS, ROOT_CRL_DAYS
from capki.db.base import utcnow
from capki.db.models.ca import CaType, CertificateAuthority
from capki.db.models.certificates import Certificate, CertificateStatus, Revocation

REASON_FLAGS: dict[str, x509.ReasonFlags] = {
    "unspecified": x509.ReasonFlags.unspecified,
    "key_compromise": x509.ReasonFlags.key_compromise,
    "affiliation_changed": x509.ReasonFlags.affiliation_changed,
    "superseded": x509.ReasonFlags.superseded,
    "cessation_of_operation": x509.ReasonFlags.cessation_of_operation,
    "privilege_withdrawn": x509.ReasonFlags.privilege_withdrawn,
}


def _crl_validity_days(ca_type: CaType) -> int:
    return ROOT_CRL_DAYS if ca_type == CaType.ROOT else INTERMEDIATE_CRL_DAYS


def build_crl(
    db: Session, ca: CertificateAuthority, issuer_private_key, issuer_cert: x509.Certificate
) -> x509.CertificateRevocationList:
    ca.crl_number += 1
    now = utcnow()

    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer_cert.subject)
        .last_update(now)
        .next_update(now + dt.timedelta(days=_crl_validity_days(ca.type)))
        .add_extension(x509.CRLNumber(ca.crl_number), critical=False)
    )

    revoked_rows = (
        db.query(Certificate, Revocation)
        .join(Revocation, Revocation.certificate_id == Certificate.id)
        .filter(Certificate.ca_id == ca.id, Certificate.status == CertificateStatus.REVOKED)
        .all()
    )
    for cert_row, revocation in revoked_rows:
        entry = (
            x509.RevokedCertificateBuilder()
            .serial_number(int(cert_row.serial_hex, 16))
            .revocation_date(revocation.revoked_at)
            .add_extension(
                x509.CRLReason(REASON_FLAGS.get(revocation.reason, x509.ReasonFlags.unspecified)),
                critical=False,
            )
            .build()
        )
        builder = builder.add_revoked_certificate(entry)

    return builder.sign(issuer_private_key, hashes.SHA256())
