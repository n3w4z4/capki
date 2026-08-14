"""backfill subject_dn email attribute display name

Recomputes subject_dn for existing certificate_authorities/certificates rows
from their stored certificate_pem, using the same name_to_string() override
now applied at issuance time (see core/crypto/ca_engine.py). Fixes subject
DNs containing an emailAddress attribute rendering as the raw OID
"1.2.840.113549.1.9.1=..." instead of "emailAddress=...". Purely cosmetic —
the certificates themselves were always correct, only this cached display
string was wrong.

Revision ID: f28996811c02
Revises: 237c8e22d7f8
Create Date: 2026-08-13 23:39:26.466471

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from cryptography import x509
from cryptography.x509.oid import NameOID

# revision identifiers, used by Alembic.
revision: str = 'f28996811c02'
down_revision: Union[str, Sequence[str], None] = '237c8e22d7f8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_NAME_ATTR_OVERRIDES = {NameOID.EMAIL_ADDRESS: "emailAddress"}

_TABLES = ["certificate_authorities", "certificates"]


def _backfill(table_name: str) -> None:
    bind = op.get_bind()
    table = sa.table(
        table_name,
        sa.column("id", sa.Integer),
        sa.column("subject_dn", sa.String),
        sa.column("certificate_pem", sa.Text),
    )
    rows = bind.execute(
        sa.select(table.c.id, table.c.subject_dn, table.c.certificate_pem).where(
            table.c.certificate_pem.is_not(None)
        )
    ).fetchall()

    for row_id, subject_dn, certificate_pem in rows:
        cert = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
        correct_dn = cert.subject.rfc4514_string(attr_name_overrides=_NAME_ATTR_OVERRIDES)
        if correct_dn != subject_dn:
            bind.execute(table.update().where(table.c.id == row_id).values(subject_dn=correct_dn))


def upgrade() -> None:
    for table_name in _TABLES:
        _backfill(table_name)


def downgrade() -> None:
    pass  # cosmetic backfill only; nothing meaningful to revert
