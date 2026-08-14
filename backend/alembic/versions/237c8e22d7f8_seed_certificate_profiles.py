"""seed certificate profiles

Revision ID: 237c8e22d7f8
Revises: b6169774fd50
Create Date: 2026-08-13 22:53:54.898871

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '237c8e22d7f8'
down_revision: Union[str, Sequence[str], None] = 'b6169774fd50'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

cert_profiles_table = sa.table(
    "cert_profiles",
    sa.column("code", sa.String),
    sa.column("display_name", sa.String),
    sa.column("key_usage", sa.JSON),
    sa.column("extended_key_usage", sa.JSON),
    sa.column("basic_constraints", sa.String),
    sa.column("max_validity_days", sa.Integer),
    sa.column("allowed_san_types", sa.JSON),
    sa.column("requires_email", sa.Boolean),
    sa.column("is_active", sa.Boolean),
)

# max_validity_days=397 mirrors the legacy intermed-ca.conf `default_days =
# 396` leaf-issuance default (see ca_engine.py module docstring).
PROFILES = [
    {
        "code": "server",
        "display_name": "TLS Server",
        "key_usage": ["digital_signature", "key_encipherment"],
        "extended_key_usage": ["server_auth", "client_auth"],
        "basic_constraints": "CA:FALSE",
        "max_validity_days": 397,
        "allowed_san_types": ["dns", "ip"],
        "requires_email": False,
        "is_active": True,
    },
    {
        "code": "client",
        "display_name": "mTLS Client",
        "key_usage": ["digital_signature"],
        "extended_key_usage": ["client_auth"],
        "basic_constraints": "CA:FALSE",
        "max_validity_days": 397,
        "allowed_san_types": ["dns", "ip"],
        "requires_email": False,
        "is_active": True,
    },
    {
        "code": "user",
        "display_name": "User / S-MIME",
        "key_usage": ["digital_signature"],
        "extended_key_usage": ["client_auth", "email_protection"],
        "basic_constraints": "CA:FALSE",
        "max_validity_days": 397,
        "allowed_san_types": ["email"],
        "requires_email": True,
        "is_active": True,
    },
    {
        "code": "code_signing",
        "display_name": "Code Signing",
        "key_usage": ["digital_signature"],
        "extended_key_usage": ["code_signing"],
        "basic_constraints": "CA:FALSE",
        "max_validity_days": 1095,
        "allowed_san_types": [],
        "requires_email": False,
        "is_active": True,
    },
]


def upgrade() -> None:
    op.bulk_insert(cert_profiles_table, PROFILES)


def downgrade() -> None:
    op.execute(cert_profiles_table.delete())
