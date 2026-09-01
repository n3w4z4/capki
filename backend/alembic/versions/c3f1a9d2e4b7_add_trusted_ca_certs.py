"""add trusted ca certs

Revision ID: c3f1a9d2e4b7
Revises: b47753bbf61b
Create Date: 2026-09-01 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c3f1a9d2e4b7'
down_revision: Union[str, Sequence[str], None] = 'b47753bbf61b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'trusted_ca_certs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('label', sa.String(length=255), nullable=True),
        sa.Column('certificate_pem', sa.Text(), nullable=False),
        sa.Column('subject_dn', sa.String(length=500), nullable=False),
        sa.Column('issuer_dn', sa.String(length=500), nullable=False),
        sa.Column('serial_hex', sa.String(length=80), nullable=False),
        sa.Column('sha256_fingerprint', sa.String(length=95), nullable=False),
        sa.Column('not_before', sa.DateTime(timezone=True), nullable=False),
        sa.Column('not_after', sa.DateTime(timezone=True), nullable=False),
        sa.Column('is_self_signed', sa.Boolean(), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False),
        sa.Column('added_by_user_id', sa.Integer(), nullable=True),
        sa.Column('added_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['added_by_user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('sha256_fingerprint'),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('trusted_ca_certs')
