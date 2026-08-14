"""add requester role and cert request/approve permissions

Revision ID: 000ca8172725
Revises: f28996811c02
Create Date: 2026-08-14 00:24:51.018898

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# Frozen snapshot, not imported from capki.core.rbac.permissions — see the
# comment in b6169774fd50 for why migrations must not read live module
# state. Do not sync this with future permissions.py edits; add a new
# migration instead.
ROLE_ADMIN = "admin"
ROLE_OPERATOR = "operator"
ROLE_REQUESTER = "requester"
CERT_REQUEST = "cert:request"
CERT_APPROVE = "cert:approve"
REQUESTER_DESCRIPTION = "Can submit certificate requests and retrieve their own issued certificates"

# revision identifiers, used by Alembic.
revision: str = '000ca8172725'
down_revision: Union[str, Sequence[str], None] = 'f28996811c02'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

roles_table = sa.table(
    "roles",
    sa.column("id", sa.Integer),
    sa.column("name", sa.String),
    sa.column("description", sa.String),
)
permissions_table = sa.table(
    "permissions",
    sa.column("id", sa.Integer),
    sa.column("code", sa.String),
    sa.column("description", sa.String),
)
role_permissions_table = sa.table(
    "role_permissions",
    sa.column("role_id", sa.Integer),
    sa.column("permission_id", sa.Integer),
)

_NEW_PERMISSIONS = {
    CERT_REQUEST: "Submit a certificate request for approval",
    CERT_APPROVE: "Approve or reject pending certificate requests",
}


def upgrade() -> None:
    bind = op.get_bind()

    op.bulk_insert(
        permissions_table,
        [{"code": code, "description": desc} for code, desc in _NEW_PERMISSIONS.items()],
    )
    op.bulk_insert(roles_table, [{"name": ROLE_REQUESTER, "description": REQUESTER_DESCRIPTION}])

    permission_ids = dict(
        bind.execute(
            sa.select(permissions_table.c.code, permissions_table.c.id).where(
                permissions_table.c.code.in_([CERT_REQUEST, CERT_APPROVE])
            )
        ).fetchall()
    )
    role_ids = dict(
        bind.execute(
            sa.select(roles_table.c.name, roles_table.c.id).where(
                roles_table.c.name.in_([ROLE_ADMIN, ROLE_OPERATOR, ROLE_REQUESTER])
            )
        ).fetchall()
    )

    op.bulk_insert(
        role_permissions_table,
        [
            {"role_id": role_ids[ROLE_REQUESTER], "permission_id": permission_ids[CERT_REQUEST]},
            {"role_id": role_ids[ROLE_OPERATOR], "permission_id": permission_ids[CERT_APPROVE]},
            # admin = all permissions; the two new ones weren't in the original frozen seed.
            {"role_id": role_ids[ROLE_ADMIN], "permission_id": permission_ids[CERT_REQUEST]},
            {"role_id": role_ids[ROLE_ADMIN], "permission_id": permission_ids[CERT_APPROVE]},
        ],
    )


def downgrade() -> None:
    bind = op.get_bind()
    permission_ids = dict(
        bind.execute(
            sa.select(permissions_table.c.code, permissions_table.c.id).where(
                permissions_table.c.code.in_([CERT_REQUEST, CERT_APPROVE])
            )
        ).fetchall()
    )
    op.execute(
        role_permissions_table.delete().where(
            role_permissions_table.c.permission_id.in_(permission_ids.values())
        )
    )
    op.execute(roles_table.delete().where(roles_table.c.name == ROLE_REQUESTER))
    op.execute(permissions_table.delete().where(permissions_table.c.code.in_([CERT_REQUEST, CERT_APPROVE])))
