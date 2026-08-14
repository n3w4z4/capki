"""seed rbac roles and permissions

Revision ID: b6169774fd50
Revises: a9124e3f8ff9
Create Date: 2026-08-13 22:37:26.986964

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# Deliberately NOT importing from capki.core.rbac.permissions: a migration
# must be a frozen historical snapshot. Importing the live module meant a
# later edit to it (adding new permissions) silently changed what THIS
# already-applied migration would insert on a fresh database, causing a
# unique-constraint collision with the migration that later adds those same
# permissions properly. This is the state ALL_PERMISSIONS/ROLE_DESCRIPTIONS/
# ROLE_PERMISSIONS had at the time this migration was written — do not sync
# it with future changes to permissions.py; add a new migration instead.
ALL_PERMISSIONS: dict[str, str] = {
    "cert:read": "View certificates",
    "cert:issue": "Issue new certificates",
    "cert:revoke": "Revoke certificates",
    "ca:read": "View certificate authorities",
    "ca:manage": "Create/renew certificate authorities",
    "ca:unlock_root": "Unlock the root CA private key",
    "ca:lock_root": "Lock the root CA private key",
    "user:read": "View users",
    "user:manage": "Create/edit/deactivate users",
    "token:read_own": "View own API tokens",
    "token:manage_own": "Create/revoke own API tokens",
    "token:manage_all": "Manage any user's API tokens",
    "settings:read": "View application settings",
    "settings:manage": "Change application settings",
    "audit:read": "View the audit log",
}

ROLE_DESCRIPTIONS: dict[str, str] = {
    "admin": "Full access: users, CAs, settings, root CA unlock",
    "operator": "Day-to-day certificate issuance and revocation",
    "auditor": "Read-only access to certificates, CAs, settings, and the audit log",
}

ROLE_PERMISSIONS: dict[str, list[str]] = {
    "admin": list(ALL_PERMISSIONS.keys()),
    "operator": [
        "cert:read",
        "cert:issue",
        "cert:revoke",
        "ca:read",
        "token:read_own",
        "token:manage_own",
        "settings:read",
    ],
    "auditor": [
        "cert:read",
        "ca:read",
        "audit:read",
        "settings:read",
        "token:read_own",
    ],
}

# revision identifiers, used by Alembic.
revision: str = 'b6169774fd50'
down_revision: Union[str, Sequence[str], None] = 'a9124e3f8ff9'
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


def upgrade() -> None:
    bind = op.get_bind()

    op.bulk_insert(
        permissions_table,
        [{"code": code, "description": desc} for code, desc in ALL_PERMISSIONS.items()],
    )
    op.bulk_insert(
        roles_table,
        [{"name": name, "description": desc} for name, desc in ROLE_DESCRIPTIONS.items()],
    )

    permission_ids = dict(
        bind.execute(sa.select(permissions_table.c.code, permissions_table.c.id)).fetchall()
    )
    role_ids = dict(bind.execute(sa.select(roles_table.c.name, roles_table.c.id)).fetchall())

    rows = [
        {"role_id": role_ids[role_name], "permission_id": permission_ids[code]}
        for role_name, codes in ROLE_PERMISSIONS.items()
        for code in codes
    ]
    op.bulk_insert(role_permissions_table, rows)


def downgrade() -> None:
    op.execute(role_permissions_table.delete())
    op.execute(roles_table.delete())
    op.execute(permissions_table.delete())
