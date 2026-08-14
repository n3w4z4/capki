"""Permission codes and the fixed role -> permission seed data for v1.

This module is deliberately dependency-free (no DB models, no SQLAlchemy) so
it can be imported both by the app at runtime (`core/rbac/context.py`) and by
the Alembic data migrations that seed `roles`/`permissions`/`role_permissions`
(see alembic/versions/*_seed_rbac.py, *_add_requester_role.py) without a
circular-import risk.
"""

CERT_READ = "cert:read"
CERT_ISSUE = "cert:issue"
CERT_REVOKE = "cert:revoke"
CERT_REQUEST = "cert:request"
CERT_APPROVE = "cert:approve"
CA_READ = "ca:read"
CA_MANAGE = "ca:manage"
CA_UNLOCK_ROOT = "ca:unlock_root"
CA_LOCK_ROOT = "ca:lock_root"
USER_READ = "user:read"
USER_MANAGE = "user:manage"
TOKEN_READ_OWN = "token:read_own"
TOKEN_MANAGE_OWN = "token:manage_own"
TOKEN_MANAGE_ALL = "token:manage_all"
SETTINGS_READ = "settings:read"
SETTINGS_MANAGE = "settings:manage"
AUDIT_READ = "audit:read"

ALL_PERMISSIONS: dict[str, str] = {
    CERT_READ: "View certificates",
    CERT_ISSUE: "Issue new certificates directly",
    CERT_REVOKE: "Revoke certificates",
    CERT_REQUEST: "Submit a certificate request for approval",
    CERT_APPROVE: "Approve or reject pending certificate requests",
    CA_READ: "View certificate authorities",
    CA_MANAGE: "Create/renew certificate authorities",
    CA_UNLOCK_ROOT: "Unlock the root CA private key",
    CA_LOCK_ROOT: "Lock the root CA private key",
    USER_READ: "View users",
    USER_MANAGE: "Create/edit/deactivate users",
    TOKEN_READ_OWN: "View own API tokens",
    TOKEN_MANAGE_OWN: "Create/revoke own API tokens",
    TOKEN_MANAGE_ALL: "Manage any user's API tokens",
    SETTINGS_READ: "View application settings",
    SETTINGS_MANAGE: "Change application settings",
    AUDIT_READ: "View the audit log",
}

ROLE_ADMIN = "admin"
ROLE_OPERATOR = "operator"
ROLE_AUDITOR = "auditor"
ROLE_REQUESTER = "requester"

ROLE_DESCRIPTIONS: dict[str, str] = {
    ROLE_ADMIN: "Full access: users, CAs, settings, root CA unlock",
    ROLE_OPERATOR: "Day-to-day certificate issuance, revocation, and approving requests",
    ROLE_AUDITOR: "Read-only access to certificates, CAs, settings, and the audit log",
    ROLE_REQUESTER: "Can submit certificate requests and retrieve their own issued certificates",
}

ROLE_PERMISSIONS: dict[str, list[str]] = {
    ROLE_ADMIN: list(ALL_PERMISSIONS.keys()),
    ROLE_OPERATOR: [
        CERT_READ,
        CERT_ISSUE,
        CERT_REVOKE,
        CERT_APPROVE,
        CA_READ,
        TOKEN_READ_OWN,
        TOKEN_MANAGE_OWN,
        SETTINGS_READ,
    ],
    ROLE_AUDITOR: [
        CERT_READ,
        CA_READ,
        AUDIT_READ,
        SETTINGS_READ,
        TOKEN_READ_OWN,
    ],
    ROLE_REQUESTER: [
        CERT_REQUEST,
    ],
}
