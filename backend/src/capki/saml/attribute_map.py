"""Maps SAML assertion attributes from an Entra ID App Role claim to an
internal RBAC role name, via `saml_config.group_role_map`
(e.g. {"CA.Admin": "admin", "CA.Operator": "operator", "CA.Auditor": "auditor"}).

Entra App Roles (configured on the Enterprise App and assigned to users or
groups) are emitted as a role claim — this is the approach chosen over raw
security-group-object-ID claims for a cleaner 1:1 mapping.
"""

ROLE_CLAIM_ATTRIBUTE_CANDIDATES = [
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",
    "roles",
    "Role",
]

EMAIL_CLAIM_ATTRIBUTE_CANDIDATES = [
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
    "email",
    "Email",
]


def resolve_role(attributes: dict[str, list[str]], group_role_map: dict[str, str] | None) -> str | None:
    if not group_role_map:
        return None
    for key in ROLE_CLAIM_ATTRIBUTE_CANDIDATES:
        for claim_value in attributes.get(key, []):
            if claim_value in group_role_map:
                return group_role_map[claim_value]
    return None


def resolve_email(attributes: dict[str, list[str]], name_id: str) -> str:
    for key in EMAIL_CLAIM_ATTRIBUTE_CANDIDATES:
        values = attributes.get(key)
        if values:
            return values[0]
    return name_id
