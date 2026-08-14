"""python3-saml SP wrapper for Entra ID SSO.

Endpoints (api/routers/saml.py):
  GET  /auth/saml/metadata  - SP metadata XML, for the Entra app registration import
  GET  /auth/saml/login     - redirects to the IdP's SSO URL with a signed AuthnRequest
  POST /auth/saml/acs       - Assertion Consumer Service: validates the response

See attribute_map.py for the Entra App Role -> internal role mapping applied
after a successful response.
"""

from typing import Any

from fastapi import Request
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings

from capki.config import settings
from capki.db.models.settings import SamlConfig


def _base_url() -> str:
    return f"https://{settings.app_hostname}"


def build_settings_dict(saml_config: SamlConfig) -> dict[str, Any]:
    base = _base_url()
    return {
        "strict": True,
        "debug": False,
        "sp": {
            "entityId": saml_config.sp_entity_id or f"{base}/api/v1/auth/saml/metadata",
            "assertionConsumerService": {
                "url": f"{base}/api/v1/auth/saml/acs",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        },
        "idp": {
            "entityId": saml_config.idp_entity_id or "",
            "singleSignOnService": {
                "url": saml_config.idp_sso_url or "",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": saml_config.idp_x509_cert or "",
        },
        "security": {
            "wantAssertionsSigned": True,
            "wantMessagesSigned": False,
            "authnRequestsSigned": False,
        },
    }


async def build_request_data(request: Request) -> dict[str, Any]:
    post_data: dict[str, Any] = {}
    if request.method == "POST":
        form = await request.form()
        post_data = dict(form)
    return {
        "https": "on",
        "http_host": request.url.hostname,
        "server_port": str(request.url.port or 443),
        "script_name": request.url.path,
        "get_data": dict(request.query_params),
        "post_data": post_data,
    }


def make_auth(request_data: dict[str, Any], saml_config: SamlConfig) -> OneLogin_Saml2_Auth:
    return OneLogin_Saml2_Auth(request_data, build_settings_dict(saml_config))


def build_sp_metadata(saml_config: SamlConfig) -> tuple[str, list[str]]:
    saml_settings = OneLogin_Saml2_Settings(build_settings_dict(saml_config), sp_validation_only=True)
    metadata = saml_settings.get_sp_metadata()
    errors = saml_settings.validate_metadata(metadata)
    return metadata.decode("utf-8") if isinstance(metadata, bytes) else metadata, list(errors)
