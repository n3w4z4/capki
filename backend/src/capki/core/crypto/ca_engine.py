"""x509 building blocks for CA certificate generation and leaf-certificate
issuance.

Validity periods mirror the legacy OpenSSL CA: root README signs itself for
10 years, and signs the intermediate for 5 years (see
../../../../root/README.txt and ../../../../intermediate/README.txt in the
repo). The legacy intermed-ca.conf's `default_days = 396` is the *leaf*
issuance default, not the intermediate's own lifetime — that constant is
reused as the cert_profiles default (see alembic seed migration), not here.
"""

import datetime as dt
import hashlib
import ipaddress

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID, NameOID

from capki.db.base import utcnow

ROOT_KEY_BITS = 4096
INTERMEDIATE_KEY_BITS = 3072
ROOT_VALIDITY_DAYS = 3653  # ~10 years
INTERMEDIATE_VALIDITY_DAYS = 1827  # ~5 years
ROOT_CRL_DAYS = 180
INTERMEDIATE_CRL_DAYS = 30


def generate_rsa_key(bits: int) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def build_name(common_name: str, organization_name: str | None) -> x509.Name:
    attrs = []
    if organization_name:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name))
    attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
    return x509.Name(attrs)


# RFC 4514 has no registered short name for this legacy PKCS#9 attribute, so
# cryptography's rfc4514_string() falls back to the raw dotted OID unless we
# supply an override — without this, subject DNs including an emailAddress
# (e.g. the "user" profile) render as "1.2.840.113549.1.9.1=..." instead of
# "emailAddress=...".
_NAME_ATTR_OVERRIDES = {NameOID.EMAIL_ADDRESS: "emailAddress"}


def name_to_string(name: x509.Name) -> str:
    return name.rfc4514_string(attr_name_overrides=_NAME_ATTR_OVERRIDES)


def _issuer_pointer_extensions(
    base_url: str, issuer_ca_id: int
) -> tuple[x509.AuthorityInformationAccess, x509.CRLDistributionPoints]:
    """Both of these extensions describe where to find data about the
    *issuer* of the certificate they're attached to — the issuer's own cert
    (AIA caIssuers) and the CRL the issuer publishes (crlDistributionPoints).
    For a self-signed root, issuer_ca_id is the root's own id."""
    aia = x509.AuthorityInformationAccess(
        [
            x509.AccessDescription(
                AuthorityInformationAccessOID.CA_ISSUERS,
                x509.UniformResourceIdentifier(f"{base_url}/ca/{issuer_ca_id}/certificate.pem"),
            )
        ]
    )
    crl_dp = x509.CRLDistributionPoints(
        [
            x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier(f"{base_url}/ca/{issuer_ca_id}/crl")],
                relative_name=None,
                reasons=None,
                crl_issuer=None,
            )
        ]
    )
    return aia, crl_dp


def _ca_key_usage() -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=False,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False,
    )


def build_root_certificate(
    private_key: rsa.RSAPrivateKey, subject: x509.Name, ca_id: int, base_url: str
) -> x509.Certificate:
    public_key = private_key.public_key()
    not_before = utcnow() - dt.timedelta(days=1)
    not_after = utcnow() + dt.timedelta(days=ROOT_VALIDITY_DAYS)
    aia, crl_dp = _issuer_pointer_extensions(base_url, ca_id)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(_ca_key_usage(), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key), critical=False)
        .add_extension(aia, critical=False)
        .add_extension(crl_dp, critical=False)
    )
    return builder.sign(private_key, hashes.SHA256())


def build_intermediate_certificate(
    intermediate_public_key,
    root_private_key: rsa.RSAPrivateKey,
    root_cert: x509.Certificate,
    subject: x509.Name,
    root_ca_id: int,
    base_url: str,
) -> x509.Certificate:
    not_before = utcnow() - dt.timedelta(days=1)
    not_after = utcnow() + dt.timedelta(days=INTERMEDIATE_VALIDITY_DAYS)
    aia, crl_dp = _issuer_pointer_extensions(base_url, root_ca_id)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.subject)
        .public_key(intermediate_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(_ca_key_usage(), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(intermediate_public_key), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_cert.public_key()),
            critical=False,
        )
        .add_extension(aia, critical=False)
        .add_extension(crl_dp, critical=False)
    )
    return builder.sign(root_private_key, hashes.SHA256())


def fingerprint(public_key) -> str:
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(der).hexdigest()


_KEY_USAGE_FIELDS = (
    "digital_signature",
    "content_commitment",
    "key_encipherment",
    "data_encipherment",
    "key_agreement",
    "key_cert_sign",
    "crl_sign",
    "encipher_only",
    "decipher_only",
)


def key_usage_from_names(names: list[str]) -> x509.KeyUsage:
    unknown = set(names) - set(_KEY_USAGE_FIELDS)
    if unknown:
        raise ValueError(f"unknown key usage name(s): {sorted(unknown)}")
    flags = {field: field in names for field in _KEY_USAGE_FIELDS}
    return x509.KeyUsage(**flags)


_EXTENDED_KEY_USAGE_OIDS = {
    "server_auth": ExtendedKeyUsageOID.SERVER_AUTH,
    "client_auth": ExtendedKeyUsageOID.CLIENT_AUTH,
    "email_protection": ExtendedKeyUsageOID.EMAIL_PROTECTION,
    "code_signing": ExtendedKeyUsageOID.CODE_SIGNING,
}


def extended_key_usage_from_names(names: list[str]) -> x509.ExtendedKeyUsage:
    unknown = set(names) - set(_EXTENDED_KEY_USAGE_OIDS)
    if unknown:
        raise ValueError(f"unknown extended key usage name(s): {sorted(unknown)}")
    return x509.ExtendedKeyUsage([_EXTENDED_KEY_USAGE_OIDS[name] for name in names])


_SAN_TYPE_NAMES: dict[type, str] = {
    x509.DNSName: "dns",
    x509.IPAddress: "ip",
    x509.RFC822Name: "email",
}


def san_type_name(general_name: x509.GeneralName) -> str | None:
    return _SAN_TYPE_NAMES.get(type(general_name))


def extract_csr_sans(csr: x509.CertificateSigningRequest) -> list[x509.GeneralName]:
    try:
        ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    return list(ext.value)


def build_leaf_certificate(
    csr: x509.CertificateSigningRequest,
    issuer_private_key,
    issuer_cert: x509.Certificate,
    serial_hex: str,
    validity_days: int,
    key_usage_names: list[str],
    extended_key_usage_names: list[str],
    issuer_ca_id: int,
    base_url: str,
    sans: list[x509.GeneralName],
) -> x509.Certificate:
    not_before = utcnow() - dt.timedelta(days=1)
    not_after = utcnow() + dt.timedelta(days=validity_days)
    aia, crl_dp = _issuer_pointer_extensions(base_url, issuer_ca_id)

    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(issuer_cert.subject)
        .public_key(csr.public_key())
        .serial_number(int(serial_hex, 16))
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(key_usage_from_names(key_usage_names), critical=True)
        .add_extension(extended_key_usage_from_names(extended_key_usage_names), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()),
            critical=False,
        )
        .add_extension(aia, critical=False)
        .add_extension(crl_dp, critical=False)
    )
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    return builder.sign(issuer_private_key, hashes.SHA256())


def classify_san(value: str) -> x509.GeneralName:
    """Best-effort classification of a free-typed SAN value for the CSR
    generator (core/crypto -> services/csr_service.py): an '@' means email,
    a parseable IP literal means IP, otherwise DNS."""
    value = value.strip()
    if "@" in value:
        return x509.RFC822Name(value)
    try:
        return x509.IPAddress(ipaddress.ip_address(value))
    except ValueError:
        return x509.DNSName(value)


def build_csr(private_key, subject: x509.Name, sans: list[x509.GeneralName]) -> x509.CertificateSigningRequest:
    builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    return builder.sign(private_key, hashes.SHA256())
