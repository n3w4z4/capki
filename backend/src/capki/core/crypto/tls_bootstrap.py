"""Bootstraps the web server's own TLS listener certificate: generates a
self-signed cert on first boot (wrapped at rest with the same master-key KEK
as the intermediate CA key), and materializes the decrypted cert/key to disk
on every startup for Uvicorn's --ssl-certfile/--ssl-keyfile.

Replacing the cert later (Settings -> TLS) writes a new `tls_listener_config`
row and requires a process restart to take effect (see plan: no live
SSLContext hot-swap in v1) — the next startup re-runs `materialize_tls_files`
and picks up the new cert.
"""

import datetime as dt
import logging
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from sqlalchemy.orm import Session

from capki.config import settings
from capki.core.crypto import envelope
from capki.core.crypto.master_key import load_or_create_master_key
from capki.db.base import utcnow
from capki.db.models.settings import TlsListenerConfig, TlsSource

logger = logging.getLogger(__name__)

# Bound to the ciphertext so a TLS-key blob can never be swapped for another
# master-key-wrapped secret (e.g. the intermediate CA key) at unwrap time.
TLS_LISTENER_AAD = b"tls_listener:1"


def _generate_self_signed(hostname: str) -> tuple[bytes, str, dt.datetime, dt.datetime]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    not_before = utcnow() - dt.timedelta(days=1)
    not_after = utcnow() + dt.timedelta(days=365)

    sans = [x509.DNSName(hostname)]
    if hostname != "localhost":
        sans.append(x509.DNSName("localhost"))

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(private_key, hashes.SHA256())
    )

    key_der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    return key_der, cert_pem, not_before, not_after


def ensure_tls_listener_config(db: Session) -> TlsListenerConfig:
    """Returns the current TLS listener config, generating a self-signed one
    on first run if none exists yet."""
    config = db.get(TlsListenerConfig, 1)
    if config is not None:
        return config

    logger.info(
        "No TLS listener config found — generating a self-signed certificate for %s",
        settings.app_hostname,
    )
    key_der, cert_pem, not_before, not_after = _generate_self_signed(settings.app_hostname)
    master_key = load_or_create_master_key()
    ciphertext, meta = envelope.wrap_with_master_key(key_der, master_key, TLS_LISTENER_AAD)

    config = TlsListenerConfig(
        id=1,
        source=TlsSource.SELF_SIGNED,
        certificate_pem=cert_pem,
        private_key_encrypted=ciphertext,
        key_wrap_meta=meta,
        not_before=not_before,
        not_after=not_after,
        updated_at=utcnow(),
    )
    db.add(config)
    db.commit()
    db.refresh(config)
    return config


def materialize_tls_files(config: TlsListenerConfig) -> tuple[Path, Path]:
    """Decrypts the configured TLS key and writes cert+key to
    settings.tls_materialized_dir so Uvicorn can load them from disk."""
    master_key = load_or_create_master_key()
    key_der = envelope.unwrap_with_master_key(
        config.private_key_encrypted, master_key, config.key_wrap_meta, TLS_LISTENER_AAD
    )
    key_pem = serialization.load_der_private_key(key_der, password=None).private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    tls_dir = settings.tls_materialized_dir
    tls_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    cert_path = tls_dir / "tls.crt"
    key_path = tls_dir / "tls.key"
    cert_path.write_text(config.certificate_pem)
    key_path.write_bytes(key_pem)
    os.chmod(key_path, 0o600)
    return cert_path, key_path
