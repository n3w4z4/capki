"""Generates a private key + CSR pair purely to hand to the caller —
nothing here ever touches the database or disk. The key exists only for the
duration of this one function call and the HTTP response that carries it;
once that response is sent, the app has no copy of it anywhere. See
api/routers/csr.py.
"""

from cryptography.hazmat.primitives import serialization

from capki.core.crypto import ca_engine

DEFAULT_KEY_BITS = 2048
MIN_PASSPHRASE_LEN = 8


class CsrGenerationError(Exception):
    """Raised for generation preconditions the API layer maps to HTTP status
    codes (e.g. weak_passphrase -> 400)."""


def generate_key_and_csr(
    *,
    common_name: str,
    organization_name: str | None,
    sans: list[str],
    passphrase: str | None = None,
    key_bits: int = DEFAULT_KEY_BITS,
) -> tuple[str, str]:
    if passphrase and len(passphrase) < MIN_PASSPHRASE_LEN:
        raise CsrGenerationError("weak_passphrase")

    private_key = ca_engine.generate_rsa_key(key_bits)
    subject = ca_engine.build_name(common_name, organization_name)
    general_names = [ca_engine.classify_san(s) for s in sans if s.strip()]
    csr = ca_engine.build_csr(private_key, subject, general_names)

    encryption: serialization.KeySerializationEncryption = (
        serialization.BestAvailableEncryption(passphrase.encode("utf-8"))
        if passphrase
        else serialization.NoEncryption()
    )
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    ).decode("ascii")
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("ascii")
    return private_key_pem, csr_pem
