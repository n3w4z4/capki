"""Process-wide singleton holding decrypted CA private keys in memory.

Root: locked by default; an Admin unlocks it with a passphrase (per process
start), and it's used only for the rare root-signs-intermediate operation.
Intermediate: auto-unlocked at process start via the app master key, so
certificate issuance keeps working across unattended restarts. See
envelope.py for the wrap/unwrap primitives.
"""

import datetime as dt
import logging

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from sqlalchemy.orm import Session

from capki.core.crypto import envelope
from capki.core.crypto.master_key import load_or_create_master_key
from capki.db.base import utcnow
from capki.db.models.ca import CaStatus, CaType, CertificateAuthority

logger = logging.getLogger(__name__)


def ca_aad(ca_id: int) -> bytes:
    """AAD binding a wrapped CA key ciphertext to its own row, so it can
    never be unwrapped as if it were a different CA's key."""
    return f"ca:{ca_id}".encode("utf-8")


class KeyVault:
    def __init__(self) -> None:
        self._intermediate_key: RSAPrivateKey | None = None
        self._intermediate_ca_id: int | None = None
        self._root_key: RSAPrivateKey | None = None
        self._root_unlocked_at: dt.datetime | None = None

    def load_intermediate(self, db: Session) -> None:
        ca = (
            db.query(CertificateAuthority)
            .filter_by(type=CaType.INTERMEDIATE, status=CaStatus.ACTIVE)
            .first()
        )
        if ca is None or ca.private_key_encrypted is None:
            self._intermediate_key = None
            self._intermediate_ca_id = None
            return

        master_key = load_or_create_master_key()
        key_der = envelope.unwrap_with_master_key(
            ca.private_key_encrypted, master_key, ca.key_wrap_meta, ca_aad(ca.id)
        )
        self._intermediate_key = serialization.load_der_private_key(key_der, password=None)
        self._intermediate_ca_id = ca.id

    @property
    def intermediate_key(self) -> RSAPrivateKey | None:
        return self._intermediate_key

    @property
    def intermediate_ca_id(self) -> int | None:
        return self._intermediate_ca_id

    def unlock_root(self, db: Session, passphrase: str) -> bool:
        ca = db.query(CertificateAuthority).filter_by(type=CaType.ROOT).first()
        if ca is None or ca.private_key_encrypted is None:
            return False
        try:
            key_der = envelope.unwrap_with_passphrase(
                ca.private_key_encrypted, passphrase, ca.key_wrap_meta, ca_aad(ca.id)
            )
        except Exception:
            return False

        self._root_key = serialization.load_der_private_key(key_der, password=None)
        self._root_unlocked_at = utcnow()
        return True

    def lock_root(self) -> None:
        self._root_key = None
        self._root_unlocked_at = None

    @property
    def root_key(self) -> RSAPrivateKey | None:
        return self._root_key

    @property
    def root_unlocked_at(self) -> dt.datetime | None:
        return self._root_unlocked_at

    def is_root_unlocked(self) -> bool:
        return self._root_key is not None


key_vault = KeyVault()
