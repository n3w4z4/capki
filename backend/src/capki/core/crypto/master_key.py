"""Loads the app-wide master key used as the KEK for the intermediate CA
private key and the web listener's TLS key (see envelope.py / key_vault.py).

Resolution order: CA_MASTER_KEY_FILE (Docker secret, preferred) ->
CA_MASTER_KEY (inline env var) -> auto-generate and persist to the secrets
file on first boot. This key is loaded once per process start and kept only
in memory; it never enters the database.
"""

import base64
import logging
import os

from capki.config import settings

logger = logging.getLogger(__name__)

MASTER_KEY_LEN = 32


def load_or_create_master_key() -> bytes:
    if settings.ca_master_key:
        return base64.b64decode(settings.ca_master_key)

    key_file = settings.ca_master_key_file
    if key_file.exists():
        return base64.b64decode(key_file.read_text().strip())

    key_file.parent.mkdir(parents=True, exist_ok=True)
    raw_key = os.urandom(MASTER_KEY_LEN)
    key_file.write_text(base64.b64encode(raw_key).decode("ascii"))
    os.chmod(key_file, 0o600)
    logger.warning(
        "No master key found at %s (and CA_MASTER_KEY not set) — generated a new one. "
        "This file protects the intermediate CA key and the web TLS key; back it up. "
        "Losing it makes those keys unrecoverable.",
        key_file,
    )
    return raw_key
