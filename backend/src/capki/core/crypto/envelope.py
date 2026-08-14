"""Envelope encryption primitives shared by every secret the app stores at
rest (root CA key, intermediate CA key, web listener TLS key). All of them
use AES-256-GCM for the actual wrap; they differ only in where the
Key-Encryption-Key (KEK) comes from — an Admin-entered passphrase (root CA)
or the app-wide master key (everything else). See key_vault.py.
"""

import base64
import os
from typing import Any

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST_KIB = 64 * 1024  # 64 MB
ARGON2_PARALLELISM = 4
ARGON2_KEY_LEN = 32
SALT_LEN = 16
NONCE_LEN = 12

WrapMeta = dict[str, Any]


def generate_salt() -> bytes:
    return os.urandom(SALT_LEN)


def _derive_kek_from_passphrase(
    passphrase: str,
    salt: bytes,
    time_cost: int = ARGON2_TIME_COST,
    memory_cost_kib: int = ARGON2_MEMORY_COST_KIB,
    parallelism: int = ARGON2_PARALLELISM,
) -> bytes:
    return hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost_kib,
        parallelism=parallelism,
        hash_len=ARGON2_KEY_LEN,
        type=Type.ID,
    )


def _aead_wrap(plaintext: bytes, kek: bytes, aad: bytes) -> tuple[bytes, WrapMeta]:
    nonce = os.urandom(NONCE_LEN)
    ciphertext = AESGCM(kek).encrypt(nonce, plaintext, aad)
    return ciphertext, {"nonce": base64.b64encode(nonce).decode("ascii")}


def _aead_unwrap(ciphertext: bytes, kek: bytes, meta: WrapMeta, aad: bytes) -> bytes:
    nonce = base64.b64decode(meta["nonce"])
    return AESGCM(kek).decrypt(nonce, ciphertext, aad)


def wrap_with_passphrase(plaintext: bytes, passphrase: str, aad: bytes) -> tuple[bytes, WrapMeta]:
    salt = generate_salt()
    kek = _derive_kek_from_passphrase(passphrase, salt)
    ciphertext, meta = _aead_wrap(plaintext, kek, aad)
    meta.update(
        {
            "kek_source": "passphrase",
            "salt": base64.b64encode(salt).decode("ascii"),
            "argon2": {
                "time_cost": ARGON2_TIME_COST,
                "memory_cost_kib": ARGON2_MEMORY_COST_KIB,
                "parallelism": ARGON2_PARALLELISM,
            },
        }
    )
    return ciphertext, meta


def unwrap_with_passphrase(ciphertext: bytes, passphrase: str, meta: WrapMeta, aad: bytes) -> bytes:
    salt = base64.b64decode(meta["salt"])
    params = meta.get("argon2", {})
    kek = _derive_kek_from_passphrase(
        passphrase,
        salt,
        time_cost=params.get("time_cost", ARGON2_TIME_COST),
        memory_cost_kib=params.get("memory_cost_kib", ARGON2_MEMORY_COST_KIB),
        parallelism=params.get("parallelism", ARGON2_PARALLELISM),
    )
    return _aead_unwrap(ciphertext, kek, meta, aad)


def wrap_with_master_key(plaintext: bytes, master_key: bytes, aad: bytes) -> tuple[bytes, WrapMeta]:
    ciphertext, meta = _aead_wrap(plaintext, master_key, aad)
    meta["kek_source"] = "master_key"
    return ciphertext, meta


def unwrap_with_master_key(ciphertext: bytes, master_key: bytes, meta: WrapMeta, aad: bytes) -> bytes:
    return _aead_unwrap(ciphertext, master_key, meta, aad)
