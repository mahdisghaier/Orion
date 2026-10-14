"""Fernet symmetric encryption for sensitive SIEM connection configs.

Used to encrypt siem_connections.config_encrypted before it touches
the database, and decrypt it when a connector actually needs to
authenticate against Sentinel/Elastic.

Fernet (from the `cryptography` package) provides authenticated
encryption: it detects tampering, not just confidentiality. If the
ciphertext is modified, decryption raises InvalidToken rather than
silently returning garbage.
"""
import json
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import settings

_fernet = Fernet(settings.SIEM_ENCRYPTION_KEY.encode())


def encrypt_config(config: dict[str, Any]) -> str:
    """Serialize a config dict to JSON, then encrypt it.

    Returns a base64-encoded encrypted string, safe to store as TEXT.
    """
    plaintext = json.dumps(config).encode("utf-8")
    return _fernet.encrypt(plaintext).decode("utf-8")


def decrypt_config(encrypted: str) -> dict[str, Any]:
    """Decrypt an encrypted config string back into a dict.

    Raises:
        InvalidToken: if the ciphertext is corrupted, tampered with,
            or was encrypted with a different key (e.g. key rotation
            without re-encryption).
    """
    try:
        plaintext = _fernet.decrypt(encrypted.encode("utf-8"))
    except InvalidToken:
        raise ValueError(
            "Failed to decrypt SIEM config — data may be corrupted "
            "or encrypted with a different SIEM_ENCRYPTION_KEY."
        )
    return json.loads(plaintext.decode("utf-8"))