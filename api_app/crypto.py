# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""
Encryption utilities for securing secrets stored in the database.

Uses Fernet symmetric encryption (AES-128-CBC with HMAC-SHA256)
from the ``cryptography`` library. The encryption key is derived
from ``SECRETS_ENCRYPTION_KEY`` if set, otherwise from
``DJANGO_SECRET`` via SHA-256.
"""

import base64
import hashlib
import json
import logging
import typing

from cryptography.fernet import Fernet  # noqa: F401
from django.conf import settings

logger = logging.getLogger(__name__)


def get_encryption_key() -> bytes:
    """
    Derive a Fernet-compatible encryption key.

    Priority:
    1. ``settings.SECRETS_ENCRYPTION_KEY`` — hashed via SHA-256
       and base64url-encoded to produce a valid 32-byte Fernet key.
    2. ``settings.SECRET_KEY`` — same derivation.

    Returns:
        bytes: A URL-safe base64-encoded key suitable for Fernet.

    Raises:
        RuntimeError: If neither key source is available.
    """
    raw_key = (
        getattr(settings, "SECRETS_ENCRYPTION_KEY", None)
        or settings.SECRET_KEY
    )
    if not raw_key:
        raise RuntimeError(
            "No encryption key available. "
            "Set SECRETS_ENCRYPTION_KEY or DJANGO_SECRET "
            "in your environment."
        )
    # Derive a 32-byte key via SHA-256, then base64url-encode
    digest = hashlib.sha256(raw_key.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def encrypt_secret(value: typing.Any) -> str:
    """
    Encrypt a JSON-serializable value.

    Args:
        value: Any JSON-serializable Python object.

    Returns:
        str: The Fernet-encrypted ciphertext (UTF-8 string).
    """
    key = get_encryption_key()
    f = Fernet(key)
    plaintext = json.dumps(value).encode("utf-8")
    return f.encrypt(plaintext).decode("utf-8")


def decrypt_secret(encrypted_value: str) -> typing.Any:
    """
    Decrypt a Fernet-encrypted value back to its original type.

    Args:
        encrypted_value: Ciphertext produced by
            :func:`encrypt_secret`.

    Returns:
        The original Python object.

    Raises:
        cryptography.fernet.InvalidToken:
            If the token is invalid or the key is wrong.
    """
    key = get_encryption_key()
    f = Fernet(key)
    plaintext = f.decrypt(encrypted_value.encode("utf-8"))
    return json.loads(plaintext.decode("utf-8"))


def is_encrypted(value: typing.Any) -> bool:
    """
    Check if a value appears to be Fernet-encrypted.

    A Fernet token is a non-empty string starting with ``gAAAAA``.

    Args:
        value: The value to check.

    Returns:
        bool: True if the value looks like a Fernet token.
    """
    return isinstance(value, str) and value.startswith("gAAAAA")
