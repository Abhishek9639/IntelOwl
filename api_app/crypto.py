# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

# encryption/decryption utilities for storing secrets at rest

import base64
import hashlib
import json
import logging
from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings

logger = logging.getLogger(__name__)

ENCRYPTED_PREFIX = "enc::"


@lru_cache(maxsize=1)
def _get_fernet() -> Fernet:
    key_material = settings.SECRET_KEY.encode()
    # Fernet needs a 32-byte url-safe base64-encoded key
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        key_material,
        salt=b"intelowl-secrets-encryption",
        iterations=100_000,
    )
    fernet_key = base64.urlsafe_b64encode(derived[:32])
    return Fernet(fernet_key)


def encrypt_secret(value) -> str:
    if isinstance(value, str) and value.startswith(ENCRYPTED_PREFIX):
        return value

    plaintext = json.dumps(value).encode()
    token = _get_fernet().encrypt(plaintext)
    return ENCRYPTED_PREFIX + token.decode()


def decrypt_secret(value):
    if not isinstance(value, str) or not value.startswith(ENCRYPTED_PREFIX):
        return value

    token = value[len(ENCRYPTED_PREFIX) :].encode()
    try:
        plaintext = _get_fernet().decrypt(token)
        return json.loads(plaintext)
    except (InvalidToken, json.JSONDecodeError):
        logger.error("failed to decrypt secret, returning raw value")
        return value
