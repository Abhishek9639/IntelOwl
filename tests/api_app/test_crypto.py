# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from unittest.mock import patch

from django.test import TestCase, override_settings

from api_app.crypto import (
    decrypt_secret,
    encrypt_secret,
    get_encryption_key,
    is_encrypted,
)


TEST_ENCRYPTION_KEY = "test-secret-key-for-unit-tests"


@override_settings(
    SECRET_KEY=TEST_ENCRYPTION_KEY,
    SECRETS_ENCRYPTION_KEY=None,
)
class CryptoUtilsTestCase(TestCase):
    """Tests for the encryption/decryption utilities."""

    def test_get_encryption_key_returns_bytes(self):
        key = get_encryption_key()
        self.assertIsInstance(key, bytes)
        # Fernet keys are 44 bytes when base64-encoded
        self.assertEqual(len(key), 44)

    def test_encrypt_decrypt_roundtrip_string(self):
        original = "my-secret-api-key"
        encrypted = encrypt_secret(original)
        decrypted = decrypt_secret(encrypted)
        self.assertEqual(decrypted, original)

    def test_encrypt_decrypt_roundtrip_integer(self):
        original = 42
        encrypted = encrypt_secret(original)
        decrypted = decrypt_secret(encrypted)
        self.assertEqual(decrypted, original)

    def test_encrypt_decrypt_roundtrip_list(self):
        original = ["key1", "key2", "key3"]
        encrypted = encrypt_secret(original)
        decrypted = decrypt_secret(encrypted)
        self.assertEqual(decrypted, original)

    def test_encrypt_decrypt_roundtrip_dict(self):
        original = {"api_key": "abc123", "timeout": 30}
        encrypted = encrypt_secret(original)
        decrypted = decrypt_secret(encrypted)
        self.assertEqual(decrypted, original)

    def test_encrypted_value_is_not_plaintext(self):
        original = "super-secret-key"
        encrypted = encrypt_secret(original)
        self.assertNotEqual(encrypted, original)
        self.assertNotIn("super-secret-key", encrypted)

    def test_is_encrypted_true(self):
        encrypted = encrypt_secret("test")
        self.assertTrue(is_encrypted(encrypted))

    def test_is_encrypted_false_for_plaintext(self):
        self.assertFalse(is_encrypted("just-a-string"))
        self.assertFalse(is_encrypted(42))
        self.assertFalse(is_encrypted(None))
        self.assertFalse(is_encrypted(["list"]))

    def test_decrypt_with_wrong_key_raises(self):
        encrypted = encrypt_secret("test-value")
        with patch(
            "api_app.crypto.get_encryption_key",
            return_value=get_encryption_key(),
        ):
            # First verify it works with same key
            self.assertEqual(
                decrypt_secret(encrypted), "test-value"
            )

    def test_encrypt_produces_different_ciphertext(self):
        """Each encryption should produce unique ciphertext
        (Fernet uses a random IV)."""
        val = "same-value"
        enc1 = encrypt_secret(val)
        enc2 = encrypt_secret(val)
        # Both should decrypt to same value
        self.assertEqual(decrypt_secret(enc1), val)
        self.assertEqual(decrypt_secret(enc2), val)
        # But ciphertexts should differ (random IV)
        self.assertNotEqual(enc1, enc2)

    def test_uses_secrets_encryption_key_when_set(self):
        """When SECRETS_ENCRYPTION_KEY is set, it should
        be used instead of SECRET_KEY."""
        with override_settings(
            SECRETS_ENCRYPTION_KEY="custom-encryption-key",
        ):
            key1 = get_encryption_key()

        with override_settings(
            SECRETS_ENCRYPTION_KEY=None,
            SECRET_KEY="a-different-secret-key",
        ):
            key2 = get_encryption_key()

        self.assertNotEqual(key1, key2)
