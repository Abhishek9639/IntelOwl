# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.choices import PythonModuleBasePaths
from api_app.crypto import ENCRYPTED_PREFIX, decrypt_secret, encrypt_secret
from api_app.models import Parameter, PluginConfig
from tests import CustomTestCase


class EncryptDecryptTestCase(CustomTestCase):
    def test_roundtrip(self):
        for value in ["abc123", 42, ["a", "b"], {"k": "v"}]:
            enc = encrypt_secret(value)
            self.assertTrue(enc.startswith(ENCRYPTED_PREFIX))
            self.assertEqual(decrypt_secret(enc), value)

    def test_prefix(self):
        self.assertTrue(encrypt_secret("x").startswith(ENCRYPTED_PREFIX))

    def test_plain_passthrough(self):
        for val in ["hello", 0, None, [], {}]:
            self.assertEqual(decrypt_secret(val), val)

    def test_no_double_encrypt(self):
        enc = encrypt_secret("test")
        self.assertEqual(encrypt_secret(enc), enc)


class PluginConfigEncryptionTestCase(CustomTestCase):
    def _get_analyzer_config(self):
        return AnalyzerConfig.objects.filter(
            python_module__base_path=PythonModuleBasePaths.FileAnalyzer.value,
        ).first()

    def test_secret_is_encrypted_on_save(self):
        ac = self._get_analyzer_config()
        param = Parameter.objects.create(
            name="test_enc",
            python_module=ac.python_module,
            is_secret=True,
            required=False,
            type="str",
        )
        pc = PluginConfig.objects.create(
            owner=self.user,
            for_organization=False,
            parameter=param,
            value="s3cret",
            analyzer_config=ac,
        )
        try:
            pc.refresh_from_db()
            self.assertTrue(pc.value.startswith(ENCRYPTED_PREFIX))
            self.assertEqual(pc.decrypted_value, "s3cret")
        finally:
            pc.delete()
            param.delete()

    def test_non_secret_stays_plain(self):
        ac = self._get_analyzer_config()
        param = Parameter.objects.create(
            name="test_plain",
            python_module=ac.python_module,
            is_secret=False,
            required=False,
            type="str",
        )
        pc = PluginConfig.objects.create(
            owner=self.user,
            for_organization=False,
            parameter=param,
            value="visible",
            analyzer_config=ac,
        )
        try:
            pc.refresh_from_db()
            self.assertEqual(pc.value, "visible")
            self.assertEqual(pc.decrypted_value, "visible")
        finally:
            pc.delete()
            param.delete()

    def test_decrypted_value(self):
        ac = self._get_analyzer_config()
        param = Parameter.objects.create(
            name="test_dec",
            python_module=ac.python_module,
            is_secret=True,
            required=False,
            type="str",
        )
        pc = PluginConfig.objects.create(
            owner=self.user,
            for_organization=False,
            parameter=param,
            value="tok3n",
            analyzer_config=ac,
        )
        try:
            pc.refresh_from_db()
            self.assertEqual(pc.decrypted_value, "tok3n")
        finally:
            pc.delete()
            param.delete()
