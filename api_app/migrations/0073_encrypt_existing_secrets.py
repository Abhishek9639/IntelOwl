# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""
Data migration to encrypt existing plaintext secret values
in the PluginConfig table.
"""

from django.db import migrations


def encrypt_existing_secrets(apps, schema_editor):
    """
    Encrypt all existing PluginConfig values where the
    associated Parameter has is_secret=True.
    """
    from api_app.crypto import encrypt_secret, is_encrypted

    PluginConfig = apps.get_model("api_app", "PluginConfig")
    secret_configs = PluginConfig.objects.filter(
        parameter__is_secret=True,
    ).exclude(value__isnull=True)

    count = 0
    for config in secret_configs:
        if not is_encrypted(config.value):
            config.value = encrypt_secret(config.value)
            # Use update to bypass the model's save() which
            # would try to double-encrypt
            PluginConfig.objects.filter(pk=config.pk).update(
                value=config.value,
            )
            count += 1

    if count:
        print(f"  Encrypted {count} existing secret value(s).")


def decrypt_existing_secrets(apps, schema_editor):
    """
    Reverse migration: decrypt all encrypted secret values
    back to plaintext.
    """
    from api_app.crypto import decrypt_secret, is_encrypted

    PluginConfig = apps.get_model("api_app", "PluginConfig")
    secret_configs = PluginConfig.objects.filter(
        parameter__is_secret=True,
    ).exclude(value__isnull=True)

    count = 0
    for config in secret_configs:
        if is_encrypted(config.value):
            config.value = decrypt_secret(config.value)
            PluginConfig.objects.filter(pk=config.pk).update(
                value=config.value,
            )
            count += 1

    if count:
        print(f"  Decrypted {count} secret value(s).")


class Migration(migrations.Migration):
    dependencies = [
        ("api_app", "0071_delete_last_elastic_report"),
    ]

    operations = [
        migrations.RunPython(
            encrypt_existing_secrets,
            decrypt_existing_secrets,
        ),
    ]
