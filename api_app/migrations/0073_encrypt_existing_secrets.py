# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import migrations


def encrypt_existing_secrets(apps, schema_editor):
    from api_app.crypto import ENCRYPTED_PREFIX, encrypt_secret

    PluginConfig = apps.get_model("api_app", "PluginConfig")
    for pc in PluginConfig.objects.filter(parameter__is_secret=True):
        if pc.value is not None and not (isinstance(pc.value, str) and pc.value.startswith(ENCRYPTED_PREFIX)):
            pc.value = encrypt_secret(pc.value)
            pc.save(update_fields=["value"])


def decrypt_existing_secrets(apps, schema_editor):
    from api_app.crypto import ENCRYPTED_PREFIX, decrypt_secret

    PluginConfig = apps.get_model("api_app", "PluginConfig")
    for pc in PluginConfig.objects.filter(parameter__is_secret=True):
        if pc.value is not None and isinstance(pc.value, str) and pc.value.startswith(ENCRYPTED_PREFIX):
            pc.value = decrypt_secret(pc.value)
            pc.save(update_fields=["value"])


class Migration(migrations.Migration):
    dependencies = [
        ("api_app", "0071_delete_last_elastic_report"),
    ]

    operations = [
        migrations.RunPython(
            encrypt_existing_secrets,
            reverse_code=decrypt_existing_secrets,
        ),
    ]
