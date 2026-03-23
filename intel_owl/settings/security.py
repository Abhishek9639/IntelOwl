# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

# Security Stuff
import base64
import hashlib

from django.core.management.utils import get_random_secret_key

from ._util import get_secret
from .commons import STAGE_LOCAL, WEB_CLIENT_DOMAIN

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = get_secret("DJANGO_SECRET", None) or get_random_secret_key()

# Encryption key for PluginConfig secrets stored in the database.
# You can set PLUGIN_CONFIG_SECRET_KEY env var to use a custom key.
# Falls back to SECRET_KEY so existing deployments work out of the box.
_plugin_secret_raw = get_secret("PLUGIN_CONFIG_SECRET_KEY", SECRET_KEY)
PLUGIN_CONFIG_FERNET_KEY = base64.urlsafe_b64encode(hashlib.sha256(_plugin_secret_raw.encode()).digest())

HTTPS_ENABLED = get_secret("HTTPS_ENABLED", False) == "True"
if HTTPS_ENABLED:
    CSRF_COOKIE_SECURE = True
    SESSION_COOKIE_SECURE = True
    WEB_CLIENT_URL = f"https://{WEB_CLIENT_DOMAIN}"
else:
    WEB_CLIENT_URL = f"http://{WEB_CLIENT_DOMAIN}"

CSRF_COOKIE_SAMESITE = "Strict"
CSRF_TRUSTED_ORIGINS = [f"{WEB_CLIENT_URL}"]

if STAGE_LOCAL:
    # required to allow requests from port 3001 (frontend development)
    CSRF_TRUSTED_ORIGINS = [f"{WEB_CLIENT_URL}:80/"]
ALLOWED_HOSTS = ["*"]

# https://docs.djangoproject.com/en/4.2/ref/settings/#data-upload-max-memory-size
DATA_UPLOAD_MAX_MEMORY_SIZE = 100 * (10**6)
FILE_UPLOAD_MAX_MEMORY_SIZE = 100 * (10**6)
