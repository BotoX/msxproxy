import os
import secrets
from pathlib import Path


# auth.py
OIDC_WELL_KNOWN_URL = 'https://login.uni-graz.at/auth/realms/UniGraz/.well-known/openid-configuration'
OIDC_AUDIENCE = 'https_webmail.uni-graz.at'

# logic.py
VALID_SPNS = {
    'http': 'http/email.uni-graz.at@PERS.AD.UNI-GRAZ.AT',
    'imap': 'imap/email.uni-graz.at@PERS.AD.UNI-GRAZ.AT',
    'smtp': 'smtp/email.uni-graz.at@PERS.AD.UNI-GRAZ.AT',
}

VALKEY_SOCK = '/dev/shm/valkey.sock'
CACHE_SECRET = secrets.token_bytes(32)


# kerberos.py
cred_dir = os.environ.get('CREDENTIALS_DIRECTORY')
if cred_dir:
    KRB5_CLIENT_KTNAME = str(Path(cred_dir) / 'krb5_keytab')
else:
    KRB5_CLIENT_KTNAME = 'FILE:/root/_msxproxy.keytab'

KRB5_PRINCIPAL = '_msxproxy@PERS.AD.UNI-GRAZ.AT'
KRB5_CCACHE_DIR = '/dev/shm/krb5_msxproxy'
