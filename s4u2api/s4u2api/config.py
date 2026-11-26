"""
Configuration loader for s4u2api.

Reads `/etc/msxproxy/s4u2api.toml` (or path from `S4U2API_CONFIG` env var)
using stdlib `tomllib`, with defaults if no file is present.
The Kerberos keytab prefers systemd `CREDENTIALS_DIRECTORY/krb5_keytab`.
"""
import os
from pathlib import Path
import secrets
import tomllib

DEFAULT_CONFIG_PATH = "/etc/msxproxy/s4u2api.toml"
CONFIG_PATH: str = os.environ.get("S4U2API_CONFIG", DEFAULT_CONFIG_PATH)

# server (__main__.py)
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 7777
SERVER_UDS: str | None = None

# auth.py
OIDC_WELL_KNOWN_URL = "https://login.uni-graz.at/auth/realms/UniGraz/.well-known/openid-configuration"
OIDC_AUDIENCE = "https_webmail.uni-graz.at"

# logic.py
VALID_SPNS: dict[str, str] = {
    "http": "http/email.uni-graz.at@PERS.AD.UNI-GRAZ.AT",
}

VALKEY_SOCK = "/dev/shm/valkey.sock"
CACHE_SECRET = secrets.token_bytes(32)

# kerberos.py
KRB5_PRINCIPAL = "_msxproxy@PERS.AD.UNI-GRAZ.AT"
KRB5_CCACHE_DIR = "/dev/shm/krb5_msxproxy"
KRB5_CLIENT_KTNAME = "FILE:/etc/msxproxy/krb5_keytab"


def load_config(path: str | Path | None = None, *, required: bool = False) -> bool:
    global CONFIG_PATH
    global SERVER_HOST, SERVER_PORT, SERVER_UDS
    global OIDC_WELL_KNOWN_URL, OIDC_AUDIENCE, VALKEY_SOCK
    global KRB5_PRINCIPAL, KRB5_CCACHE_DIR, KRB5_CLIENT_KTNAME

    cfg_path = Path(path) if path is not None else Path(CONFIG_PATH)
    CONFIG_PATH = str(cfg_path)

    if cfg_path.is_file():
        with cfg_path.open("rb") as f:
            data = tomllib.load(f)

        srv = data.get("server", {})
        if "host" in srv:
            SERVER_HOST = str(srv["host"])
        if "port" in srv:
            SERVER_PORT = int(srv["port"])
        if "uds" in srv:
            raw_uds = str(srv["uds"]).strip()
            SERVER_UDS = raw_uds or None

        oidc = data.get("oidc", {})
        if "well_known_url" in oidc:
            OIDC_WELL_KNOWN_URL = str(oidc["well_known_url"])
        if "audience" in oidc:
            OIDC_AUDIENCE = str(oidc["audience"])

        valkey = data.get("valkey", {})
        if "socket" in valkey:
            VALKEY_SOCK = str(valkey["socket"])

        krb = data.get("kerberos", {})
        if "principal" in krb:
            KRB5_PRINCIPAL = str(krb["principal"])
        if "ccache_dir" in krb:
            KRB5_CCACHE_DIR = str(krb["ccache_dir"])
        if "keytab" in krb:
            KRB5_CLIENT_KTNAME = str(krb["keytab"])

        if "valid_spns" in data:
            VALID_SPNS.clear()
            VALID_SPNS.update({str(k): str(v) for k, v in data["valid_spns"].items()})
        loaded = True
    else:
        if required:
            raise FileNotFoundError(f"s4u2api config file not found: {cfg_path}")
        loaded = False

    # Systemd LoadCredential always takes precedence for the Kerberos keytab
    cred_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    if cred_dir:
        cred_kt = Path(cred_dir) / "krb5_keytab"
        if cred_kt.is_file():
            KRB5_CLIENT_KTNAME = str(cred_kt)

    return loaded


load_config()
