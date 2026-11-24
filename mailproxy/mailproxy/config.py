"""
Configuration loader for mailproxy.

Reads `/etc/msxproxy/mailproxy.toml` (or path from `MAILPROXY_CONFIG` env var /
`--config` CLI flag) using stdlib `tomllib`, with sensible defaults if no file
is present. Supports in-place hot reload via `reload_config()`.
"""
from ipaddress import ip_network
import logging
import os
from pathlib import Path
import tomllib

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = "/etc/msxproxy/mailproxy.toml"
CONFIG_PATH: str = os.environ.get("MAILPROXY_CONFIG", DEFAULT_CONFIG_PATH)

# ---------------------------------------------------------
# Defaults (overridden by mailproxy.toml when present)
# ---------------------------------------------------------

S4U2API_HOST = "127.0.0.1"
S4U2API_PORT = 7777

IMAP_BACKENDS: list[tuple[str, int, bool]] = [
    ("ex19ms01.uni-graz.at", 993, True),
    ("ex19ms02.uni-graz.at", 993, True),
    ("ex19ms03.uni-graz.at", 993, True),
    ("ex19ms04.uni-graz.at", 993, True),
]

IMAP_CAPS: list[str] = [
    "IMAP4",
    "IMAP4rev1",
    "UIDPLUS",
    "MOVE",
    "ID",
    "UNSELECT",
    "CHILDREN",
    "IDLE",
    "NAMESPACE",
    "LITERAL+",
]

SMTP_BACKENDS: list[tuple[str, int, bool]] = [
    ("ex19ms01.uni-graz.at", 587, False),
    ("ex19ms02.uni-graz.at", 587, False),
    ("ex19ms03.uni-graz.at", 587, False),
    ("ex19ms04.uni-graz.at", 587, False),
]

ESMTP_CAPS: list[str] = [
    "SIZE 104857600",
    "PIPELINING",
    "DSN",
    "ENHANCEDSTATUSCODES",
    "X-ANONYMOUSTLS",
    "8BITMIME",
    "BINARYMIME",
    "CHUNKING",
    "XEXCH50",
    "XRDST",
    "XSHADOWREQUEST",
]

OIDC_WELL_KNOWN_URL = "https://login.uni-graz.at/auth/realms/UniGraz/.well-known/openid-configuration"
OIDC_AUDIENCE = "https_webmail.uni-graz.at"
AUTH_CLIENT_ID = "https_webmail.uni-graz.at_DirectGrant"
AUTH_CLIENT_SECRET = ""

TRUSTED_NETWORKS: list = [
    ip_network("143.50.0.0/16"),
    ip_network("10.0.0.0/8"),
]

LISTEN_IMAP_HOST = "0.0.0.0"
LISTEN_IMAP_PORT = 143
LISTEN_IMAPS_HOST = "0.0.0.0"
LISTEN_IMAPS_PORT = 993

LISTEN_SMTP_HOST = "0.0.0.0"
LISTEN_SMTP_PORT = 587
LISTEN_SMTPS_HOST = "0.0.0.0"
LISTEN_SMTPS_PORT = 465

EHLO = "mailproxy.uni-graz.at"
PROXY_HOSTNAME = "mailproxy.uni-graz.at"
AUTH_TIMEOUT = 60

PROXY_CERTS: list[tuple[str, str]] = [
    ("/etc/msxproxy/mailproxy.pem", "/etc/msxproxy/mailproxy.key"),
]

LB_CHECK_INTERVAL = 10.0
LB_FALL = 3
LB_RISE = 2
LB_TIMEOUT = 3.0


def _parse_backends(entries: list) -> list[tuple[str, int, bool]]:
    result = []
    for item in entries:
        if isinstance(item, dict):
            result.append((str(item["host"]), int(item["port"]), bool(item.get("tls", False))))
        else:
            host, port, is_tls = item
            result.append((str(host), int(port), bool(is_tls)))
    return result


def load_config(path: str | Path | None = None, *, required: bool = False) -> bool:
    """
    Load settings from a TOML file and update module globals in-place.
    Lists (`TRUSTED_NETWORKS`, `IMAP_CAPS`, `ESMTP_CAPS`, `IMAP_BACKENDS`,
    `SMTP_BACKENDS`) are mutated in-place so existing imported references stay
    up to date on hot reload.
    """
    global CONFIG_PATH
    global S4U2API_HOST, S4U2API_PORT
    global OIDC_WELL_KNOWN_URL, OIDC_AUDIENCE, AUTH_CLIENT_ID, AUTH_CLIENT_SECRET
    global LISTEN_IMAP_HOST, LISTEN_IMAP_PORT, LISTEN_IMAPS_HOST, LISTEN_IMAPS_PORT
    global LISTEN_SMTP_HOST, LISTEN_SMTP_PORT, LISTEN_SMTPS_HOST, LISTEN_SMTPS_PORT
    global EHLO, PROXY_HOSTNAME, AUTH_TIMEOUT
    global LB_CHECK_INTERVAL, LB_FALL, LB_RISE, LB_TIMEOUT

    cfg_path = Path(path) if path is not None else Path(CONFIG_PATH)
    CONFIG_PATH = str(cfg_path)

    if not cfg_path.is_file():
        if required:
            raise FileNotFoundError(f"mailproxy config file not found: {cfg_path}")
        return False

    with cfg_path.open("rb") as f:
        data = tomllib.load(f)

    s4u = data.get("s4u2api", {})
    if "host" in s4u:
        S4U2API_HOST = str(s4u["host"])
    if "port" in s4u:
        S4U2API_PORT = int(s4u["port"])

    oidc = data.get("oidc", {})
    if "well_known_url" in oidc:
        OIDC_WELL_KNOWN_URL = str(oidc["well_known_url"])
    if "audience" in oidc:
        OIDC_AUDIENCE = str(oidc["audience"])
    if "client_id" in oidc:
        AUTH_CLIENT_ID = str(oidc["client_id"])
    if "client_secret" in oidc:
        AUTH_CLIENT_SECRET = str(oidc["client_secret"])

    proxy = data.get("proxy", {})
    if "hostname" in proxy:
        PROXY_HOSTNAME = str(proxy["hostname"])
    if "ehlo" in proxy:
        EHLO = str(proxy["ehlo"])
    if "auth_timeout" in proxy:
        AUTH_TIMEOUT = int(proxy["auth_timeout"])
    if "certs" in proxy:
        PROXY_CERTS[:] = [(str(c["cert"]), str(c["key"])) for c in proxy["certs"]]
    if "trusted_networks" in proxy:
        TRUSTED_NETWORKS[:] = [ip_network(net) for net in proxy["trusted_networks"]]

    imap = data.get("imap", {})
    if "listen_host" in imap:
        LISTEN_IMAP_HOST = str(imap["listen_host"])
    if "listen_port" in imap:
        LISTEN_IMAP_PORT = int(imap["listen_port"])
    if "imaps_host" in imap:
        LISTEN_IMAPS_HOST = str(imap["imaps_host"])
    if "imaps_port" in imap:
        LISTEN_IMAPS_PORT = int(imap["imaps_port"])
    if "backends" in imap:
        IMAP_BACKENDS[:] = _parse_backends(imap["backends"])
    if "caps" in imap:
        IMAP_CAPS[:] = [str(c) for c in imap["caps"]]

    smtp = data.get("smtp", {})
    if "listen_host" in smtp:
        LISTEN_SMTP_HOST = str(smtp["listen_host"])
    if "listen_port" in smtp:
        LISTEN_SMTP_PORT = int(smtp["listen_port"])
    if "smtps_host" in smtp:
        LISTEN_SMTPS_HOST = str(smtp["smtps_host"])
    if "smtps_port" in smtp:
        LISTEN_SMTPS_PORT = int(smtp["smtps_port"])
    if "backends" in smtp:
        SMTP_BACKENDS[:] = _parse_backends(smtp["backends"])
    if "caps" in smtp:
        ESMTP_CAPS[:] = [str(c) for c in smtp["caps"]]

    lb = data.get("loadbalancer", {})
    if "check_interval" in lb:
        LB_CHECK_INTERVAL = float(lb["check_interval"])
    if "fall" in lb:
        LB_FALL = int(lb["fall"])
    if "rise" in lb:
        LB_RISE = int(lb["rise"])
    if "timeout" in lb:
        LB_TIMEOUT = float(lb["timeout"])

    return True


# Load /etc/msxproxy/mailproxy.toml automatically on import if it exists
load_config()
