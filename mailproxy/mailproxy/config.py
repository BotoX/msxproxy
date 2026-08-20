from ipaddress import ip_network

# ---------------------------------------------------------
# S4U2Api
# ---------------------------------------------------------

S4U2API_HOST = "127.0.0.1"
S4U2API_PORT = "7777"

# ---------------------------------------------------------
# Exchange hosts / ports / caps
# ---------------------------------------------------------

# IMAP
IMAP_BACKENDS = [ # host, port, is_tls
    ("ex19ms01.uni-graz.at", 993, True),
    ("ex19ms02.uni-graz.at", 993, True),
    ("ex19ms03.uni-graz.at", 993, True),
    ("ex19ms04.uni-graz.at", 993, True)
]

IMAP_CAPS = [
    "IMAP4",
    "IMAP4rev1",
    "UIDPLUS",
    "MOVE",
    "ID",
    "UNSELECT",
    "CHILDREN",
    "IDLE",
    "NAMESPACE",
    "LITERAL+"
]

# SMTP
SMTP_BACKENDS = [ # host, port, is_tls
    ("ex19ms01.uni-graz.at", 587, False),
    ("ex19ms02.uni-graz.at", 587, False),
    ("ex19ms03.uni-graz.at", 587, False),
    ("ex19ms04.uni-graz.at", 587, False)
]

ESMTP_CAPS = [
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
    "XSHADOWREQUEST"
]

# ---------------------------------------------------------
# Keycloak / JWT / Authentication
# ---------------------------------------------------------

OIDC_WELL_KNOWN_URL = "https://login.uni-graz.at/auth/realms/UniGraz/.well-known/openid-configuration"
OIDC_AUDIENCE = "https_webmail.uni-graz.at"
AUTH_CLIENT_ID = "https_webmail.uni-graz.at_DirectGrant"
AUTH_CLIENT_SECRET = "***"

TRUSTED_NETWORKS = [
    ip_network("143.50.0.0/16"),
    ip_network("10.0.0.0/8")
]

# ---------------------------------------------------------
# Proxy listening addresses
# ---------------------------------------------------------

# IMAP
LISTEN_IMAP_HOST = "0.0.0.0"     # STARTTLS-capable/plain port
LISTEN_IMAP_PORT = 143
LISTEN_IMAPS_HOST = "0.0.0.0"    # implicit TLS
LISTEN_IMAPS_PORT =  993

# SMTP
LISTEN_SMTP_HOST = "0.0.0.0"     # STARTTLS-capable/plain port
LISTEN_SMTP_PORT = 587
LISTEN_SMTPS_HOST = "0.0.0.0"    # implicit TLS
LISTEN_SMTPS_PORT = 465

# ---------------------------------------------------------
# Proxy misc
# ---------------------------------------------------------

# EHLO / server name for outbound SMTP (what proxy presents to Exchange)
EHLO = "mailproxy.uni-graz.at"

# Public-facing hostname of the proxy for IMAP/SMTP greetings
PROXY_HOSTNAME = "mailproxy.uni-graz.at"

# Close unauthenticated connections after this timeout
AUTH_TIMEOUT = 60

# ---------------------------------------------------------
# TLS cert for clients connecting to proxy
# ---------------------------------------------------------

PROXY_CERT_FILE = "mailproxy.pem"
PROXY_KEY_FILE = "mailproxy.key"

# ---------------------------------------------------------
# Load Balancer
# ---------------------------------------------------------
LB_CHECK_INTERVAL = 10.0  # 'inter': Seconds between active health checks
LB_FALL = 3               # 'fall': Consecutive failures to mark DOWN
LB_RISE = 2               # 'rise': Consecutive successes to mark UP
LB_TIMEOUT = 3.0          # Health check connection timeout
