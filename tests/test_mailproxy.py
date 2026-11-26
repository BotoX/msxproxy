"""Unit tests for mailproxy (offline, no Keycloak/Exchange required)."""
import asyncio
import base64
import importlib
import sys
import types
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# Prevent mailproxy.auth from making a live HTTP call to Keycloak on import
def _import_mailproxy_auth_mocked():
    if "mailproxy.auth" in sys.modules:
        return sys.modules["mailproxy.auth"]

    mock_resp_wk = MagicMock()
    mock_resp_wk.json.return_value = {
        "issuer": "https://login.example/realms/test",
        "authorization_endpoint": "https://login.example/auth",
        "token_endpoint": "https://login.example/token",
        "jwks_uri": "https://login.example/jwks",
    }
    mock_resp_jwks = MagicMock()
    mock_resp_jwks.json.return_value = {"keys": [{"kty": "oct", "kid": "test-kid", "k": "c2VjcmV0"}]}

    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client.get.side_effect = [mock_resp_wk, mock_resp_jwks]

    with patch("httpx.Client", return_value=mock_client):
        return importlib.import_module("mailproxy.auth")


mp_auth = _import_mailproxy_auth_mocked()

from mailproxy import config as mp_config  # noqa: E402
from mailproxy import utils as mp_utils  # noqa: E402
from mailproxy.imap_parser import ImapParser  # noqa: E402
from mailproxy.imap_proxy import ImapProxyServer  # noqa: E402
from mailproxy.loadbalancer import Backend, LoadBalancer  # noqa: E402
from mailproxy.metrics import MetricsRegistry, start_metrics_server  # noqa: E402
from mailproxy.smtp_backend import (  # noqa: E402
    read_smtp_multiline_reply,
    smtp_capabilities_from_ehlo,
    smtp_gssapi_auth,
)
from mailproxy.smtp_proxy import SmtpProxyServer  # noqa: E402


class DummyWriter:
    def __init__(self, peername=("203.0.113.10", 12345), is_tls=False):
        self.buf = bytearray()
        self._peername = peername
        self._is_tls = is_tls
        self.closed = False
        self.tls_started = False

    def write(self, data: bytes):
        self.buf.extend(data)

    async def drain(self):
        pass

    def get_extra_info(self, key, default=None):
        if key == "peername":
            return self._peername
        if key == "ssl_object":
            return object() if self._is_tls else None
        return default

    async def start_tls(self, ssl_ctx, server_hostname=None):
        self.tls_started = True
        self._is_tls = True

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


def _reader_with(data: bytes) -> asyncio.StreamReader:
    r = asyncio.StreamReader()
    r.feed_data(data)
    r.feed_eof()
    return r


# ── ImapParser tests ──────────────────────────────────────────────────────────

def test_imap_parser_atoms_quoted_and_literals():
    async def run():
        w = DummyWriter()
        raw = (
            b'A001 LOGIN "alice \\"quoted\\"" {5}\r\nhello\r\n'
            b'A002 LOGIN {4+}\r\nuser {4+}\r\npass\r\n'
        )
        parser = ImapParser(_reader_with(raw), w)

        c1 = await parser.read_command()
        assert c1.tag == "A001"
        assert c1.command == "LOGIN"
        assert c1.args == [b'alice "quoted"', b"hello"]
        assert b"+ \r\n" in w.buf  # synchronous literal sent continuation

        w.buf.clear()
        c2 = await parser.read_command()
        assert c2.tag == "A002"
        assert c2.args == [b"user", b"pass"]
        assert w.buf == b""  # non-synchronous literal sent no continuation

    asyncio.run(run())


def test_imap_parser_rejects_bare_lf_and_oversize_tag():
    async def run():
        p1 = ImapParser(_reader_with(b"A001 CAPABILITY\n"))
        with pytest.raises(RuntimeError, match="bare LF"):
            await p1.read_command()

        p2 = ImapParser(_reader_with(b"A" * 40 + b" CAPABILITY\r\n"))
        with pytest.raises(RuntimeError, match="tag too long"):
            await p2.read_command()

    asyncio.run(run())


# ── SASL parsers & sasl_auth_flow tests ──────────────────────────────────────

def test_sasl_payload_parsers():
    assert mp_utils.parse_xoauth2_payload(b"user=alice@uni.at\x01auth=Bearer tok123\x01\x01") == (
        "alice@uni.at",
        "tok123",
    )
    assert mp_utils.parse_oauthbearer_payload(b"n,a=bob@uni.at,\x01auth=Bearer tok456\x01\x01") == (
        "bob@uni.at",
        "tok456",
    )
    assert mp_utils.parse_plain_payload(b"authz\x00alice\x00s3cr3t") == ("authz", "alice", "s3cr3t")
    assert mp_utils.parse_plain_payload(b"\x00alice\x00s3cr3t") == (None, "alice", "s3cr3t")

    with pytest.raises(ValueError):
        mp_utils.parse_plain_payload(b"\x00alice\x00")
    with pytest.raises(ValueError):
        mp_utils.parse_xoauth2_payload(b"user=alice\x01\x01")


def test_sasl_login_empty_credentials_rejected():
    """Regression test for finding #15: empty LOGIN credentials must raise ValueError."""
    async def run():
        # Empty base64 username & password
        r = _reader_with(b"\r\n\r\n")
        w = DummyWriter()
        with pytest.raises(ValueError, match="missing username"):
            await mp_utils.sasl_auth_flow("smtp", "LOGIN", None, r, w, "203.0.113.10")

        # Valid username, empty password
        r2 = _reader_with(base64.b64encode(b"alice") + b"\r\n\r\n")
        w2 = DummyWriter()
        with pytest.raises(ValueError, match="missing password"):
            await mp_utils.sasl_auth_flow("imap", "LOGIN", None, r2, w2, "203.0.113.10")

    asyncio.run(run())


def test_sasl_cancel_and_invalid_utf8_raise_value_error():
    """Regression test for finding #21: '*' abort and bad UTF-8 raise ValueError cleanly."""
    async def run():
        r = _reader_with(b"*\r\n")
        w = DummyWriter()
        with pytest.raises(ValueError, match="cancelled"):
            await mp_utils.sasl_auth_flow("imap", "PLAIN", None, r, w, "203.0.113.10")

        # Invalid UTF-8 inside valid base64
        bad_b64 = base64.b64encode(b"\xff\xfe\x00user\x00pass")
        r2 = _reader_with(b"")
        w2 = DummyWriter()
        with pytest.raises(ValueError, match="invalid SASL payload"):
            await mp_utils.sasl_auth_flow("smtp", "PLAIN", bad_b64, r2, w2, "203.0.113.10")

    asyncio.run(run())


# ── STARTTLS command injection protection (finding #2) ───────────────────────

def test_starttls_pipelining_rejected_imap_and_smtp():
    async def run():
        # IMAP: client pipelines AUTHENTICATE after STARTTLS in same TCP packet
        imap_srv = ImapProxyServer(lb=MagicMock(), ssl_ctx=MagicMock())
        r_imap = _reader_with(b"A001 STARTTLS\r\nA002 AUTHENTICATE PLAIN\r\n")
        w_imap = DummyWriter(is_tls=False)
        await imap_srv.handle_client(r_imap, w_imap)
        assert not w_imap.tls_started
        assert b"Command pipelining not allowed with STARTTLS" in w_imap.buf

        # SMTP: client pipelines AUTH after STARTTLS in same TCP packet
        smtp_srv = SmtpProxyServer(lb=MagicMock(), ssl_ctx=MagicMock())
        r_smtp = _reader_with(b"STARTTLS\r\nAUTH PLAIN\r\n")
        w_smtp = DummyWriter(is_tls=False)
        await smtp_srv.handle_client(r_smtp, w_smtp)
        assert not w_smtp.tls_started
        assert b"501 5.5.4 Command pipelining not allowed with STARTTLS" in w_smtp.buf

    asyncio.run(run())


def test_smtp_ehlo_omits_pipelining_before_tls():
    async def run():
        smtp_srv = SmtpProxyServer(lb=MagicMock(), ssl_ctx=MagicMock())
        r = _reader_with(b"EHLO client.example\r\nQUIT\r\n")
        w = DummyWriter(is_tls=False)
        await smtp_srv.handle_client(r, w)
        out = w.buf.decode()
        assert "STARTTLS" in out
        assert "PIPELINING" not in out

    asyncio.run(run())


# ── SMTP backend multiline & GSSAPI error handling (finding #18) ─────────────

def test_smtp_multiline_and_gssapi_4xx_fails_immediately():
    async def run():
        lines = await read_smtp_multiline_reply(
            _reader_with(b"250-mail.example\r\n250-STARTTLS\r\n250 8BITMIME\r\n")
        )
        assert smtp_capabilities_from_ehlo(lines) == ["mail.example", "STARTTLS", "8BITMIME"]

        # Backend returns 454 temporary auth failure -> must return (False, ...) immediately
        fake_conn = AsyncMock()
        fake_conn.impersonate.return_value = "dG9rZW4="
        cm = AsyncMock()
        cm.__aenter__.return_value = fake_conn

        with patch("mailproxy.smtp_backend.s4u2api.connection", return_value=cm):
            ok, last = await smtp_gssapi_auth(
                _reader_with(b"454 4.7.0 Temporary authentication failure\r\n"),
                DummyWriter(),
                "alice@EXAMPLE.COM",
                "jwt",
                "smtp",
            )
            assert ok is False
            assert last.startswith("454")

    asyncio.run(run())


# ── Trusted network / ACR policy & secret loading ────────────────────────────

def test_claims2principal_acr_policy():
    claims_direct = {
        "azp": "https_webmail.uni-graz.at_DirectGrant",
        "acr": "password",
        "krb5_principal": "alice@PERS.AD.UNI-GRAZ.AT",
    }
    # External IP without mail-password -> TrustedNetworkError
    with pytest.raises(mp_auth.TrustedNetworkError):
        mp_auth.claims2principal(claims_direct, "203.0.113.5")

    # Trusted IP -> allowed
    assert mp_auth.claims2principal(claims_direct, "10.1.2.3") == "alice@PERS.AD.UNI-GRAZ.AT"

    # External IP with mail-password -> allowed
    claims_mp = dict(claims_direct, acr="mail-password")
    assert mp_auth.claims2principal(claims_mp, "203.0.113.5") == "alice@PERS.AD.UNI-GRAZ.AT"


def test_toml_config_load_and_hot_reload(tmp_path):
    cfg_file = tmp_path / "mailproxy.toml"
    cfg_file.write_text(
        """
[s4u2api]
host = "127.0.0.2"
port = 8888

[oidc]
well_known_url = "https://idp.example/.well-known/openid-configuration"
audience = "aud_test"
client_id = "cid_test"
client_secret = "super_secret_1"

[proxy]
hostname = "mx.example"
ehlo = "mx.example"
auth_timeout = 30
certs = [
    { cert = "/tmp/ec.pem",  key = "/tmp/ec.key" },
    { cert = "/tmp/rsa.pem", key = "/tmp/rsa.key" },
]
trusted_networks = ["192.0.2.0/24"]

[imap]
backends = [{ host = "imap1.example", port = 993, tls = true }]
caps = ["IMAP4rev1", "IDLE"]

[smtp]
backends = [{ host = "smtp1.example", port = 587, tls = false }]
caps = ["SIZE 1024"]

[loadbalancer]
check_interval = 5.0
fall = 2
rise = 1
timeout = 1.5
""",
        encoding="utf-8",
    )

    orig_path = mp_config.CONFIG_PATH
    orig_certs = list(mp_config.PROXY_CERTS)
    orig_nets = list(mp_config.TRUSTED_NETWORKS)
    orig_imap = list(mp_config.IMAP_BACKENDS)
    orig_smtp = list(mp_config.SMTP_BACKENDS)
    orig_icaps = list(mp_config.IMAP_CAPS)
    orig_ecaps = list(mp_config.ESMTP_CAPS)
    orig_s4u = (mp_config.S4U2API_HOST, mp_config.S4U2API_PORT)
    orig_auth = (mp_config.OIDC_WELL_KNOWN_URL, mp_config.OIDC_AUDIENCE, mp_config.AUTH_CLIENT_ID, mp_config.AUTH_CLIENT_SECRET)
    orig_timeout = mp_config.AUTH_TIMEOUT
    try:
        assert mp_config.load_config(cfg_file, required=True) is True
        assert mp_config.S4U2API_HOST == "127.0.0.2"
        assert mp_config.S4U2API_PORT == 8888
        assert mp_config.AUTH_CLIENT_SECRET == "super_secret_1"
        assert mp_config.AUTH_TIMEOUT == 30
        assert mp_config.PROXY_CERTS == [("/tmp/ec.pem", "/tmp/ec.key"), ("/tmp/rsa.pem", "/tmp/rsa.key")]
        assert mp_config.IMAP_BACKENDS == [("imap1.example", 993, True)]
        assert mp_config.SMTP_BACKENDS == [("smtp1.example", 587, False)]
        # TRUSTED_NETWORKS was mutated in-place, so mailproxy.auth sees the new network immediately!
        assert mp_auth.trusted_network("192.0.2.55") is True
        assert mp_auth.trusted_network("10.0.0.1") is False

        # Simulate hot reload updating secret & trusted_networks
        cfg_file.write_text(
            cfg_file.read_text(encoding="utf-8")
            .replace("super_secret_1", "super_secret_2")
            .replace("192.0.2.0/24", "198.51.100.0/24"),
            encoding="utf-8",
        )
        assert mp_config.load_config() is True
        assert mp_auth.trusted_network("198.51.100.7") is True
        assert mp_auth.trusted_network("192.0.2.55") is False

        # reload_from_config refreshes OIDC client credentials & JWKS
        resp_wk = MagicMock()
        resp_wk.json.return_value = {
            "issuer": "https://idp.example",
            "authorization_endpoint": "https://idp.example/auth",
            "token_endpoint": "https://idp.example/token",
            "jwks_uri": "https://idp.example/jwks",
        }
        resp_jwks = MagicMock()
        resp_jwks.json.return_value = {"keys": [{"kty": "oct", "kid": "test-kid", "k": "c2VjcmV0"}]}
        mock_client = MagicMock()
        mock_client.__enter__.return_value = mock_client
        mock_client.get.side_effect = [resp_wk, resp_jwks]
        with patch("httpx.Client", return_value=mock_client):
            mp_auth.oidc.reload_from_config()
        assert mp_auth.oidc.client_secret == "super_secret_2"
        assert mp_auth.oidc.audience == "aud_test"
    finally:
        mp_config.CONFIG_PATH = orig_path
        mp_config.PROXY_CERTS[:] = orig_certs
        mp_config.TRUSTED_NETWORKS[:] = orig_nets
        mp_config.IMAP_BACKENDS[:] = orig_imap
        mp_config.SMTP_BACKENDS[:] = orig_smtp
        mp_config.IMAP_CAPS[:] = orig_icaps
        mp_config.ESMTP_CAPS[:] = orig_ecaps
        mp_config.S4U2API_HOST, mp_config.S4U2API_PORT = orig_s4u
        (
            mp_config.OIDC_WELL_KNOWN_URL,
            mp_config.OIDC_AUDIENCE,
            mp_config.AUTH_CLIENT_ID,
            mp_config.AUTH_CLIENT_SECRET,
        ) = orig_auth
        mp_config.AUTH_TIMEOUT = orig_timeout


# ── LoadBalancer & Prometheus Metrics ────────────────────────────────────────

def test_loadbalancer_rise_and_fall():
    b = Backend("IMAP-LB", "ex01.example", 993, True)
    assert not b.is_up
    b.mark_success(2)
    assert not b.is_up
    b.mark_success(2)
    assert b.is_up
    b.mark_failed(3)
    b.mark_failed(3)
    assert b.is_up
    b.mark_failed(3)
    assert not b.is_up


def test_loadbalancer_hot_reload_preserves_state_and_probes_new():
    async def run():
        lb = LoadBalancer("IMAP-LB", [("ex01.example", 993, True), ("ex02.example", 993, True)])
        lb.backends[0].is_up = True
        lb.backends[1].is_up = True

        # Start a real local listener to represent a newly added healthy backend
        srv = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
        new_port = srv.sockets[0].getsockname()[1]
        try:
            # Remove ex02, keep ex01, add 127.0.0.1:new_port (plain TCP)
            await lb.reload([("ex01.example", 993, True), ("127.0.0.1", new_port, False)])
            keys = [b.key for b in lb.backends]
            assert keys == [("ex01.example", 993, True), ("127.0.0.1", new_port, False)]
            # Kept backend preserved its UP state without flapping; new backend was probed UP
            assert lb.backends[0].is_up is True
            assert lb.backends[1].is_up is True

            # Empty backend list must be rejected (keep previous backends)
            await lb.reload([])
            assert [b.key for b in lb.backends] == keys
        finally:
            srv.close()
            await srv.wait_closed()

    asyncio.run(run())


def test_metrics_registry_and_http_endpoint():
    async def run():
        reg = MetricsRegistry()
        reg.inc("imap", "conn_total", 3)
        reg.inc("imap", "conn_active", 2)
        reg.dec("imap", "conn_active", 1)
        reg.inc("smtp", "auth_ok", 5)

        lb = LoadBalancer("IMAP-LB", [("ex01.example", 993, True)])
        lb.backends[0].is_up = True

        rendered = reg.render([lb])
        assert 'mailproxy_connections_total{protocol="imap"} 3' in rendered
        assert 'mailproxy_connections_active{protocol="imap"} 1' in rendered
        assert 'mailproxy_auth_total{protocol="smtp",result="ok"} 5' in rendered
        assert 'mailproxy_backend_up{pool="imap",backend="ex01.example:993"} 1' in rendered

        srv = await start_metrics_server("127.0.0.1", 0, [lb])
        port = srv.sockets[0].getsockname()[1]
        try:
            r, w = await asyncio.open_connection("127.0.0.1", port)
            w.write(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
            await w.drain()
            resp = await r.read()
            w.close()
            await w.wait_closed()
            assert b"200 OK" in resp
            assert b"mailproxy_connections_total" in resp
            assert b'mailproxy_backend_up{pool="imap",backend="ex01.example:993"} 1' in resp

            r2, w2 = await asyncio.open_connection("127.0.0.1", port)
            w2.write(b"GET /other HTTP/1.1\r\nHost: localhost\r\n\r\n")
            await w2.drain()
            resp2 = await r2.read()
            w2.close()
            await w2.wait_closed()
            assert b"404 Not Found" in resp2
        finally:
            srv.close()
            await srv.wait_closed()

    asyncio.run(run())


def test_dual_ecdsa_and_rsa_cert_loading(tmp_path):
    """Verify _load_certs loads both ECDSA P-384 and RSA-2048 certs onto one SSLContext."""
    import shutil
    import ssl
    import subprocess
    from mailproxy.__main__ import _load_certs

    openssl = shutil.which("openssl")
    if not openssl:
        pytest.skip("openssl not installed")

    ec_cert, ec_key = tmp_path / "ec.pem", tmp_path / "ec.key"
    rsa_cert, rsa_key = tmp_path / "rsa.pem", tmp_path / "rsa.key"

    subprocess.run(
        [
            openssl, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:secp384r1",
            "-keyout", str(ec_key), "-out", str(ec_cert), "-days", "1", "-nodes", "-subj", "/CN=ec.local",
        ],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        [
            openssl, "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(rsa_key), "-out", str(rsa_cert), "-days", "1", "-nodes", "-subj", "/CN=rsa.local",
        ],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )

    orig_certs = list(mp_config.PROXY_CERTS)
    try:
        mp_config.PROXY_CERTS[:] = [(str(ec_cert), str(ec_key)), (str(rsa_cert), str(rsa_key))]
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        _load_certs(ctx)
    finally:
        mp_config.PROXY_CERTS[:] = orig_certs


# ── Shared-memory multi-worker rate limiter tests ────────────────────────────

def test_ratelimit_toml_config_and_hot_reload(tmp_path):
    from ipaddress import ip_network

    orig = (
        mp_config.CONFIG_PATH,
        mp_config.RATELIMIT_ENABLED,
        mp_config.RATELIMIT_BASE_BANTIME,
        mp_config.RATELIMIT_FINDTIME,
        mp_config.RATELIMIT_MAXRETRY,
        mp_config.RATELIMIT_MAX_BANTIME,
        list(mp_config.RATELIMIT_IGNORE_NETWORKS),
    )
    cfg = tmp_path / "mailproxy_rl.toml"
    try:
        cfg.write_text(
            """\
[ratelimit]
enabled = true
base_bantime = 120
findtime = 3600
maxretry = 5
max_bantime = 600
ignore_networks = ["127.0.0.1/32", "2001:db8::/32"]
""",
            encoding="utf-8",
        )
        assert mp_config.load_config(cfg, required=True) is True
        assert mp_config.RATELIMIT_ENABLED is True
        assert mp_config.RATELIMIT_BASE_BANTIME == 120
        assert mp_config.RATELIMIT_FINDTIME == 3600
        assert mp_config.RATELIMIT_MAXRETRY == 5
        assert mp_config.RATELIMIT_MAX_BANTIME == 600
        assert mp_config.RATELIMIT_IGNORE_NETWORKS == [
            ip_network("127.0.0.1/32"),
            ip_network("2001:db8::/32"),
        ]

        # Hot reload disabling rate limiting and clearing ignore_networks
        cfg.write_text(
            """\
[ratelimit]
enabled = false
maxretry = 20
ignore_networks = []
""",
            encoding="utf-8",
        )
        assert mp_config.load_config(cfg, required=True) is True
        assert mp_config.RATELIMIT_ENABLED is False
        assert mp_config.RATELIMIT_MAXRETRY == 20
        assert mp_config.RATELIMIT_IGNORE_NETWORKS == []
    finally:
        (
            mp_config.CONFIG_PATH,
            mp_config.RATELIMIT_ENABLED,
            mp_config.RATELIMIT_BASE_BANTIME,
            mp_config.RATELIMIT_FINDTIME,
            mp_config.RATELIMIT_MAXRETRY,
            mp_config.RATELIMIT_MAX_BANTIME,
            orig_ignore,
        ) = orig
        mp_config.RATELIMIT_IGNORE_NETWORKS[:] = orig_ignore


def test_shared_ratelimiter_bans_multipliers_reset_and_eviction():
    from ipaddress import ip_network
    from mailproxy.ratelimit import SharedRateLimiter

    now = [1_700_000_000.0]
    rl = SharedRateLimiter(num_sets=16, ways=4, time_fn=lambda: now[0])
    assert rl.capacity == 64

    orig = (
        mp_config.RATELIMIT_ENABLED,
        mp_config.RATELIMIT_BASE_BANTIME,
        mp_config.RATELIMIT_FINDTIME,
        mp_config.RATELIMIT_MAXRETRY,
        mp_config.RATELIMIT_MAX_BANTIME,
        list(mp_config.RATELIMIT_IGNORE_NETWORKS),
    )
    try:
        mp_config.RATELIMIT_ENABLED = True
        mp_config.RATELIMIT_BASE_BANTIME = 60
        mp_config.RATELIMIT_FINDTIME = 3600
        mp_config.RATELIMIT_MAXRETRY = 3
        mp_config.RATELIMIT_MAX_BANTIME = 150
        mp_config.RATELIMIT_IGNORE_NETWORKS[:] = []

        ip = "198.51.100.10"
        assert rl.check(ip) == (False, 0)
        assert rl.on_failure(ip) == (False, 0)
        assert rl.on_failure(ip) == (False, 0)
        # 3rd failure triggers ban #1 (1x = 60s)
        assert rl.on_failure(ip) == (True, 60)
        assert rl.check(ip) == (True, 60)
        # IPv4-mapped IPv6 normalizes to the same key
        assert rl.check("::ffff:198.51.100.10") == (True, 60)

        # Advance 25s -> 35s remaining
        now[0] += 25
        assert rl.check(ip) == (True, 35)

        # Expire ban #1
        now[0] += 36
        assert rl.check(ip) == (False, 0)

        # Successful login clears fails but preserves ban count (bans == 1)
        assert rl.on_failure(ip) == (False, 0)
        rl.on_success(ip)
        assert rl.on_failure(ip) == (False, 0)
        assert rl.on_failure(ip) == (False, 0)
        # 3rd failure after on_success triggers ban #2 (2x = 120s)
        assert rl.on_failure(ip) == (True, 120)

        # Expire ban #2 and trigger ban #3 -> capped at max_bantime = 150s (not 180s)
        now[0] += 121
        assert rl.on_failure(ip) == (False, 0)
        assert rl.on_failure(ip) == (False, 0)
        assert rl.on_failure(ip) == (True, 150)

        # Expire entire findtime window -> starts fresh at ban #1 (60s)
        now[0] += 3601
        assert rl.check(ip) == (False, 0)
        for _ in range(2):
            assert rl.on_failure(ip) == (False, 0)
        assert rl.on_failure(ip) == (True, 60)

        # ignore_networks exempts matching IPv4 & IPv6 CIDRs
        mp_config.RATELIMIT_IGNORE_NETWORKS[:] = [
            ip_network("203.0.113.0/24"),
            ip_network("2001:db8:cafe::/48"),
        ]
        for _ in range(10):
            assert rl.on_failure("203.0.113.5") == (False, 0)
            assert rl.on_failure("2001:db8:cafe::1") == (False, 0)
        assert rl.check("203.0.113.5") == (False, 0)
        assert rl.check("2001:db8:cafe::1") == (False, 0)

        # Disabled toggle bypasses checks and recording
        mp_config.RATELIMIT_ENABLED = False
        assert rl.check(ip) == (False, 0)
        assert rl.on_failure("198.51.100.99") == (False, 0)

        # Set-full eviction prefers evicting unbanned entries over actively banned ones
        mp_config.RATELIMIT_ENABLED = True
        mp_config.RATELIMIT_IGNORE_NETWORKS[:] = []
        tiny = SharedRateLimiter(num_sets=1, ways=2, time_fn=lambda: now[0])
        # Ban ip_a (slot 0)
        for _ in range(2):
            tiny.on_failure("198.51.100.1")
        assert tiny.on_failure("198.51.100.1") == (True, 60)
        # Single failure for ip_b (slot 1, unbanned)
        now[0] += 1
        assert tiny.on_failure("198.51.100.2") == (False, 0)
        # Failure for ip_c must evict unbanned ip_b, keeping banned ip_a intact!
        now[0] += 1
        assert tiny.on_failure("198.51.100.3") == (False, 0)
        banned, remaining = tiny.check("198.51.100.1")
        assert banned is True and remaining > 0
    finally:
        (
            mp_config.RATELIMIT_ENABLED,
            mp_config.RATELIMIT_BASE_BANTIME,
            mp_config.RATELIMIT_FINDTIME,
            mp_config.RATELIMIT_MAXRETRY,
            mp_config.RATELIMIT_MAX_BANTIME,
            orig_ignore,
        ) = orig
        mp_config.RATELIMIT_IGNORE_NETWORKS[:] = orig_ignore


def test_shared_ratelimiter_across_forked_workers():
    """Verify failures recorded across separate forked workers share one ban table."""
    import multiprocessing
    from mailproxy.ratelimit import SharedRateLimiter

    rl = SharedRateLimiter(num_sets=64, ways=4)
    orig = (
        mp_config.RATELIMIT_ENABLED,
        mp_config.RATELIMIT_BASE_BANTIME,
        mp_config.RATELIMIT_FINDTIME,
        mp_config.RATELIMIT_MAXRETRY,
        mp_config.RATELIMIT_MAX_BANTIME,
        list(mp_config.RATELIMIT_IGNORE_NETWORKS),
    )
    try:
        mp_config.RATELIMIT_ENABLED = True
        mp_config.RATELIMIT_BASE_BANTIME = 120
        mp_config.RATELIMIT_FINDTIME = 3600
        mp_config.RATELIMIT_MAXRETRY = 4
        mp_config.RATELIMIT_MAX_BANTIME = 300
        mp_config.RATELIMIT_IGNORE_NETWORKS[:] = []

        attacker_ip = "198.51.100.77"
        mp_ctx = multiprocessing.get_context("fork")

        def worker_record(count: int):
            for _ in range(count):
                rl.on_failure(attacker_ip)

        p1 = mp_ctx.Process(target=worker_record, args=(2,))
        p2 = mp_ctx.Process(target=worker_record, args=(2,))
        p1.start()
        p2.start()
        p1.join(timeout=5)
        p2.join(timeout=5)
        assert p1.exitcode == 0 and p2.exitcode == 0

        # Combined 2 + 2 = 4 failures across workers must ban the IP in parent and new workers
        banned, remaining = rl.check(attacker_ip)
        assert banned is True and remaining > 0

        q = mp_ctx.Queue()

        def worker_check():
            q.put(rl.check(attacker_ip))

        p3 = mp_ctx.Process(target=worker_check)
        p3.start()
        p3.join(timeout=5)
        assert p3.exitcode == 0
        w_banned, w_rem = q.get(timeout=2)
        assert w_banned is True and w_rem > 0
    finally:
        (
            mp_config.RATELIMIT_ENABLED,
            mp_config.RATELIMIT_BASE_BANTIME,
            mp_config.RATELIMIT_FINDTIME,
            mp_config.RATELIMIT_MAXRETRY,
            mp_config.RATELIMIT_MAX_BANTIME,
            orig_ignore,
        ) = orig
        mp_config.RATELIMIT_IGNORE_NETWORKS[:] = orig_ignore
