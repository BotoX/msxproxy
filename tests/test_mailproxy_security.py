"""
Security, protocol state-machine, fuzzing, and concurrency tests for mailproxy.

Designed to exercise security boundaries and catch regressions or unknown bugs
in protocol parsing, auth isolation, TLS enforcement, timeouts, and TCP relay.
"""
import asyncio
import base64
import random
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mailproxy import auth as mp_auth
from mailproxy import config as mp_config
from mailproxy import utils as mp_utils
from mailproxy.imap_backend import imap_ensure_tls, imap_gssapi_auth
from mailproxy.imap_parser import ImapParser
from mailproxy.imap_proxy import ImapProxyServer
from mailproxy.relay import relay
from mailproxy.smtp_backend import smtp_ensure_tls_and_ehlo, smtp_gssapi_auth
from mailproxy.smtp_proxy import SmtpProxyServer


class MockWriter:
    def __init__(self, peername=("203.0.113.42", 54321), is_tls=False):
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


def _reader(data: bytes) -> asyncio.StreamReader:
    r = asyncio.StreamReader()
    r.feed_data(data)
    r.feed_eof()
    return r


# ── 1. Pre-auth command smuggling & state-machine enforcement ─────────────────

@pytest.mark.parametrize(
    "cmd_bytes",
    [
        b"A1 SELECT INBOX\r\n",
        b"A1 FETCH 1:* BODY[]\r\n",
        b"A1 APPEND INBOX {3+}\r\nabc\r\n",
        b"A1 IDLE\r\n",
        b"A1 EXPUNGE\r\n",
        b"A1 LIST \"\" \"*\"\r\n",
    ],
)
def test_imap_rejects_post_auth_commands_before_auth(cmd_bytes):
    async def run():
        lb = MagicMock()
        srv = ImapProxyServer(lb=lb, ssl_ctx=MagicMock())
        w = MockWriter(is_tls=True)
        await srv.handle_client(_reader(cmd_bytes + b"A2 LOGOUT\r\n"), w)
        out = w.buf.decode()
        assert "A1 BAD Authentication required" in out
        lb.connect.assert_not_called()

    asyncio.run(run())


def test_imap_enforces_tls_before_all_auth_mechanisms():
    async def run():
        lb = MagicMock()
        srv = ImapProxyServer(lb=lb, ssl_ctx=MagicMock())
        raw = (
            b"A1 CAPABILITY\r\n"
            b"A2 LOGIN alice secret\r\n"
            b"A3 AUTHENTICATE PLAIN\r\n"
            b"A4 AUTHENTICATE XOAUTH2\r\n"
            b"A5 AUTHENTICATE OAUTHBEARER\r\n"
            b"A6 AUTHENTICATE LOGIN\r\n"
            b"A7 LOGOUT\r\n"
        )
        w = MockWriter(is_tls=False)
        await srv.handle_client(_reader(raw), w)
        out = w.buf.decode()
        assert "LOGINDISABLED" in out
        assert "STARTTLS" in out
        assert "AUTH=PLAIN" not in out
        for tag in ("A2", "A3", "A4", "A5", "A6"):
            assert f"{tag} NO [PRIVACYREQUIRED]" in out
        lb.connect.assert_not_called()

    asyncio.run(run())


def test_imap_rejects_double_starttls_and_unsupported_mech():
    async def run():
        srv = ImapProxyServer(lb=MagicMock(), ssl_ctx=MagicMock())
        raw = (
            b"A1 STARTTLS\r\n"
            b"A2 AUTHENTICATE CRAM-MD5\r\n"
            b"A3 AUTHENTICATE\r\n"
            b"A4 LOGIN onlyuser\r\n"
            b"A5 LOGOUT\r\n"
        )
        w = MockWriter(is_tls=True)
        await srv.handle_client(_reader(raw), w)
        out = w.buf.decode()
        assert "A1 BAD Already encrypted" in out
        assert "A2 NO Unsupported SASL mechanism" in out
        assert "A3 BAD Missing auth mechanism" in out
        assert "A4 BAD LOGIN requires username and password" in out

    asyncio.run(run())


@pytest.mark.parametrize(
    "cmd_bytes,expected",
    [
        (b"MAIL FROM:<attacker@evil.example>\r\n", b"530 5.7.0 Authentication required"),
        (b"RCPT TO:<victim@uni-graz.at>\r\n", b"530 5.7.0 Authentication required"),
        (b"DATA\r\n", b"530 5.7.0 Authentication required"),
        (b"BDAT 10 LAST\r\n", b"530 5.7.0 Authentication required"),
        (b"VRFY admin\r\n", b"252 2.5.2 Cannot VRFY; authenticate first"),
        (b"EXPN staff\r\n", b"502 5.5.2 Command not recognized"),
        (b"AUTH PLAIN dGVzdA==\r\n", b"538 5.7.11 Encryption required"),
    ],
)
def test_smtp_blocks_relay_and_cleartext_auth(cmd_bytes, expected):
    async def run():
        lb = MagicMock()
        srv = SmtpProxyServer(lb=lb, ssl_ctx=MagicMock())
        w = MockWriter(is_tls=False)
        await srv.handle_client(_reader(cmd_bytes + b"QUIT\r\n"), w)
        assert expected in w.buf
        lb.connect.assert_not_called()

    asyncio.run(run())


def test_smtp_rejects_double_starttls_and_unsupported_mech():
    async def run():
        srv = SmtpProxyServer(lb=MagicMock(), ssl_ctx=MagicMock())
        raw = (
            b"STARTTLS\r\n"
            b"AUTH CRAM-MD5\r\n"
            b"AUTH\r\n"
            b"QUIT\r\n"
        )
        w = MockWriter(is_tls=True)
        with patch("asyncio.sleep", new_callable=AsyncMock):
            await srv.handle_client(_reader(raw), w)
        out = w.buf.decode()
        assert "502 5.5.1 Already encrypted" in out
        assert "504 5.7.4 Unrecognized authentication type" in out
        assert "501 5.5.4 Syntax: AUTH mechanism" in out

    asyncio.run(run())


# ── 2. ImapParser boundary & fuzz testing ────────────────────────────────────

@pytest.mark.parametrize(
    "payload",
    [
        b"",                                   # immediate EOF
        b"A1 LOGIN {999999999}\r\n",           # huge literal length
        b"A1 LOGIN {4097+}\r\n" + b"a" * 4097 + b"\r\n",  # 1 byte over 4096 limit
        b"A1 LOGIN {-1}\r\n",                  # negative literal
        b"A1 LOGIN {}\r\n",                    # empty literal length
        b"A1 LOGIN {4+x}\r\n",                 # garbage after +
        b"A1 LOGIN " + b" ".join([b"a"] * 9) + b"\r\n",  # >8 args
        b'A1 LOGIN "' + b"x" * 4097 + b'"\r\n',           # >4096 quoted string
        b"A1 LOGIN " + b"x" * 4097 + b"\r\n",             # >4096 atom
        b"A1 " + b"X" * 33 + b"\r\n",                     # >32 command
        b"A1 LOGIN \xff\xfe\r\n",                         # non-UTF-8 in tag/cmd vs atom
        b"\xff\xfe LOGIN a b\r\n",                        # non-UTF-8 tag
        b"A1 LOGIN \"unterminated\\",                     # backslash at EOF
        b"A1 LOGIN {10+}\r\nshort",                       # truncated literal EOF
        b"A1\rX",                                         # CR without LF in tag
        b"A1 CMD\rX",                                     # CR without LF in command
        b"A1 CMD arg\rX",                                 # CR without LF in atom
    ],
)
def test_imap_parser_adversarial_inputs_never_crash_unhandled(payload):
    async def run():
        p = ImapParser(_reader(payload), MockWriter())
        try:
            await p.read_command()
        except (RuntimeError, ValueError, asyncio.IncompleteReadError):
            pass

    asyncio.run(run())


def test_imap_parser_boundary_exact_limits_succeed():
    async def run():
        # Exact 4096-byte literal and exact 8 arguments must succeed
        data_4096 = b"Z" * 4096
        p1 = ImapParser(_reader(b"A1 LOGIN {4096+}\r\n" + data_4096 + b"\r\n"), MockWriter())
        cmd1 = await p1.read_command()
        assert cmd1.args == [data_4096]

        # Exact 0-byte literal must succeed
        p2 = ImapParser(_reader(b"A2 LOGIN {0+}\r\n\r\n"), MockWriter())
        cmd2 = await p2.read_command()
        assert cmd2.args == [b""]

        # Random binary fuzzing (50 seeded inputs): must only raise expected parser errors
        rng = random.Random(1337)
        for _ in range(50):
            fuzz = bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 256)))
            pf = ImapParser(_reader(fuzz), MockWriter())
            try:
                await pf.read_command()
            except (RuntimeError, ValueError, asyncio.IncompleteReadError):
                pass

    asyncio.run(run())


# ── 3. AuthZ isolation: client-supplied authzid must NEVER impersonate another mailbox ──

def test_gssapi_backend_ignores_attacker_authzid():
    """Even if a client sends authzid=admin in SASL PLAIN/XOAUTH2, backend GSSAPI sends authzid=b''."""
    async def run():
        fake_ctx = MagicMock()
        # Server offers NO_LAYER (0x01) + maxbuf 4096
        fake_ctx.unwrap.return_value = MagicMock(message=b"\x01\x00\x10\x00", encrypted=False, qop=0)
        captured_plain = []
        def fake_wrap(msg, encrypt=False):
            captured_plain.append(msg)
            return MagicMock(message=b"wrapped", encrypted=False)
        fake_ctx.wrap.side_effect = fake_wrap

        fake_s4u = AsyncMock()
        fake_s4u.impersonate.return_value = "aW5pdA=="
        fake_s4u.complete = True
        fake_s4u.ctx = fake_ctx
        cm = AsyncMock()
        cm.__aenter__.return_value = fake_s4u

        # IMAP GSSAPI
        be_reader_imap = _reader(
            b"+ " + base64.b64encode(b"srv_sec_layer") + b"\r\n"
            b"B001 OK AUTHENTICATE completed\r\n"
        )
        with patch("mailproxy.imap_backend.s4u2api.connection", return_value=cm):
            await imap_gssapi_auth(be_reader_imap, MockWriter(), "alice@UNI.AT", "jwt", "imap")

        # SMTP GSSAPI
        be_reader_smtp = _reader(
            b"334 " + base64.b64encode(b"srv_sec_layer") + b"\r\n"
            b"235 2.7.0 Authentication successful\r\n"
        )
        with patch("mailproxy.smtp_backend.s4u2api.connection", return_value=cm):
            ok, _ = await smtp_gssapi_auth(be_reader_smtp, MockWriter(), "alice@UNI.AT", "jwt", "smtp")
            assert ok is True

        # Both wrapped SASL security layer payloads must have empty authzid (exactly 4 bytes)
        assert len(captured_plain) == 2
        for msg in captured_plain:
            assert len(msg) == 4, f"Unexpected non-empty authzid in SASL wrap: {msg!r}"
            assert msg[0] == 0x01  # NO_LAYER

    asyncio.run(run())


def test_sasl_security_layer_rejects_short_and_no_nolayer_tokens():
    ctx_short = MagicMock()
    ctx_short.unwrap.return_value = MagicMock(message=b"\x01\x00", encrypted=False, qop=0)
    with pytest.raises(RuntimeError, match="too short"):
        mp_utils.sasl_security_layer(ctx_short, b"tok", b"")

    ctx_enc_only = MagicMock()
    ctx_enc_only.unwrap.return_value = MagicMock(message=b"\x04\x00\x10\x00", encrypted=False, qop=0)
    with pytest.raises(RuntimeError, match="NO_LAYER"):
        mp_utils.sasl_security_layer(ctx_enc_only, b"tok", b"")


# ── 4. Network / IPv6 / ACR edge cases ───────────────────────────────────────

@pytest.mark.parametrize(
    "ip,expected",
    [
        ("143.50.1.2", True),
        ("10.255.0.1", True),
        ("143.51.0.1", False),
        ("192.168.1.1", False),
        ("127.0.0.1", False),
        ("2001:db8::1", False),
        ("::ffff:10.0.0.1", False),  # IPv4-mapped IPv6 must NOT bypass IPv4 CIDR check
    ],
)
def test_trusted_network_ipv4_and_ipv6(ip, expected):
    assert mp_auth.trusted_network(ip) is expected


def test_claims2principal_edge_cases():
    # Non-DirectGrant OAuth token (azp does not end with _DirectGrant) allowed externally
    oauth_claims = {"azp": "https_webmail.uni-graz.at", "acr": "1", "krb5_principal": "alice@UNI.AT"}
    assert mp_auth.claims2principal(oauth_claims, "203.0.113.1") == "alice@UNI.AT"

    # Case-sensitivity: ACR "MAIL-PASSWORD" != "mail-password"
    wrong_case = {"azp": "app_DirectGrant", "acr": "MAIL-PASSWORD", "krb5_principal": "alice@UNI.AT"}
    with pytest.raises(mp_auth.TrustedNetworkError):
        mp_auth.claims2principal(wrong_case, "203.0.113.1")

    # Missing krb5_principal
    with pytest.raises(ValueError, match="krb5_principal"):
        mp_auth.claims2principal({"azp": "app_DirectGrant", "acr": "mail-password"}, "10.0.0.1")


# ── 5. Slowloris / AUTH_TIMEOUT enforcement & backend TLS downgrade rejection ─

def test_imap_and_smtp_enforce_auth_timeout():
    async def run():
        orig = mp_config.AUTH_TIMEOUT
        mp_config.AUTH_TIMEOUT = 0.05
        try:
            # Hung client that never sends anything
            r1 = asyncio.StreamReader()
            w1 = MockWriter()
            await ImapProxyServer(MagicMock(), MagicMock()).handle_client(r1, w1)
            assert b"* BYE Timeout" in w1.buf and w1.closed

            r2 = asyncio.StreamReader()
            w2 = MockWriter()
            await SmtpProxyServer(MagicMock(), MagicMock()).handle_client(r2, w2)
            assert b"421 4.4.2 Timeout" in w2.buf and w2.closed
        finally:
            mp_config.AUTH_TIMEOUT = orig

    asyncio.run(run())


def test_backend_refuses_cleartext_downgrade_and_pipelined_starttls():
    async def run():
        # IMAP backend does NOT advertise STARTTLS -> must refuse
        r_no_tls = _reader(
            b"* OK Exchange ready\r\n"
            b"* CAPABILITY IMAP4rev1 AUTH=GSSAPI\r\n"
            b"B001 OK CAPABILITY completed\r\n"
        )
        with pytest.raises(RuntimeError, match="does not advertise STARTTLS"):
            await imap_ensure_tls(r_no_tls, MockWriter(is_tls=False), "ex01", MagicMock())

        # IMAP backend sends pipelined data after STARTTLS OK -> must refuse
        r_pipe = _reader(
            b"* OK Exchange ready\r\n"
            b"* CAPABILITY IMAP4rev1 STARTTLS\r\n"
            b"B001 OK CAPABILITY completed\r\n"
            b"B002 OK Begin TLS\r\n"
            b"* INJECTED PLAINTEXT\r\n"
        )
        with pytest.raises(RuntimeError, match="unexpected pipelined data"):
            await imap_ensure_tls(r_pipe, MockWriter(is_tls=False), "ex01", MagicMock())

        # SMTP backend does NOT advertise STARTTLS -> must refuse
        r_smtp_no_tls = _reader(
            b"220 ex01 ESMTP\r\n"
            b"250-ex01\r\n"
            b"250 AUTH GSSAPI\r\n"
        )
        with pytest.raises(RuntimeError, match="does not support STARTTLS"):
            await smtp_ensure_tls_and_ehlo(r_smtp_no_tls, MockWriter(is_tls=False), "ex01", MagicMock(), "proxy")

        # SMTP backend injects bytes after 220 Ready -> must refuse
        r_smtp_pipe = _reader(
            b"220 ex01 ESMTP\r\n"
            b"250-ex01\r\n"
            b"250 STARTTLS\r\n"
            b"220 2.0.0 Ready\r\n"
            b"250 INJECTED\r\n"
        )
        with pytest.raises(RuntimeError, match="unexpected pipelined data"):
            await smtp_ensure_tls_and_ehlo(r_smtp_pipe, MockWriter(is_tls=False), "ex01", MagicMock(), "proxy")

    asyncio.run(run())


# ── 6. TCP relay binary integrity, graceful half-close drain & cancellation ──

def test_relay_binary_integrity_and_graceful_drain():
    async def run():
        payload_c2s = bytes(range(256)) * 512  # 128 KiB binary with NULs & CRLFs
        payload_s2c = b"* BYE Exchange signing off\r\n" + bytes(reversed(range(256))) * 256
        received_on_be = bytearray()

        async def fake_backend(r, w):
            data = await r.readexactly(len(payload_c2s))
            received_on_be.extend(data)
            w.write(payload_s2c)
            await w.drain()
            w.close()
            await w.wait_closed()

        be_srv = await asyncio.start_server(fake_backend, "127.0.0.1", 0)
        be_port = be_srv.sockets[0].getsockname()[1]

        async def proxy_handler(c_r, c_w):
            b_r, b_w = await asyncio.open_connection("127.0.0.1", be_port)
            try:
                await relay(c_r, c_w, b_r, b_w, drain_timeout=2.0)
            finally:
                b_w.close()
                c_w.close()

        px_srv = await asyncio.start_server(proxy_handler, "127.0.0.1", 0)
        px_port = px_srv.sockets[0].getsockname()[1]

        try:
            cr, cw = await asyncio.open_connection("127.0.0.1", px_port)
            cw.write(payload_c2s)
            await cw.drain()
            received_on_client = await cr.read()
            cw.close()
            await cw.wait_closed()

            assert bytes(received_on_be) == payload_c2s
            assert received_on_client == payload_s2c
        finally:
            px_srv.close()
            be_srv.close()
            await px_srv.wait_closed()
            await be_srv.wait_closed()

    asyncio.run(run())


# ── 7. Built-in rate limiter enforcement & exclusions on IMAP & SMTP ─────────

def test_imap_and_smtp_ratelimit_enforcement_and_exclusions():
    """
    Verify:
    - Repeated invalid credentials trigger ban on IMAP, immediately closing the
      connection with `* BYE`, and reject subsequent SMTP connections from the
      same IP on connect with `421 4.7.0`.
    - TrustedNetworkError and base OIDCError (Keycloak outage) do NOT count
      toward rate-limit bans.
    """
    from mailproxy.auth import OIDCError, TrustedNetworkError, UnauthorizedError
    from mailproxy.ratelimit import ratelimit

    orig = (
        mp_config.RATELIMIT_ENABLED,
        mp_config.RATELIMIT_BASE_BANTIME,
        mp_config.RATELIMIT_FINDTIME,
        mp_config.RATELIMIT_MAXRETRY,
        mp_config.RATELIMIT_MAX_BANTIME,
        list(mp_config.RATELIMIT_IGNORE_NETWORKS),
    )

    async def run():
        ratelimit.reset()
        mp_config.RATELIMIT_ENABLED = True
        mp_config.RATELIMIT_BASE_BANTIME = 120
        mp_config.RATELIMIT_FINDTIME = 3600
        mp_config.RATELIMIT_MAXRETRY = 2
        mp_config.RATELIMIT_MAX_BANTIME = 300
        mp_config.RATELIMIT_IGNORE_NETWORKS[:] = []

        imap_srv = ImapProxyServer(lb=MagicMock(), ssl_ctx=MagicMock())
        smtp_srv = SmtpProxyServer(lb=MagicMock(), ssl_ctx=MagicMock())

        # 1. TrustedNetworkError must NOT trigger a ban even after > maxretry attempts
        with patch("mailproxy.imap_proxy.imap_login", new=AsyncMock(side_effect=TrustedNetworkError())), \
             patch("mailproxy.imap_proxy.asyncio.sleep", new=AsyncMock()):
            r = _reader(
                b"A1 LOGIN alice regularpw\r\n"
                b"A2 LOGIN alice regularpw\r\n"
                b"A3 LOGIN alice regularpw\r\n"
                b"A4 LOGOUT\r\n"
            )
            w = MockWriter(is_tls=True, peername=("198.51.100.50", 40001))
            await imap_srv.handle_client(r, w)
            assert b"AUTHORIZATIONFAILED" in w.buf
            assert b"Too many failed authentication attempts" not in w.buf
            assert ratelimit.check("198.51.100.50") == (False, 0)

        # 2. Base OIDCError (Keycloak outage) must NOT trigger a ban
        with patch("mailproxy.imap_proxy.imap_login", new=AsyncMock(side_effect=OIDCError("Keycloak down"))), \
             patch("mailproxy.imap_proxy.asyncio.sleep", new=AsyncMock()):
            r = _reader(
                b"A1 LOGIN alice pw\r\n"
                b"A2 LOGIN alice pw\r\n"
                b"A3 LOGIN alice pw\r\n"
                b"A4 LOGOUT\r\n"
            )
            w = MockWriter(is_tls=True, peername=("198.51.100.51", 40002))
            await imap_srv.handle_client(r, w)
            assert b"[UNAVAILABLE] Authentication service temporarily unavailable" in w.buf
            assert ratelimit.check("198.51.100.51") == (False, 0)

        # 3. Invalid credentials (UnauthorizedError) trigger ban on 2nd failure,
        #    immediately closing IMAP with `* BYE` and rejecting SMTP on connect!
        with patch("mailproxy.imap_proxy.imap_login", new=AsyncMock(side_effect=UnauthorizedError("bad pw"))), \
             patch("mailproxy.imap_proxy.asyncio.sleep", new=AsyncMock()):
            r = _reader(
                b"A1 LOGIN alice bad1\r\n"
                b"A2 LOGIN alice bad2\r\n"
                b"A3 LOGIN alice bad3\r\n"
            )
            w = MockWriter(is_tls=True, peername=("198.51.100.60", 40003))
            await imap_srv.handle_client(r, w)
            assert b"A1 NO [AUTHENTICATIONFAILED]" in w.buf
            assert b"A2 NO [AUTHENTICATIONFAILED]" in w.buf
            assert b"* BYE [UNAVAILABLE] Too many failed authentication attempts" in w.buf
            # Connection closed immediately after A2 -> A3 never processed
            assert b"A3 " not in w.buf
            banned, rem = ratelimit.check("198.51.100.60")
            assert banned is True and rem > 0

        # Subsequent SMTP connection from the SAME banned IP is rejected immediately on connect
        r_smtp = _reader(b"EHLO attacker.example\r\n")
        w_smtp = MockWriter(is_tls=True, peername=("198.51.100.60", 40004))
        await smtp_srv.handle_client(r_smtp, w_smtp)
        assert b"421 4.7.0 Too many failed authentication attempts" in w_smtp.buf
        assert b"220 " not in w_smtp.buf

    try:
        asyncio.run(run())
    finally:
        ratelimit.reset()
        (
            mp_config.RATELIMIT_ENABLED,
            mp_config.RATELIMIT_BASE_BANTIME,
            mp_config.RATELIMIT_FINDTIME,
            mp_config.RATELIMIT_MAXRETRY,
            mp_config.RATELIMIT_MAX_BANTIME,
            orig_ignore,
        ) = orig
        mp_config.RATELIMIT_IGNORE_NETWORKS[:] = orig_ignore
