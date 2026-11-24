import asyncio
import contextlib
import gssapi
import base64
import binascii
import logging
import socket

from . import auth

logger = logging.getLogger(__name__)

AUTH_MECHS = ("XOAUTH2", "OAUTHBEARER", "PLAIN", "LOGIN")
NO_LAYER = 0x01


def sasl_security_layer(ctx: gssapi.SecurityContext, server_token: str, authzid: bytes) -> str:
    unwrapped = ctx.unwrap(server_token)
    s_plain = unwrapped.message
    logger.debug(
        "[GSSAPI-SASL] S: unwrapped SASL token: len=%d, encrypted=%s, qop=%s",
        len(s_plain), unwrapped.encrypted, unwrapped.qop
    )

    if len(s_plain) < 4:
        raise RuntimeError(f"[GSSAPI-SASL] SASL security-layer token too short: {len(s_plain)} bytes")

    s_layers = s_plain[0]
    s_maxbuf = int.from_bytes(s_plain[1:4], "big")
    s_authzid = s_plain[4:]

    logger.debug("[GSSAPI-SASL] S: layers=0x%02x, maxbuf=%d, authzid=%r", s_layers, s_maxbuf, s_authzid)

    if not (s_layers & NO_LAYER):
        raise RuntimeError(f"[GSSAPI-SASL] server does not allow NO_LAYER (layers=0x{s_layers:02x})")

    # 2. Choose our layer + authzid
    c_layers = NO_LAYER
    c_maxbuf = s_maxbuf
    c_authzid = authzid

    c_plain = (
        bytes([c_layers]) +
        c_maxbuf.to_bytes(3, "big") +
        c_authzid
    )
    logger.debug("[GSSAPI-SASL] C: layers=0x%02x, maxbuf=%d, authzid=%r", c_layers, c_maxbuf, c_authzid)

    # 3. Wrap the client plaintext
    wrap_result = ctx.wrap(c_plain, encrypt=False)
    wrapped = wrap_result.message
    logger.debug("[GSSAPI-SASL] C: wrap_result: encrypted=%s", wrap_result.encrypted)

    client_b64 = base64.b64encode(wrapped).decode()
    return client_b64


def parse_xoauth2_payload(payload: bytes) -> tuple[str, str]:
    """
    XOAUTH2 payload (Google-style), format:

        user=<authzid>\x01auth=Bearer <token>\x01\x01
    """
    parts = payload.split(b"\x01")
    authzid = None
    token = None
    for part in parts:
        if part.startswith(b"user="):
            authzid = part[5:].decode()
        elif part.startswith(b"auth="):
            rest = part[5:].decode()
            if rest.startswith("Bearer "):
                token = rest[len("Bearer ") :]
    if not authzid or not token:
        raise ValueError("invalid XOAUTH2 payload")
    return authzid, token


def parse_oauthbearer_payload(payload: bytes) -> tuple[str, str]:
    """
    OAUTHBEARER payload (RFC 7628), typically:

        "n,a=<authzid>,\x01auth=Bearer <token>\x01\x01"
    """
    authzid = None
    token = None
    parts = payload.split(b"\x01")
    for part in parts:
        if b"a=" in part:
            idx = part.find(b"a=")
            rest = part[idx + 2 :]
            rest = rest.rstrip(b",")
            authzid = rest.decode()
        if part.startswith(b"auth="):
            rest = part[5:].decode()
            if rest.startswith("Bearer "):
                token = rest[len("Bearer ") :]
    if not authzid or not token:
        raise ValueError("invalid OAUTHBEARER payload")
    return authzid, token


def parse_plain_payload(payload: bytes) -> tuple[str | None, str, str]:
    """
    Parse SASL PLAIN payload.

    Wire format (RFC 4616):
        message = [authzid] UTF8NUL authcid UTF8NUL passwd

    We return (authzid_or_None, authcid, passwd).
    """
    parts = payload.split(b"\x00")
    if len(parts) != 3:
        raise ValueError(f"invalid PLAIN payload: expected 3 parts, got {len(parts)}")

    authzid_raw, authcid_raw, passwd_raw = parts

    authzid = authzid_raw.decode() if authzid_raw else None
    authcid = authcid_raw.decode()
    passwd = passwd_raw.decode()

    if not authcid:
        raise ValueError("invalid PLAIN payload: missing authcid")
    if not passwd:
        raise ValueError("invalid PLAIN payload: missing passwd")

    return authzid, authcid, passwd


async def sasl_auth_flow(
    mode: str,
    mech: str,
    initial_b64: bytes | str | None,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    ip_address: str
) -> tuple[str | None, str | None, tuple[str | None, str | None]]:
    """
    Shared SASL helper for SMTP + IMAP.

    Handles:
      - XOAUTH2 / OAUTHBEARER  (token, via verify_token)
      - PLAIN / LOGIN          (username/password, via authenticate_password)

    Returns:
      upn, jwt, authzid, (username, password)

    Arguments:
      mode        - "smtp" or "imap" (controls prompts and logging format)
      mech        - SASL mechanism (uppercased)
      initial_b64 - initial | Noneclient response (already bytes, not decoded)

    Raises:
      OIDCError for auth failures (token or password).
      EOFError if the connection has been closed by the client.
      Any other exception for unexpected issues.
    """
    mech = mech.upper()
    upn: str | None = None
    jwt: str | None = None
    claims: dict[str, any] | None = None
    username: str | None = None
    authzid: str | None = None
    password: str | None = None

    try:
        #
        # SASL XOAUTH2 / OAUTHBEARER
        #
        if mech in ("XOAUTH2", "OAUTHBEARER"):
            if initial_b64 and initial_b64 != b"=":
                xoauth_raw = base64.b64decode(initial_b64)
            else:
                if mode == "smtp":
                    writer.write(b"334 \r\n")
                    await writer.drain()
                else:  # imap
                    writer.write(b"+ \r\n")
                    await writer.drain()
                line = await reader.readline()
                if not line:
                    raise EOFError()
                line_stripped = line.strip()
                if line_stripped == b"*":
                    raise ValueError("SASL authentication cancelled by client")
                xoauth_raw = base64.b64decode(line_stripped)

            # Parse and verify token
            if mech == "XOAUTH2":
                authzid, access_token = parse_xoauth2_payload(xoauth_raw)
            else:  # OAUTHBEARER
                authzid, access_token = parse_oauthbearer_payload(xoauth_raw)

            jwt = access_token
            claims = auth.oidc.verify(access_token)

        #
        # SASL PLAIN
        #
        elif mech == "PLAIN":
            if initial_b64 and initial_b64 != b"=":
                plain_raw = base64.b64decode(initial_b64)
            else:
                if mode == "smtp":
                    writer.write(b"334 \r\n")
                    await writer.drain()
                else:  # imap
                    writer.write(b"+ \r\n")
                    await writer.drain()
                line = await reader.readline()
                if not line:
                    raise EOFError()
                line_stripped = line.strip()
                if line_stripped == b"*":
                    raise ValueError("SASL authentication cancelled by client")
                plain_raw = base64.b64decode(line_stripped)

            authzid, username, password = parse_plain_payload(plain_raw)

        #
        # SASL LOGIN
        #
        elif mech == "LOGIN":
            if initial_b64 and initial_b64 != b"=":
                username = base64.b64decode(initial_b64).decode()
            else:
                if mode == "smtp":
                    # "334 " + base64("Username:")
                    writer.write(b"334 VXNlcm5hbWU6\r\n")
                    await writer.drain()
                else:  # imap
                    # "+ " + base64("Username:")
                    writer.write(b"+ VXNlcm5hbWU6\r\n")
                    await writer.drain()
                line = await reader.readline()
                if not line:
                    raise EOFError()
                line_stripped = line.strip()
                if line_stripped == b"*":
                    raise ValueError("SASL authentication cancelled by client")
                username = base64.b64decode(line_stripped).decode()

            if mode == "smtp":
                writer.write(b"334 UGFzc3dvcmQ6\r\n")
                await writer.drain()
            else:  # imap
                writer.write(b"+ UGFzc3dvcmQ6\r\n")
                await writer.drain()
            line = await reader.readline()
            if not line:
                raise EOFError()
            line_stripped = line.strip()
            if line_stripped == b"*":
                raise ValueError("SASL authentication cancelled by client")
            password = base64.b64decode(line_stripped).decode()

            if not username:
                raise ValueError("invalid LOGIN payload: missing username")
            if not password:
                raise ValueError("invalid LOGIN payload: missing password")
    except (binascii.Error, UnicodeDecodeError) as e:
        raise ValueError(f"invalid SASL payload: {e}")

    # Password-based verification (PLAIN / LOGIN)
    if username and password:
        json, claims = await auth.password(username, password, ip_address)
        jwt = json["id_token"]

    if claims:
        upn = auth.claims2principal(claims, ip_address)

    if not upn or not jwt:
        raise ValueError("authentication failed: missing principal or token")

    return upn, jwt, authzid, (username, password)


async def imap_login(
    username: str,
    password: str,
    ip_address: str
) -> tuple[str | None, str | None, tuple[str | None, str | None]]:
    if not username:
        raise ValueError("invalid LOGIN payload: missing username")
    if not password:
        raise ValueError("invalid LOGIN payload: missing password")

    json, claims = await auth.password(username, password, ip_address)
    jwt = json["id_token"]

    upn = auth.claims2principal(claims, ip_address)
    return upn, jwt, None, (username, password)


def has_buffered_data(reader: asyncio.StreamReader) -> bool:
    """
    Return True if StreamReader already holds unconsumed bytes.
    Used before STARTTLS to reject pipelined plaintext command injection (CVE-2011-0411).
    """
    return bool(getattr(reader, "_buffer", None))


def enable_tcp_keepalive(writer: asyncio.StreamWriter) -> None:
    """Enable OS-default TCP keepalive probes (Linux default: 2h idle) on a socket."""
    sock = writer.get_extra_info("socket")
    if sock is None:
        return
    with contextlib.suppress(OSError, AttributeError):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)


async def close_writer(writer: asyncio.StreamWriter, timeout: float = 2.0) -> None:
    """
    Close a StreamWriter without blocking indefinitely.

    writer.close() queues a FIN and is non-blocking.
    writer.wait_closed() blocks until the remote peer acknowledges the FIN,
    which can take seconds for an idle or unresponsive client.  We cap the
    wait so shutdown stays snappy.
    """
    with contextlib.suppress(Exception):
        writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=timeout)
    except (asyncio.TimeoutError, Exception):
        pass
