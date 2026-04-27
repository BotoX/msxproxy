import asyncio
import ssl
import base64
import logging

from .s4u2api import s4u2api
from .utils import sasl_security_layer

logger = logging.getLogger(__name__)


async def read_smtp_multiline_reply(reader: asyncio.StreamReader) -> list[str]:
    """
    Read a (possibly multi-line) SMTP reply and return all text lines.
    """
    lines: list[str] = []
    line = await reader.readline()
    if not line:
        raise RuntimeError("SMTP connection closed while waiting for reply")
    s = line.decode().rstrip("\r\n")
    lines.append(s)
    logger.debug("SMTP RAW: %s", s)

    if len(s) < 4 or not s[:3].isdigit():
        return lines

    code = s[:3]
    # single-line if '250 ' (space); multi-line if '250-'
    if len(s) >= 4 and s[3] == " ":
        return lines

    # multi-line: 250-... until 250 <text>
    while True:
        line = await reader.readline()
        if not line:
            break
        s = line.decode().rstrip("\r\n")
        lines.append(s)
        logger.debug("SMTP RAW: %s", s)
        if len(s) >= 4 and s[:3] == code and s[3] == " ":
            break
    return lines


def smtp_capabilities_from_ehlo(lines: list[str]) -> list[str]:
    """
    Parse EHLO reply lines into a list of 'CAPABILITY [arg]' strings.
    """
    caps: list[str] = []
    for line in lines:
        if len(line) < 4 or not line[:3].isdigit():
            continue
        # strip "250-" or "250 "
        rest = line[4:].strip()
        if rest:
            caps.append(rest)
    return caps


async def smtp_ensure_tls_and_ehlo(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    hostname: str,
    ssl_context: ssl.SSLContext,
    ehlo_name: str
) -> list[str]:
    """
    Ensure the connection to the SMTP backend is under TLS, using either:

    - Already implicit TLS (if the socket is wrapped by SSL), or
    - Plain TCP upgraded via STARTTLS, if advertised.

    Steps:

    1. Read 220 greeting (possibly multi-line).
    2. If already TLS (implicit), just send EHLO and return capabilities.
    3. If not TLS:
       * send EHLO
       * if STARTTLS is advertised:
           - send STARTTLS
           - on 220, upgrade to TLS
           - send EHLO again over TLS
           - return TLS capabilities
         else:
           - raise (we do not allow cleartext backend).
    """
    # 1) Greeting
    greet_lines = await read_smtp_multiline_reply(reader)
    for gl in greet_lines:
        logger.debug("SMTP backend greeting: %s", gl)

    # Check if we are already under TLS
    is_tls = writer.get_extra_info("ssl_object") is not None

    if is_tls:
        logger.info("SMTP backend connection is already TLS (implicit). Sending EHLO.")
        ehlo_cmd = f"EHLO {ehlo_name}\r\n"
        writer.write(ehlo_cmd.encode())
        logger.debug("SMTP send: %s", ehlo_cmd.strip())
        await writer.drain()

        ehlo_lines = await read_smtp_multiline_reply(reader)
        for el in ehlo_lines:
            logger.debug("SMTP backend EHLO (TLS): %s", el)
        return smtp_capabilities_from_ehlo(ehlo_lines)

    # Not TLS yet: do initial EHLO in clear to detect STARTTLS.
    ehlo_cmd = f"EHLO {ehlo_name}\r\n"
    writer.write(ehlo_cmd.encode())
    logger.debug("SMTP send: %s", ehlo_cmd.strip())
    await writer.drain()

    ehlo_lines = await read_smtp_multiline_reply(reader)
    for el in ehlo_lines:
        logger.debug("SMTP backend EHLO (pre-TLS): %s", el)

    caps = smtp_capabilities_from_ehlo(ehlo_lines)
    logger.debug("SMTP pre-TLS caps: %r", caps)

    if not any(c.upper().startswith("STARTTLS") for c in caps):
        # We refuse to proceed without TLS
        raise RuntimeError("SMTP backend does not support STARTTLS; cleartext is not allowed")

    # 3) STARTTLS
    starttls_cmd = "STARTTLS\r\n"
    writer.write(starttls_cmd.encode())
    logger.debug("SMTP send: %s", starttls_cmd.strip())
    await writer.drain()

    line = await reader.readline()
    if not line:
        raise RuntimeError("SMTP backend closed after STARTTLS")
    resp = line.decode().rstrip("\r\n")
    logger.debug("SMTP STARTTLS response: %s", resp)
    if not resp.startswith("220"):
        raise RuntimeError(f"SMTP STARTTLS failed: {resp}")

    # 4) Upgrade to TLS
    await writer.start_tls(ssl_context, server_hostname=hostname)
    logger.info("SMTP STARTTLS completed; connection upgraded to TLS")

    # 5) EHLO again over TLS
    ehlo_cmd = f"EHLO {ehlo_name}\r\n"
    writer.write(ehlo_cmd.encode())
    logger.debug("SMTP send (TLS EHLO): %s", ehlo_cmd.strip())
    await writer.drain()

    ehlo_tls_lines = await read_smtp_multiline_reply(reader)
    for el in ehlo_tls_lines:
        logger.debug("SMTP backend EHLO (TLS): %s", el)

    tls_caps = smtp_capabilities_from_ehlo(ehlo_tls_lines)
    logger.debug("SMTP TLS caps: %r", tls_caps)
    return tls_caps


async def smtp_gssapi_auth(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    upn: str,
    jwt: str,
    spn: str
) -> tuple[bool, str]:
    """
    Perform SMTP AUTH GSSAPI against the backend, including the SASL
    security layer negotiation. Assumes connection is already under TLS.
    """
    async with s4u2api.connection() as s4u2api_conn:
        first_b64 = await s4u2api_conn.impersonate(upn, jwt, spn)
        if not first_b64:
            raise RuntimeError("GSSAPI SMTP: no initial token")

        cmd = f"AUTH GSSAPI {first_b64}\r\n"
        writer.write(cmd.encode())
        logger.debug("SMTP GSSAPI send: %s", cmd.strip())
        await writer.drain()

        security_layer_done = False
        while True:
            line = await reader.readline()
            if not line:
                raise RuntimeError("SMTP backend closed during AUTH GSSAPI")
            line_str = line.decode().rstrip("\r\n")
            logger.debug("SMTP GSSAPI recv: %r", line_str)

            if line_str.startswith("235 "):
                logger.info("GSSAPI SMTP auth succeeded for %r", upn)
                return True, line_str
            if line_str.startswith("535 "):
                return False, line_str

            if not line_str.startswith("334 "):
                # Unexpected line, ignore or raise; we log and continue to be conservative.
                logger.warning("Unexpected SMTP response during GSSAPI: %r", line_str)
                continue

            server_b64 = line_str[4:].strip()
            if not server_b64:
                # Empty challenge, treat as continuation with empty token.
                server_token = b""
            else:
                server_token = base64.b64decode(server_b64)

            if not s4u2api_conn.complete:
                # AP-REQ / AP-REP / context negotiation
                out_token = await s4u2api_conn.step(server_token)
                if out_token:
                    client_b64 = base64.b64encode(out_token).decode()
                    writer.write((client_b64 + "\r\n").encode())
                else:
                    writer.write(b"\r\n")
                await writer.drain()
                continue

            if not security_layer_done:
                authzid = b""
                client_b64 = sasl_security_layer(s4u2api_conn.ctx, server_token, authzid)
                writer.write((client_b64 + "\r\n").encode())
                logger.debug("[GSSAPI-SMTP] sent client wrapped security-layer response: %s", client_b64)
                await writer.drain()
                security_layer_done = True
                continue

            logger.debug("[GSSAPI-SMTP] extra continuation after security layer, ignoring")


async def smtp_login_auth(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    username: str,
    password: str,
) -> tuple[bool, str]:
    """
    Perform SMTP AUTH LOGIN against the backend. Assumes the connection
    is already under TLS and after EHLO where 'AUTH LOGIN' is advertised.
    """
    # 1) Send AUTH LOGIN
    cmd = "AUTH LOGIN\r\n"
    logger.debug("SMTP LOGIN send: %r", cmd.strip())
    writer.write(cmd.encode())
    await writer.drain()

    # 2) Expect "334 VXNlcm5hbWU6"
    line = await reader.readline()
    if not line:
        logger.error("SMTP backend closed during AUTH LOGIN (username prompt)")
        return False, ""
    line_str = line.decode().rstrip("\r\n")
    logger.debug("SMTP LOGIN recv (username prompt): %r", line_str)

    if not line_str.startswith("334"):
        logger.warning("Unexpected response to AUTH LOGIN: %r", line_str)
        return False, line_str

    # 3) Send base64(username)
    user_b64 = base64.b64encode(username.encode()).decode()
    writer.write((user_b64 + "\r\n").encode())
    logger.debug("SMTP LOGIN send username (b64): %r", user_b64)
    await writer.drain()

    # 4) Expect "334 UGFzc3dvcmQ6"
    line = await reader.readline()
    if not line:
        logger.error("SMTP backend closed during AUTH LOGIN (password prompt)")
        return False, ""
    line_str = line.decode().rstrip("\r\n")
    logger.debug("SMTP LOGIN recv (password prompt): %r", line_str)

    if not line_str.startswith("334"):
        logger.warning("Unexpected response after username in AUTH LOGIN: %r", line_str)
        return False, line_str

    # 5) Send base64(password)
    pwd_b64 = base64.b64encode(password.encode()).decode()
    writer.write((pwd_b64 + "\r\n").encode())
    logger.debug("SMTP LOGIN send password (b64): %r", pwd_b64)
    await writer.drain()

    # 6) Read final response (235 or 535/5xx)
    line = await reader.readline()
    if not line:
        logger.error("SMTP backend closed after AUTH LOGIN password")
        return False, ""
    line_str = line.decode().rstrip("\r\n")
    logger.debug("SMTP LOGIN final recv: %r", line_str)

    ok = line_str.startswith("235 ")
    if ok:
        logger.info("SMTP AUTH LOGIN succeeded for username=%r", username)
    else:
        logger.warning("SMTP AUTH LOGIN failed for username=%r: %s", username, line_str)

    return ok, line_str
