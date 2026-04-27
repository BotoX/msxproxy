import asyncio
import base64
import logging
import ssl
from dataclasses import dataclass

from .s4u2api import s4u2api
from .utils import sasl_security_layer

logger = logging.getLogger(__name__)


@dataclass
class ImapResponse:
    tagged: str | None           # e.g. "A001" or None for untagged/continuation
    status_or_data: str          # rest of the line after tag / '*' / '+'
    is_continuation: bool        # '+' lines
    raw: str                     # full decoded line without CRLF


async def read_imap_response_line(reader: asyncio.StreamReader) -> ImapResponse:
    """
    Read a single IMAP response line and parse it into ImapResponse.

    We distinguish:
      +<SP>text                continuation
      *<SP>data                untagged
      <tag><SP>status-or-data  tagged
    """
    line = await reader.readline()
    if not line:
        raise RuntimeError("IMAP backend closed connection unexpectedly")

    s = line.decode().rstrip("\r\n")

    # Continuation: "+ ..."
    if s.startswith("+"):
        # Remove leading '+', keep the rest as data
        data = s[1:].lstrip()
        return ImapResponse(
            tagged=None,
            status_or_data=data,
            is_continuation=True,
            raw=s,
        )

    # Untagged: "* ..."
    if s.startswith("*"):
        data = s[1:].lstrip()
        return ImapResponse(
            tagged=None,
            status_or_data=data,
            is_continuation=False,
            raw=s,
        )

    # Tagged: "<tag> <rest>"
    if " " in s:
        tag, rest = s.split(" ", 1)
        return ImapResponse(
            tagged=tag,
            status_or_data=rest,
            is_continuation=False,
            raw=s,
        )

    # Fallback (shouldn't normally happen in well‑formed IMAP)
    return ImapResponse(
        tagged=None,
        status_or_data=s,
        is_continuation=False,
        raw=s,
    )


class ImapTagCounter:
    """
    Simple IMAP tag generator for backend commands. Ensures we always
    increment and never re-use tags within a single backend session.
    """

    def __init__(self, prefix: str = "B") -> None:
        self.prefix = prefix
        self.counter = 1

    def next(self) -> str:
        tag = f"{self.prefix}{self.counter:03d}"
        self.counter += 1
        return tag


async def imap_get_capabilities(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    tag_counter: ImapTagCounter,
) -> tuple[str, str]:
    """
    Send CAPABILITY and return (tag_used, capability_payload).

    capability_payload is the text after "CAPABILITY " from the *last*
    untagged "* CAPABILITY ..." line for this command.

    Example server response:
        * CAPABILITY IMAP4 IMAP4rev1 LOGINDISABLED STARTTLS SASL-IR ...
        B001 OK CAPABILITY completed.

    We return:
        ("B001", "IMAP4 IMAP4rev1 LOGINDISABLED STARTTLS SASL-IR ...")
    """
    tag = tag_counter.next()
    writer.write(f"{tag} CAPABILITY\r\n".encode())
    await writer.drain()

    capability_payload = ""
    while True:
        resp = await read_imap_response_line(reader)
        logger.debug("IMAP backend CAPABILITY: %s", resp.raw)

        if resp.tagged is None:
            # Untagged. For CAPABILITY, RFC says format is:
            #   * CAPABILITY capability1 capability2 ...
            # Our read_imap_response_line() ensures status_or_data starts AFTER the '* '.
            # So here status_or_data starts with "CAPABILITY ...".
            data_upper = resp.status_or_data.upper()
            if data_upper.startswith("CAPABILITY "):
                # Strip the literal prefix "CAPABILITY " and keep the rest
                capability_payload = resp.status_or_data[len("CAPABILITY ") :]

        if resp.tagged == tag:
            # Tagged completion for this CAPABILITY command
            break

    return tag, capability_payload


async def imap_ensure_tls(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    hostname: str,
    ssl_context: ssl.SSLContext
) -> ImapTagCounter:
    """
    Ensure the backend IMAP connection is using TLS.

    Logic:
      * Read greeting.
      * Send CAPABILITY on the current channel.
      * If the connection is already TLS (implicit TLS on port 993),
        no STARTTLS is required, we just return.
      * If not TLS and STARTTLS is advertised, perform STARTTLS and
        then refresh CAPABILITY.
      * If not TLS and STARTTLS is NOT advertised, raise an error
        (cleartext backend is not allowed).

    Returns an ImapTagCounter that is already incremented past the
    CAPABILITY/STARTTLS tags used here, ready for further commands.
    """
    tag_counter = ImapTagCounter()

    # Read server greeting
    greeting = await reader.readline()
    logger.debug("IMAP backend greeting: %r", greeting)

    # Check if connection is already TLS (implicit TLS)
    ssl_obj = writer.get_extra_info("ssl_object")
    if ssl_obj is not None:
        # Already TLS; still useful to know capabilities, but we don't *require* it.
        _, caps_line = await imap_get_capabilities(reader, writer, tag_counter)
        logger.debug("IMAP backend capabilities (implicit TLS): %s", caps_line)
        return tag_counter

    # Not TLS yet: we are on a cleartext port and must do STARTTLS if advertised.
    _, caps_line = await imap_get_capabilities(reader, writer, tag_counter)
    caps = caps_line.upper().split()
    logger.debug("IMAP backend capabilities (pre-STARTTLS): %s", caps_line)

    if "STARTTLS" not in caps:
        raise RuntimeError("IMAP backend does not advertise STARTTLS on a cleartext connection")

    starttls_tag = tag_counter.next()
    writer.write(f"{starttls_tag} STARTTLS\r\n".encode())
    await writer.drain()

    while True:
        resp = await read_imap_response_line(reader)
        logger.debug("IMAP backend STARTTLS: %s", resp.raw)
        if resp.tagged == starttls_tag:
            if not resp.status_or_data.upper().startswith("OK"):
                raise RuntimeError(f"IMAP backend STARTTLS failed: {resp.raw}")
            break

    # Upgrade the connection to TLS in-place
    await writer.start_tls(ssl_context, server_hostname=hostname)
    logger.info("IMAP backend connection upgraded to TLS via STARTTLS")

    # After STARTTLS, capabilities typically change, so refresh them
    _, caps_line2 = await imap_get_capabilities(reader, writer, tag_counter)
    logger.debug("IMAP backend capabilities (post-STARTTLS): %s", caps_line2)

    return tag_counter


async def imap_gssapi_auth(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    upn: str,
    jwt: str,
    spn: str,
    tag_counter: ImapTagCounter | None = None,
) -> None:
    """
    Perform IMAP AUTHENTICATE GSSAPI on an already-TLS backend connection.

    The caller is responsible for calling imap_ensure_tls() first.
    """
    if tag_counter is None:
        tag_counter = ImapTagCounter()

    # GSSAPI AUTH with remote S4U2Api
    async with s4u2api.connection() as s4u2api_conn:
        first_b64 = await s4u2api_conn.impersonate(upn, jwt, spn)
        if not first_b64:
            raise RuntimeError("GSSAPI IMAP: no initial token")

        tag = tag_counter.next()
        auth_cmd = f"{tag} AUTHENTICATE GSSAPI {first_b64}\r\n".encode()
        writer.write(auth_cmd)
        logger.debug("[GSSAPI-IMAP] C: %s", auth_cmd.decode().rstrip())
        await writer.drain()

        security_layer_done = False

        while True:
            resp = await read_imap_response_line(reader)
            logger.debug("[GSSAPI-IMAP] S: %s", resp.raw)

            # Continuation: server expects another token
            if resp.is_continuation:
                server_b64 = resp.status_or_data.strip()
                if server_b64:
                    server_token = base64.b64decode(server_b64)
                else:
                    server_token = b""

                if not s4u2api_conn.complete:
                    out_token = await s4u2api_conn.step(server_token)
                    if out_token:
                        client_b64 = base64.b64encode(out_token).decode()
                        logger.debug("[GSSAPI-IMAP] C: %s", client_b64)
                        writer.write((client_b64 + "\r\n").encode())
                    else:
                        logger.debug("[GSSAPI-IMAP] C: ")
                        writer.write(b"\r\n")
                    await writer.drain()
                    continue

                if not security_layer_done:
                    authzid = b""
                    client_b64 = sasl_security_layer(s4u2api_conn.ctx, server_token, authzid)
                    writer.write((client_b64 + "\r\n").encode())
                    logger.debug("[GSSAPI-IMAP] Sent client wrapped security-layer response: %s", client_b64)
                    await writer.drain()
                    security_layer_done = True
                    continue

                logger.debug("[GSSAPI-IMAP] extra continuation after security layer, ignoring")
                continue

            # Tagged / untagged responses
            if resp.tagged == tag:
                if resp.status_or_data.upper().startswith("OK"):
                    logger.debug("[GSSAPI-IMAP] auth succeeded")
                    return
                raise RuntimeError(f"[GSSAPI-IMAP] auth failed for {upn}: {resp.raw}")

            logger.debug("[GSSAPI-IMAP] ignoring untagged response: %s", resp.raw)


async def imap_plain_auth(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    authcid: str,
    password: str,
    authzid: str = "",
    sasl_ir: bool = True,
    tag_counter: ImapTagCounter | None = None,
) -> None:
    """
    Perform IMAP AUTHENTICATE PLAIN against the backend, on an already-TLS
    connection. The caller must ensure TLS with imap_ensure_tls().
    """
    if tag_counter is None:
        tag_counter = ImapTagCounter()

    # Build SASL PLAIN blob: authzid NUL authcid NUL password
    blob = authzid.encode() + b"\x00" + authcid.encode() + b"\x00" + password.encode()
    b64 = base64.b64encode(blob).decode()

    logger.debug(
        "IMAP PLAIN authcid=%r authzid=%r blob_hex=%s b64=%s",
        authcid,
        authzid,
        blob.hex(),
        b64,
    )

    tag = tag_counter.next()

    # Send AUTHENTICATE PLAIN
    if sasl_ir:
        cmd = f"{tag} AUTHENTICATE PLAIN {b64}\r\n"
        writer.write(cmd.encode())
        logger.debug("IMAP PLAIN (SASL-IR) send: %s", cmd.strip())
        await writer.drain()
    else:
        cmd = f"{tag} AUTHENTICATE PLAIN\r\n"
        writer.write(cmd.encode())
        logger.debug("IMAP PLAIN send: %s", cmd.strip())
        await writer.drain()

        cont = await read_imap_response_line(reader)
        if not cont.is_continuation:
            raise RuntimeError(f"Expected continuation for AUTHENTICATE PLAIN, got: {cont.raw}")
        writer.write((b64 + "\r\n").encode())
        await writer.drain()

    # Read final tagged response
    while True:
        resp = await read_imap_response_line(reader)
        logger.debug("IMAP PLAIN auth response: %s", resp.raw)
        if resp.tagged == tag:
            if not resp.status_or_data.upper().startswith("OK"):
                raise RuntimeError(f"IMAP PLAIN auth failed for {authcid}/{authzid}: {resp.raw}")
            return
