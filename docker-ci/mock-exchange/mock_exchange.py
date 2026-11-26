#!/usr/bin/env python3
"""
Mock Microsoft Exchange server for msxproxy integration testing.

Listens on:
  - HTTPS  :443  (/mapi/healthcheck.htm, /Microsoft-Server-ActiveSync,
                  /EWS/Exchange.asmx, /owa/*, /autodiscover/autodiscover.xml)
  - IMAPS  :993  (implicit TLS, CAPABILITY + AUTHENTICATE GSSAPI + NOOP + LOGOUT)
  - SMTP   :587  (plain + STARTTLS, EHLO + AUTH GSSAPI + NOOP + QUIT)

Validates the mock Kerberos token produced by `mock_s4u2api.py`:
    base64("MOCK-KRB5:<upn>:<fullspn>")

On HTTPS connections, tracks per-TCP-connection authentication state just like
real Exchange NTLM/Negotiate pinning, and returns diagnostic headers
(`X-Mock-Principal`, `X-Mock-Conn-Id`, `X-Mock-Auth-Header-Present`) so tests
can assert both token verification and ngx_http_upstream_ntlm_module pinning.
"""
from __future__ import annotations

import asyncio
import base64
import gzip
import itertools
import json
import logging
import os
import re
import ssl
import urllib.parse

logging.basicConfig(level=logging.INFO, format="[mock-exchange] %(message)s")
logger = logging.getLogger("mock-exchange")

CERT_FILE = os.environ.get("EXCHANGE_CERT", "/certs/exchange.pem")
KEY_FILE = os.environ.get("EXCHANGE_KEY", "/certs/exchange.key")
EXPECTED_SPN = os.environ.get("EXCHANGE_SPN", "http/exchange.test.local@TEST.LOCAL")

_CONN_SEQ = itertools.count(1)
_ALNUM_RE = re.compile(r"^[A-Za-z0-9]+$")


def _make_ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT_FILE, KEY_FILE)
    return ctx


def _verify_mock_krb5_token(b64_token: str) -> str | None:
    """Decode and validate MOCK-KRB5:<upn>:<spn>; return <upn> or None."""
    try:
        raw = base64.b64decode(b64_token, validate=True).decode("utf-8")
    except Exception:
        return None
    if not raw.startswith("MOCK-KRB5:"):
        return None
    rest = raw[len("MOCK-KRB5:") :]
    upn, sep, spn = rest.partition(":")
    if not sep or not upn or "@" not in upn:
        return None
    if spn != EXPECTED_SPN:
        logger.warning("SPN mismatch: got %r, expected %r", spn, EXPECTED_SPN)
        return None
    return upn


# ---------------------------------------------------------------------------
# HTTPS (Exchange ActiveSync / EWS / OWA / Autodiscover / Healthcheck)
# ---------------------------------------------------------------------------

async def _read_http_request(reader: asyncio.StreamReader):
    req_line = await reader.readline()
    if not req_line:
        return None
    line_str = req_line.decode("iso-8859-1").rstrip("\r\n")
    parts = line_str.split(" ", 2)
    if len(parts) != 3:
        return None
    method, target, version = parts

    headers: dict[str, str] = {}
    while True:
        hline = await reader.readline()
        if not hline or hline in (b"\r\n", b"\n"):
            break
        k, sep, v = hline.decode("iso-8859-1").rstrip("\r\n").partition(":")
        if sep:
            headers[k.strip().lower()] = v.strip()

    body = b""
    te = headers.get("transfer-encoding", "").lower()
    if "chunked" in te:
        chunks = []
        while True:
            size_line = await reader.readline()
            if not size_line:
                break
            size = int(size_line.strip().split(b";", 1)[0], 16)
            if size == 0:
                await reader.readline()
                break
            chunks.append(await reader.readexactly(size))
            await reader.readexactly(2)
        body = b"".join(chunks)
    elif "content-length" in headers:
        cl = int(headers["content-length"])
        if cl > 0:
            body = await reader.readexactly(cl)

    return method, target, version, headers, body


def _build_http_response(
    status: int,
    reason: str,
    headers: dict[str, str],
    body: bytes,
    keep_alive: bool,
) -> bytes:
    hdrs = dict(headers)
    hdrs["Content-Length"] = str(len(body))
    hdrs["Connection"] = "keep-alive" if keep_alive else "close"
    lines = [f"HTTP/1.1 {status} {reason}"]
    for k, v in hdrs.items():
        lines.append(f"{k}: {v}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("iso-8859-1") + body


async def handle_https(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    conn_id = str(next(_CONN_SEQ))
    pinned_upn: str | None = None

    try:
        while True:
            try:
                req = await asyncio.wait_for(_read_http_request(reader), timeout=60)
            except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionResetError):
                break
            if req is None:
                break

            method, target, version, headers, _body = req
            parsed = urllib.parse.urlsplit(target)
            path = parsed.path
            qs = urllib.parse.parse_qs(parsed.query)

            conn_hdr = headers.get("connection", "").lower()
            keep_alive = (version == "HTTP/1.1" and conn_hdr != "close")

            # Unauthenticated healthcheck endpoint for OpenResty resty.upstream.healthcheck
            if path.lower().endswith("/healthcheck.htm"):
                resp = _build_http_response(
                    200, "OK", {"Content-Type": "text/plain"}, b"200 OK\n", keep_alive
                )
                writer.write(resp)
                await writer.drain()
                if not keep_alive:
                    break
                continue

            auth_hdr = headers.get("authorization", "")
            auth_present = bool(auth_hdr.strip())
            if auth_hdr.startswith("Negotiate "):
                upn = _verify_mock_krb5_token(auth_hdr[len("Negotiate ") :].strip())
                if not upn:
                    resp = _build_http_response(
                        401,
                        "Unauthorized",
                        {"WWW-Authenticate": "Negotiate", "Content-Type": "text/plain"},
                        b"Invalid Negotiate token\n",
                        False,
                    )
                    writer.write(resp)
                    await writer.drain()
                    break
                pinned_upn = upn
            elif pinned_upn is None:
                resp = _build_http_response(
                    401,
                    "Unauthorized",
                    {"WWW-Authenticate": "Negotiate", "Content-Type": "text/plain"},
                    b"Authentication required\n",
                    False,
                )
                writer.write(resp)
                await writer.drain()
                break

            base_hdrs = {
                "X-Mock-Principal": pinned_upn,
                "X-Mock-Conn-Id": conn_id,
                "X-Mock-Auth-Header-Present": "yes" if auth_present else "no",
            }

            if path.lower() == "/microsoft-server-activesync":
                # Mirror real Exchange constraint: DeviceId must be alphanumeric-only
                dev_ids = qs.get("DeviceId") or qs.get("deviceid") or []
                if dev_ids and not _ALNUM_RE.match(dev_ids[0]):
                    resp = _build_http_response(
                        400,
                        "Bad Request",
                        {**base_hdrs, "Content-Type": "text/plain"},
                        b"Invalid DeviceId (must be alphanumeric)\n",
                        keep_alive,
                    )
                else:
                    as_hdrs = {
                        **base_hdrs,
                        "MS-Server-ActiveSync": "15.1",
                        "MS-ASProtocolVersions": "12.0,12.1,14.0,14.1,16.0,16.1",
                        "MS-ASProtocolCommands": "Sync,SendMail,SmartForward,SmartReply,GetAttachment,FolderSync,Provision,Options,Settings",
                        "Content-Type": "text/plain",
                    }
                    resp = _build_http_response(200, "OK", as_hdrs, b"", keep_alive)

            elif path.lower() == "/autodiscover/autodiscover.xml":
                xml_body = (
                    '<?xml version="1.0" encoding="utf-8"?>'
                    '<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">'
                    "<Response><Account><AccountType>email</AccountType><Action>settings</Action>"
                    "<Protocol><Type>EXCH</Type><Server>email.uni-graz.at</Server>"
                    "<ASUrl>https://email.uni-graz.at/EWS/Exchange.asmx</ASUrl></Protocol>"
                    "<Internal><OWAUrl>https://email.uni-graz.at/owa/</OWAUrl></Internal>"
                    "</Account></Response></Autodiscover>"
                ).encode("utf-8")
                resp = _build_http_response(
                    200,
                    "OK",
                    {**base_hdrs, "Content-Type": "application/xml; charset=utf-8"},
                    xml_body,
                    keep_alive,
                )

            elif re.match(r"^/owa/([^/]+/)?sessiondata\.ashx$", path, re.IGNORECASE):
                payload = json.dumps(
                    {
                        "owaUserConfig": {
                            "ApplicationSettings": {
                                "CheckForForgottenAttachmentsEnabled": True,
                                "CloseWindowOnLogout": True,
                                "ConsoleTracingEnabled": False,
                                "IsLegacySignOut": True,
                            }
                        }
                    },
                    separators=(",", ":"),
                ).encode("utf-8")
                sd_hdrs = {**base_hdrs, "Content-Type": "application/x-javascript"}
                if "gzip" in headers.get("accept-encoding", "").lower():
                    payload = gzip.compress(payload)
                    sd_hdrs["Content-Encoding"] = "gzip"
                resp = _build_http_response(200, "OK", sd_hdrs, payload, keep_alive)

            elif re.match(r"^/owa/([^/]+/)?service\.svc$", path, re.IGNORECASE) and (
                any(
                    v.lower() == "getowauserconfiguration"
                    for v in (qs.get("action") or qs.get("Action") or [])
                )
                or headers.get("action", "").lower() == "getowauserconfiguration"
                or headers.get("x-owa-actionname", "").lower() == "getowauserconfiguration"
            ):
                payload = json.dumps(
                    {
                        "Body": {
                            "ApplicationSettings": {
                                "CloseWindowOnLogout": True,
                            }
                        }
                    },
                    separators=(",", ":"),
                ).encode("utf-8")
                svc_hdrs = {**base_hdrs, "Content-Type": "application/json; charset=utf-8"}
                if "gzip" in headers.get("accept-encoding", "").lower():
                    payload = gzip.compress(payload)
                    svc_hdrs["Content-Encoding"] = "gzip"
                resp = _build_http_response(200, "OK", svc_hdrs, payload, keep_alive)

            elif path.lower().startswith("/owa"):
                body = f"Mock OWA OK for {pinned_upn}\n".encode("utf-8")
                resp = _build_http_response(
                    200, "OK", {**base_hdrs, "Content-Type": "text/html; charset=utf-8"}, body, keep_alive
                )

            else:
                body = f"Mock Exchange OK ({method} {path}) for {pinned_upn}\n".encode("utf-8")
                resp = _build_http_response(
                    200, "OK", {**base_hdrs, "Content-Type": "text/plain"}, body, keep_alive
                )

            writer.write(resp)
            await writer.drain()
            if not keep_alive:
                break
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# IMAPS (:993 implicit TLS)
# ---------------------------------------------------------------------------

async def handle_imaps(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        writer.write(b"* OK Mock Exchange IMAP4 service ready.\r\n")
        await writer.drain()

        while True:
            raw = await asyncio.wait_for(reader.readline(), timeout=60)
            if not raw:
                break
            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            parts = line.split(" ", 3)
            tag = parts[0]
            cmd = parts[1].upper() if len(parts) > 1 else ""

            if cmd == "CAPABILITY":
                writer.write(b"* CAPABILITY IMAP4 IMAP4rev1 AUTH=GSSAPI UIDPLUS IDLE MOVE\r\n")
                writer.write(f"{tag} OK CAPABILITY completed.\r\n".encode())
            elif cmd == "AUTHENTICATE":
                mech = parts[2].upper() if len(parts) > 2 else ""
                tok = parts[3].strip() if len(parts) > 3 else ""
                if mech == "GSSAPI" and _verify_mock_krb5_token(tok):
                    writer.write(f"{tag} OK AUTHENTICATE completed.\r\n".encode())
                else:
                    writer.write(f"{tag} NO AUTHENTICATE failed.\r\n".encode())
            elif cmd == "NOOP":
                writer.write(f"{tag} OK NOOP completed.\r\n".encode())
            elif cmd == "LOGOUT":
                writer.write(b"* BYE Mock Exchange IMAP4 signing off.\r\n")
                writer.write(f"{tag} OK LOGOUT completed.\r\n".encode())
                await writer.drain()
                break
            else:
                writer.write(f"{tag} OK {cmd} completed.\r\n".encode())
            await writer.drain()
    except (asyncio.TimeoutError, ConnectionResetError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# SMTP (:587 plain + STARTTLS)
# ---------------------------------------------------------------------------

async def handle_smtp(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    ssl_ctx: ssl.SSLContext,
) -> None:
    is_tls = False
    try:
        writer.write(b"220 exchange.test.local Mock Exchange ESMTP ready\r\n")
        await writer.drain()

        while True:
            raw = await asyncio.wait_for(reader.readline(), timeout=60)
            if not raw:
                break
            line = raw.decode("utf-8", errors="replace").strip()
            upper = line.upper()

            if upper.startswith("EHLO") or upper.startswith("HELO"):
                if not is_tls:
                    writer.write(
                        b"250-exchange.test.local Hello\r\n"
                        b"250-SIZE 104857600\r\n"
                        b"250 STARTTLS\r\n"
                    )
                else:
                    writer.write(
                        b"250-exchange.test.local Hello\r\n"
                        b"250-SIZE 104857600\r\n"
                        b"250-PIPELINING\r\n"
                        b"250 AUTH GSSAPI\r\n"
                    )
            elif upper == "STARTTLS":
                writer.write(b"220 2.0.0 SMTP server ready\r\n")
                await writer.drain()
                await writer.start_tls(ssl_ctx)
                is_tls = True
                continue
            elif upper.startswith("AUTH GSSAPI "):
                tok = line[len("AUTH GSSAPI ") :].strip()
                if is_tls and _verify_mock_krb5_token(tok):
                    writer.write(b"235 2.7.0 Authentication successful\r\n")
                else:
                    writer.write(b"535 5.7.3 Authentication unsuccessful\r\n")
            elif upper == "NOOP":
                writer.write(b"250 2.0.0 OK\r\n")
            elif upper == "QUIT":
                writer.write(b"221 2.0.0 Service closing transmission channel\r\n")
                await writer.drain()
                break
            else:
                writer.write(b"250 2.0.0 OK\r\n")
            await writer.drain()
    except (asyncio.TimeoutError, ConnectionResetError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def main() -> None:
    ssl_ctx = _make_ssl_ctx()

    https_srv = await asyncio.start_server(handle_https, "0.0.0.0", 443, ssl=ssl_ctx)
    imaps_srv = await asyncio.start_server(handle_imaps, "0.0.0.0", 993, ssl=ssl_ctx)
    smtp_srv = await asyncio.start_server(
        lambda r, w: handle_smtp(r, w, ssl_ctx), "0.0.0.0", 587
    )

    logger.info("Listening on HTTPS :443, IMAPS :993, SMTP+STARTTLS :587 (SPN=%s)", EXPECTED_SPN)
    async with https_srv, imaps_srv, smtp_srv:
        await asyncio.gather(
            https_srv.serve_forever(),
            imaps_srv.serve_forever(),
            smtp_srv.serve_forever(),
        )


if __name__ == "__main__":
    asyncio.run(main())
