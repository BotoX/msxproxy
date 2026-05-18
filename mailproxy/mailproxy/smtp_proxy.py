import asyncio
import ssl
import logging
import traceback
import contextlib

from . import config
from .auth import OIDCError, TrustedNetworkError
from .utils import AUTH_MECHS, sasl_auth_flow, close_writer
from .smtp_backend import smtp_ensure_tls_and_ehlo, smtp_gssapi_auth, smtp_login_auth
from .relay import relay
from .loadbalancer import LoadBalancer

logger = logging.getLogger(__name__)


class SmtpProxyServer:
    def __init__(self, lb: LoadBalancer, ssl_ctx: ssl.SSLContext | None = None) -> None:
        self.lb = lb
        self._ssl_ctx = ssl_ctx

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        addr = writer.get_extra_info("peername")
        is_tls = writer.get_extra_info("ssl_object") is not None

        logger.debug(f"SMTP client connected: {addr}, TLS={is_tls}")

        tries = 0
        be_reader = None
        be_writer = None
        try:
            async with asyncio.timeout(config.AUTH_TIMEOUT):
                # Initial greeting
                greeting = f"220 {config.PROXY_HOSTNAME} ESMTP ready\r\n"
                writer.write(greeting.encode())
                await writer.drain()

                while not be_writer:
                    try:
                        line = await reader.readline()
                        if not line:
                            return
                    except ValueError:
                        writer.write(b"500 5.0.0 Line too long\r\n")
                        await writer.drain()
                        continue

                    try:
                        line_str = line.decode().rstrip("\r\n")
                        if not line_str:
                            continue
                    except UnicodeDecodeError:
                        writer.write(b"500 5.0.0 Unicode decode error\r\n")
                        await writer.drain()
                        continue

                    parts = line_str.split(" ", 2)
                    cmd = parts[0].upper()

                    if cmd in ("EHLO", "HELO"):
                        caps = [f"{config.PROXY_HOSTNAME} Hello [{addr[0]}]"]
                        if cmd == "EHLO":
                            # STARTTLS only if not already TLS and ssl_context available
                            if (not is_tls) and (self._ssl_ctx is not None):
                                caps.insert(1, "STARTTLS")
                            else:
                                caps.append("AUTH " + " ".join(AUTH_MECHS))
                            caps.extend(config.ESMTP_CAPS)

                        for cap in caps[:-1]:
                            writer.write(f"250-{cap}\r\n".encode())
                        writer.write(f"250 {caps[-1]}\r\n".encode())
                        await writer.drain()

                    elif cmd == "STARTTLS":
                        if is_tls:
                            writer.write(b"502 5.5.1 Already encrypted\r\n")
                            await writer.drain()
                            continue

                        if self._ssl_ctx is None:
                            writer.write(b"454 4.7.0 TLS not available\r\n")
                            await writer.drain()
                            continue

                        writer.write(b"220 2.0.0 Ready to start TLS\r\n")
                        await writer.drain()

                        try:
                            await writer.start_tls(self._ssl_ctx)
                        except Exception as e:
                            logger.warning("SMTP start_tls error from '%s': %s", addr[0], e)
                            return
                        is_tls = True  # from now on, this connection is encrypted

                    elif cmd == "AUTH":
                        # Enforce TLS before AUTH
                        if not is_tls:
                            writer.write(b"538 5.7.11 Encryption required for requested authentication mechanism\r\n")
                            await writer.drain()
                            continue

                        be_reader, be_writer = await self._handle_auth(parts, reader, writer, addr)
                        if not be_writer:
                            tries += 1
                            await asyncio.sleep(tries)

                    elif cmd == "QUIT":
                        writer.write(b"221 2.0.0 Bye\r\n")
                        await writer.drain()
                        return

                    elif cmd == "NOOP" or cmd == "RSET":
                        writer.write(b"250 2.0.0 OK\r\n")
                        await writer.drain()

                    elif cmd == "VRFY":
                        writer.write(b"252 2.5.2 Cannot VRFY; authenticate first\r\n")
                        await writer.drain()

                    elif cmd == "HELP":
                        writer.write(b"214 2.0.0 See RFC 5321\r\n")
                        await writer.drain()

                    elif cmd in ("MAIL", "RCPT", "DATA", "BDAT"):
                        writer.write(b"530 5.7.0 Authentication required\r\n")
                        await writer.drain()

                    else:
                        writer.write(b"502 5.5.2 Command not recognized\r\n")
                        await writer.drain()

            if be_reader and be_writer:
                # Start relaying traffic
                await relay(reader, writer, be_reader, be_writer)

        except TimeoutError:
            logger.debug(f"SMTP client {addr} timed out after {config.AUTH_TIMEOUT}s")
            with contextlib.suppress(Exception):
                writer.write(b"421 4.4.2 Timeout: closing connection\r\n")
                await writer.drain()

        except (EOFError, ConnectionResetError):
            pass

        finally:
            if be_writer:
                await close_writer(be_writer)
            await close_writer(writer)
            logger.debug(f"SMTP client disconnected: {addr}")

    async def _handle_auth(
        self,
        parts: list[str],
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        addr: tuple[str, int]
    ) -> tuple[asyncio.StreamReader | None, asyncio.StreamWriter | None]:
        if len(parts) < 2:
            writer.write(b"501 5.5.4 Syntax: AUTH mechanism [initial-response]\r\n")
            await writer.drain()
            return None, None

        mech = parts[1].upper()
        initial_b64 = parts[2].strip() if len(parts) > 2 else None

        if mech not in AUTH_MECHS:
            writer.write(b"504 5.7.4 Unrecognized authentication type\r\n")
            await writer.drain()
            return None, None

        try:
            upn, jwt, authzid, (username, password) = await sasl_auth_flow(
                mode="smtp",
                mech=mech,
                initial_b64=initial_b64,
                reader=reader,
                writer=writer,
                ip_address=addr[0]
            )
        except EOFError:  # Connection closed
            return None, None
        except TrustedNetworkError:
            writer.write(b"535 5.7.8 External access requires using a Mail Password. Generate one at https://login.uni-graz.at\r\n")
            await writer.drain()
            return None, None
        except (OIDCError, ValueError) as e:
            logger.info("SMTP %s authentication failed from '%s': %s", mech, addr[0], e)
            writer.write(b"535 5.7.8 Authentication credentials invalid\r\n")
            await writer.drain()
            return None, None
        except Exception as e:
            traceback.print_exc()
            logger.warning("SMTP %s auth error: %s", mech, e)
            writer.write(b"454 4.7.0 Unexpected authentication error\r\n")
            await writer.drain()
            return None, None

        logger.info(f"SMTP ({mech}) authenticated {upn} (u={username}) (authzid={authzid})")

        # --------------- BACKEND CONNECTION ---------------
        be_reader, be_writer, be_host, be_ssl_ctx = None, None, None, None
        be_username = None
        be_password = None

        try:
            be_reader, be_writer, be_host, be_ssl_ctx = await self.lb.connect()
        except ConnectionError as e:
            logger.error(str(e))
            writer.write(b"454 4.7.0 Service unavailable; all backends down\r\n")
            await writer.drain()
            return None, None

        try:
            caps = await smtp_ensure_tls_and_ehlo(
                reader=be_reader,
                writer=be_writer,
                hostname=be_host,
                ssl_context=be_ssl_ctx,
                ehlo_name=config.EHLO
            )
            logger.debug("Backend SMTP capabilities after TLS: %r", caps)

            if False and be_username and be_password:
                ok, last_line = await smtp_login_auth(
                    be_reader,
                    be_writer,
                    be_username,
                    be_password
                )
                if not ok:
                    raise RuntimeError(f"SMTP LOGIN auth failed on backend: {last_line}")
            else:
                ok, last_line = await smtp_gssapi_auth(
                    reader=be_reader,
                    writer=be_writer,
                    upn=upn,
                    jwt=jwt,
                    spn="smtp"
                )
                if not ok:
                    raise RuntimeError(f"SMTP GSSAPI auth failed on backend: {last_line}")

        except Exception as e:
            traceback.print_exc()
            logger.error(f"Backend SMTP auth failed for {upn}: {e}")
            await close_writer(be_writer)
            writer.write(b"454 4.7.0 Backend authentication failed\r\n")
            await writer.drain()
            return None, None

        # If we get here, backend auth has succeeded
        writer.write(b"235 2.7.0 Authentication successful\r\n")
        await writer.drain()

        return be_reader, be_writer
