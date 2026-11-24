import asyncio
import ssl
import logging
import traceback
import contextlib

from . import config
from .auth import OIDCError, TrustedNetworkError
from .utils import AUTH_MECHS, sasl_auth_flow, imap_login, close_writer, has_buffered_data
from .imap_parser import ImapParser, ImapCommand
from .imap_backend import (
    imap_gssapi_auth,
    imap_plain_auth,
    imap_ensure_tls
)
from .relay import relay
from .loadbalancer import LoadBalancer

logger = logging.getLogger(__name__)


class ImapProxyServer:
    def __init__(self, lb: LoadBalancer, ssl_ctx: ssl.SSLContext | None = None) -> None:
        self.lb = lb
        self._ssl_ctx = ssl_ctx

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        addr = writer.get_extra_info("peername")
        is_tls = writer.get_extra_info("ssl_object") is not None

        parser = ImapParser(reader, writer)

        logger.debug(f"IMAP client connected: {addr}, TLS={is_tls}")

        tries = 0
        be_reader = None
        be_writer = None
        try:
            async with asyncio.timeout(config.AUTH_TIMEOUT):
                # Initial greeting
                greeting = f"* OK {config.PROXY_HOSTNAME} IMAP4 service ready\r\n"
                writer.write(greeting.encode())
                await writer.drain()

                while not be_writer:
                    try:
                        cmd = await parser.read_command()
                    except ValueError as e:
                        writer.write(f"{e}\r\n".encode())
                        await writer.drain()
                        continue
                    except RuntimeError as e:
                        writer.write(f"{e}\r\n".encode())
                        await writer.drain()
                        return

                    tag = cmd.tag
                    command = cmd.command

                    if not tag or not command:
                        writer.write(f"{tag or '*'} BAD Command Error.\r\n".encode())
                        await writer.drain()
                        continue

                    if command == "CAPABILITY":
                        caps = config.IMAP_CAPS[:]

                        if (not is_tls) and (self._ssl_ctx is not None):
                            # Cleartext connection, STARTTLS available
                            caps.insert(0, "STARTTLS")
                            # Don’t allow cleartext LOGIN/PLAIN
                            caps.append("LOGINDISABLED")
                        else:
                            for mech in AUTH_MECHS:
                                caps.append(f"AUTH={mech}")
                            caps.append("SASL-IR")

                        caps = " ".join(caps).encode()
                        cap_line = b"* CAPABILITY " + caps + b"\r\n"
                        writer.write(cap_line)
                        writer.write(f"{tag} OK CAPABILITY completed\r\n".encode())
                        await writer.drain()

                    elif command == "STARTTLS":
                        if is_tls:
                            writer.write(f"{tag} BAD Already encrypted\r\n".encode())
                            await writer.drain()
                            continue

                        if self._ssl_ctx is None:
                            writer.write(f"{tag} BAD TLS not available\r\n".encode())
                            await writer.drain()
                            continue

                        if has_buffered_data(reader):
                            logger.warning("IMAP STARTTLS pipelined cleartext data from '%s'; closing connection", addr[0])
                            writer.write(f"{tag} BAD Command pipelining not allowed with STARTTLS\r\n".encode())
                            await writer.drain()
                            return

                        # RFC 3501: send tagged OK, then start TLS negotiation
                        writer.write(f"{tag} OK Begin TLS negotiation now\r\n".encode())
                        await writer.drain()

                        try:
                            await writer.start_tls(self._ssl_ctx)
                        except Exception as e:
                            logger.warning("IMAP start_tls error from '%s': %s", addr[0], e)
                            return
                        is_tls = True

                        # After start_tls, the transport/protocol changed; rebuild parser.
                        parser = ImapParser(reader, writer)

                    elif command == "AUTHENTICATE" or command == "LOGIN":
                        # Enforce TLS before AUTHENTICATE
                        if not is_tls:
                            writer.write(f"{tag} NO [PRIVACYREQUIRED] Encryption required for authentication\r\n".encode())
                            await writer.drain()
                            continue

                        be_reader, be_writer = await self._handle_auth(cmd, reader, writer, addr)
                        if not be_writer:
                            tries += 1
                            await asyncio.sleep(tries)

                    elif command == "LOGOUT":
                        writer.write(b"* BYE IMAP4 proxy signing off\r\n")
                        writer.write(f"{tag} OK LOGOUT completed\r\n".encode())
                        await writer.drain()
                        return

                    else:
                        # For everything else, require authentication first.
                        writer.write(f"{tag} BAD Authentication required\r\n".encode("utf-8"))
                        await writer.drain()

            if be_reader and be_writer:
                # Start relaying traffic
                await relay(reader, writer, be_reader, be_writer)

        except TimeoutError:
            logger.debug(f"IMAP client {addr} timed out after {config.AUTH_TIMEOUT}s")
            with contextlib.suppress(Exception):
                writer.write(b"* BYE Timeout: closing connection\r\n")
                await writer.drain()

        except (EOFError, ConnectionResetError):
            pass

        finally:
            if be_writer:
                await close_writer(be_writer)
            await close_writer(writer)
            logger.debug(f"IMAP client disconnected: {addr}")

    async def _handle_auth(
        self,
        cmd: ImapCommand,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        addr: tuple[str, int]
    ) -> tuple[asyncio.StreamReader | None, asyncio.StreamWriter | None]:
        tag = cmd.tag
        args = cmd.args

        try:
            if cmd.command == "LOGIN":
                mech = "LOGIN"
                if len(cmd.args) < 2:
                    writer.write(f"{tag} BAD LOGIN requires username and password\r\n".encode())
                    await writer.drain()
                    return None, None

                upn, jwt, authzid, (username, password) = await imap_login(
                    username=args[0].decode(),
                    password=args[1].decode(),
                    ip_address=addr[0]
                )

            else:  # cmd.command == "AUTHENTICATE":
                if not args:
                    writer.write(f"{tag} BAD Missing auth mechanism\r\n".encode())
                    await writer.drain()
                    return None, None

                mech = args[0].decode().upper()
                initial_b64 = args[1] if len(args) > 1 else None

                if mech not in AUTH_MECHS:
                    writer.write(f"{tag} NO Unsupported SASL mechanism\r\n".encode())
                    await writer.drain()
                    return None, None

                upn, jwt, authzid, (username, password) = await sasl_auth_flow(
                    mode="imap",
                    mech=mech,
                    initial_b64=initial_b64,
                    reader=reader,
                    writer=writer,
                    ip_address=addr[0]
                )
                mech = f"SASL {mech}"

        except (EOFError, ConnectionResetError):  # Connection closed
            return None, None
        except TrustedNetworkError:
            writer.write(b"* OK [ALERT] External access requires using a Mail Password. Generate one at https://login.uni-graz.at\r\n")
            writer.write(f"{tag} NO [AUTHORIZATIONFAILED] External access requires using a Mail Password. Generate one at https://login.uni-graz.at\r\n".encode())
            await writer.drain()
            return None, None
        except (OIDCError, ValueError, UnicodeDecodeError) as e:
            logger.info("IMAP %s authentication failed from '%s': %r", mech, addr[0], str(e))
            writer.write(f"{tag} NO [AUTHENTICATIONFAILED] Authentication credentials invalid\r\n".encode())
            await writer.drain()
            return None, None
        except Exception as e:
            traceback.print_exc()
            logger.warning("IMAP %s auth error: %r", mech, str(e))
            writer.write(f"{tag} NO [UNAVAILABLE] Unexpected authentication error\r\n".encode())
            await writer.drain()
            return None, None

        logger.info("IMAP (%s) authenticated %r (u=%r) (authzid=%r)", mech, upn, username, authzid)

        # --------------- BACKEND CONNECTION ---------------
        be_reader, be_writer, be_host, be_ssl_ctx = None, None, None, None
        be_username = None
        be_password = None

        try:
            be_reader, be_writer, be_host, be_ssl_ctx = await self.lb.connect()
        except ConnectionError as e:
            logger.error(str(e))
            writer.write(f"{tag} NO [UNAVAILABLE] All backends unavailable\r\n".encode())
            await writer.drain()
            return None, None

        try:
            tag_counter = await imap_ensure_tls(
                reader=be_reader,
                writer=be_writer,
                hostname=be_host,
                ssl_context=be_ssl_ctx
            )

            if False and be_username and be_password:
                await imap_plain_auth(
                    be_reader,
                    be_writer,
                    be_username,
                    be_password,
                    tag_counter=tag_counter
                )
            else:
                await imap_gssapi_auth(
                    reader=be_reader,
                    writer=be_writer,
                    upn=upn,
                    jwt=jwt,
                    spn="imap",
                    tag_counter=tag_counter
                )
        except Exception as e:
            traceback.print_exc()
            logger.error(f"IMAP backend auth failed for {upn}: {e}")
            await close_writer(be_writer)
            writer.write(f"{tag} NO [UNAVAILABLE] Backend authentication failed\r\n".encode())
            await writer.drain()
            return None, None

        # If we get here, backend auth has succeeded.
        writer.write(f"{tag} OK {cmd.command} completed\r\n".encode())
        await writer.drain()

        return be_reader, be_writer
