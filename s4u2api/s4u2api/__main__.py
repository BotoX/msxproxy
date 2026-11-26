import logging
import asyncio
import uvloop
import socket
import os
import ssl
import argparse
import contextlib
import multiprocessing
import signal
import pathlib
import traceback

from . import aionetstrings
from . import auth
from . import config
from . import kerberos
from . import logic

logger = logging.getLogger(__name__)

CCACHE_PRUNE_INTERVAL = 3600


async def client_connected(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peername = writer.get_extra_info('peername')
    ctx = None

    try:
        while not reader.at_eof():
            try:
                req = await asyncio.wait_for(
                    aionetstrings.read_dict(reader), timeout=60
                )
                if req is None:  # EOF / disconnect
                    break
            except asyncio.TimeoutError:
                break
            except asyncio.IncompleteReadError:
                break
            except (ValueError, UnicodeDecodeError) as e:
                traceback.print_exc()
                aionetstrings.write_dict(writer, {'error': str(e)})
                await writer.drain()
                break

            try:
                res, ctx = await logic.client_message(req, ctx, peername)
                aionetstrings.write_dict(writer, res)
            except Exception as e:
                traceback.print_exc()
                data = {'error': str(e)}
                aionetstrings.write_dict(writer, data)

            await writer.drain()

    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


async def _ccache_prune_loop(stop_event: asyncio.Event) -> None:
    while not stop_event.is_set():
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=CCACHE_PRUNE_INTERVAL)
            break
        except asyncio.TimeoutError:
            pass
        try:
            removed = kerberos.kerb_proxy.prune_ccaches()
            if removed:
                logger.info("Pruned %d expired Kerberos ccache file(s).", removed)
        except Exception as e:
            logger.warning("Failed to prune Kerberos ccaches: %s", e)


async def run_server(sock, ssl_ctx, *, flush_on_start: bool = False):
    loop = asyncio.get_running_loop()
    if flush_on_start:
        await logic.setup()

    server = await asyncio.start_server(client_connected, sock=sock, ssl=ssl_ctx)
    stop_event = asyncio.Event()

    def _request_stop() -> None:
        if not stop_event.is_set():
            logger.info("Shutdown requested.")
            stop_event.set()

    async def _do_hot_reload() -> None:
        logger.info("SIGHUP received: hot-reloading s4u2api config, OIDC JWKS, and Kerberos credentials...")
        try:
            config.load_config()
        except Exception as e:
            logger.error("Hot reload failed while reading %s: %s (keeping previous config)", config.CONFIG_PATH, e)
            return

        try:
            await loop.run_in_executor(None, auth.oidc.reload_from_config)
            logger.info("Reloaded OIDC settings and JWKS.")
        except Exception as e:
            logger.error("Hot reload failed to refresh OIDC/JWKS: %s (keeping previous JWKS)", e)

        try:
            kerberos.kerb_proxy.reload_from_config()
            logger.info("Reloaded Kerberos principal/keytab settings.")
        except Exception as e:
            logger.error("Hot reload failed to update Kerberos settings: %s (keeping previous settings)", e)

        try:
            await logic.setup()
            logger.info("Flushed Valkey JWT cache after reload.")
        except Exception as e:
            logger.error("Hot reload failed to flush Valkey cache: %s", e)

    def _request_reload() -> None:
        asyncio.create_task(_do_hot_reload())

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _request_stop)
    if hasattr(signal, "SIGHUP"):
        loop.add_signal_handler(signal.SIGHUP, _request_reload)

    prune_task = asyncio.create_task(_ccache_prune_loop(stop_event))
    try:
        async with server:
            await stop_event.wait()
    finally:
        stop_event.set()
        prune_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await prune_task


def worker(sock, ssl_ctx):
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, signal.SIG_IGN)

    try:
        uvloop.run(run_server(sock, ssl_ctx, flush_on_start=False))
    except Exception:
        logging.exception("s4u2api worker crashed")


def main():
    def parse_uds(s):
        if ':' in s:
            path, mode_str = s.rsplit(':', 1)
            try:
                mode = int(mode_str, 8)
            except ValueError:
                raise argparse.ArgumentTypeError(f'Invalid octal mode: {mode_str}')
            return pathlib.Path(path), mode
        else:
            return pathlib.Path(s), 0o600

    default_uds = parse_uds(config.SERVER_UDS) if config.SERVER_UDS else None
    parser = argparse.ArgumentParser(description='Kerberos S4U2Proxy API Server')
    parser.register('type', 'uds', parse_uds)
    parser.add_argument('--uds', type='uds', default=default_uds, help='Path to Unix Domain Socket (optional :chmod suffix; overrides host/port)')
    parser.add_argument('--host', default=config.SERVER_HOST, help='TCP Listen Host (default from config: %(default)s)')
    parser.add_argument('--port', type=int, default=config.SERVER_PORT, help='TCP Listen Port (default from config: %(default)s)')
    parser.add_argument("--log", default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], help="Set the logging level (default: %(default)s)")
    parser.add_argument('--workers', type=int, default=1, help='Number of workers')
    parser.add_argument('--cert', help='Path to SSL certificate (for remote TCP)')
    parser.add_argument('--key', help='Path to SSL key (for remote TCP)')
    args = parser.parse_args()

    if args.log == 'DEBUG':
        logging.basicConfig(
            level=args.log,
            format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        )
    else:
        logging.basicConfig(
            level=args.log,
            format='[%(levelname)s] %(name)s: %(message)s',
        )

    ssl_ctx = None
    if args.cert and args.key:
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(args.cert, args.key)

    if args.uds:
        path, mode = args.uds
        if os.path.exists(path):
            os.remove(path)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(str(path))
        os.chmod(path, mode)
        logger.info(f'Listening on UDS {path} (chmod {oct(mode)})')
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((args.host, args.port))
        logger.info(f'Listening on {args.host}:{args.port}')

    sock.listen(4096)
    sock.setblocking(False)

    if args.workers > 1:
        uvloop.run(logic.setup())

        processes = []
        for _ in range(args.workers):
            p = multiprocessing.Process(target=worker, args=(sock, ssl_ctx))
            p.start()
            processes.append(p)

        def _forward_sighup(signum, frame):
            logger.info("Forwarding SIGHUP to %d worker(s)...", len(processes))
            for p in processes:
                if p.is_alive() and p.pid:
                    os.kill(p.pid, signal.SIGHUP)

        def _forward_sigterm(signum, frame):
            logger.info("Shutting down %d worker(s)...", len(processes))
            for p in processes:
                if p.is_alive():
                    p.terminate()

        if hasattr(signal, "SIGHUP"):
            signal.signal(signal.SIGHUP, _forward_sighup)
        signal.signal(signal.SIGTERM, _forward_sigterm)

        logger.info(f'Spawned {len(processes)} workers.')

        try:
            for p in processes:
                p.join()
        except KeyboardInterrupt:
            logger.info('\nShutting down workers...')
            for p in processes:
                if p.is_alive():
                    p.terminate()
            for p in processes:
                p.join()
    else:
        try:
            uvloop.run(run_server(sock, ssl_ctx, flush_on_start=True))
        except KeyboardInterrupt:
            logger.info('\nShutting down.')

    sock.close()
    if args.uds and os.path.exists(args.uds[0]):
        os.remove(args.uds[0])


if __name__ == '__main__':
    main()
