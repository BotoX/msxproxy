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
from . import logic

logger = logging.getLogger(__name__)


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


async def run_server(sock, ssl):
    server = await asyncio.start_server(client_connected, sock=sock, ssl=ssl)
    async with server:
        await server.serve_forever()


def worker(sock, ssl):
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    try:
        uvloop.run(run_server(sock, ssl))
    except Exception:
        pass


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

    parser = argparse.ArgumentParser(description='Kerberos S4U2Proxy API Server')
    parser.register('type', 'uds', parse_uds)
    parser.add_argument('--uds', type='uds', help='Path to Unix Domain Socket (optional :chmod suffix)')
    parser.add_argument('--host', default='127.0.0.1', help='TCP Listen Host (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=7777, help='TCP Listen Port (default: 7777)')
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

        logger.info(f'Spawned {len(processes)} workers.')

        try:
            for p in processes:
                p.join()
        except KeyboardInterrupt:
            logger.info('\nShutting down workers...')
            for p in processes:
                p.terminate()
    else:
        try:
            async def single_worker(sock, ssl_ctx):
                await logic.setup()
                await run_server(sock, ssl_ctx)

            uvloop.run(single_worker(sock, ssl_ctx))
        except KeyboardInterrupt:
            logger.info('\nShutting down.')

    sock.close()
    if args.uds and os.path.exists(args.uds[0]):
        os.remove(args.uds[0])


if __name__ == '__main__':
    main()
