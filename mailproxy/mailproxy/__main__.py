import asyncio
import signal
import socket
import ssl
import logging
import argparse
import multiprocessing
import uvloop

from . import config
from .imap_proxy import ImapProxyServer
from .smtp_proxy import SmtpProxyServer
from .loadbalancer import LoadBalancer

logger = logging.getLogger(__name__)

SHUTDOWN_TIMEOUT = 5.0


def _make_tcp_socket(host: str, port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.bind((host, port))
    sock.listen(4096)
    sock.setblocking(False)
    return sock


async def _serve(socks: tuple[socket.socket, ...], ssl_ctx: ssl.SSLContext) -> None:
    loop = asyncio.get_running_loop()
    imap_sock, imaps_sock, smtp_sock, smtps_sock = socks

    imap_lb = await LoadBalancer.create("IMAP-LB", config.IMAP_BACKENDS)
    smtp_lb = await LoadBalancer.create("SMTP-LB", config.SMTP_BACKENDS)

    imap_proxy = ImapProxyServer(imap_lb, ssl_ctx)
    smtp_proxy = SmtpProxyServer(smtp_lb, ssl_ctx)

    imap_srv  = await asyncio.start_server(imap_proxy.handle_client, sock=imap_sock)
    imaps_srv = await asyncio.start_server(imap_proxy.handle_client, sock=imaps_sock, ssl=ssl_ctx)
    smtp_srv  = await asyncio.start_server(smtp_proxy.handle_client, sock=smtp_sock)
    smtps_srv = await asyncio.start_server(smtp_proxy.handle_client, sock=smtps_sock, ssl=ssl_ctx)

    stop_event = asyncio.Event()

    def _request_stop() -> None:
        if not stop_event.is_set():
            logger.info("Shutdown requested.")
            stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _request_stop)

    # Stop accepting new connections as soon as the stop event fires.
    async with imap_srv, imaps_srv, smtp_srv, smtps_srv:
        await stop_event.wait()

    # Stop load balancers
    await asyncio.gather(imap_lb.cancel(), smtp_lb.cancel(), return_exceptions=True)

    # Cancel and drain every in-flight connection task.
    current = asyncio.current_task()
    pending = [t for t in asyncio.all_tasks() if t is not current]

    if pending:
        logger.info("Waiting for %d active connection(s) to close ...", len(pending))
        for t in pending:
            t.cancel()
        try:
            await asyncio.wait_for(
                asyncio.gather(*pending, return_exceptions=True),
                timeout=SHUTDOWN_TIMEOUT,
            )
        except asyncio.TimeoutError:
            still = sum(1 for t in pending if not t.done())
            logger.warning(
                "Shutdown timeout (%.0fs): %d connection(s) did not close in time.",
                SHUTDOWN_TIMEOUT, still,
            )

    logger.info("All connections closed. Goodbye.")


def _worker(socks: tuple[socket.socket, ...], ssl_ctx: ssl.SSLContext) -> None:
    # Workers must not react to ^C themselves — the parent catches it and
    # sends SIGTERM to each worker, which _serve() handles via its event loop.
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    try:
        uvloop.run(_serve(socks, ssl_ctx))
    except Exception:
        logging.exception("Worker crashed")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="IMAP/SMTP authentication proxy")
    parser.add_argument(
        "--log", default='INFO',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        help="Set the logging level (default: %(default)s)"
    )
    parser.add_argument(
        "--workers", type=int, default=1,
        help="Number of worker processes (default: %(default)d)",
    )
    parser.add_argument(
        "--cert", default=config.PROXY_CERT_FILE,
        help="TLS certificate for client-facing listeners (default: %(default)s)",
    )
    parser.add_argument(
        "--key", default=config.PROXY_KEY_FILE,
        help="TLS private key for client-facing listeners (default: %(default)s)",
    )
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
        logging.getLogger("httpx").setLevel(logging.WARNING)

    # Build TLS context once in the parent.  Workers inherit it via fork
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.load_cert_chain(args.cert, args.key)

    # Bind all four sockets before forking so every worker shares the same
    # file descriptions.  SO_REUSEPORT lets them all call accept() in parallel.
    socks = (
        _make_tcp_socket(config.LISTEN_IMAP_HOST,  config.LISTEN_IMAP_PORT),   # IMAP  STARTTLS  143
        _make_tcp_socket(config.LISTEN_IMAPS_HOST, config.LISTEN_IMAPS_PORT),  # IMAPS implicit  993
        _make_tcp_socket(config.LISTEN_SMTP_HOST,  config.LISTEN_SMTP_PORT),   # SMTP  STARTTLS  587
        _make_tcp_socket(config.LISTEN_SMTPS_HOST, config.LISTEN_SMTPS_PORT),  # SMTPS implicit  465
    )

    logger.info("IMAP  (STARTTLS)     %s:%d", config.LISTEN_IMAP_HOST,  config.LISTEN_IMAP_PORT)
    logger.info("IMAPS (implicit TLS) %s:%d", config.LISTEN_IMAPS_HOST, config.LISTEN_IMAPS_PORT)
    logger.info("SMTP  (STARTTLS)     %s:%d", config.LISTEN_SMTP_HOST,  config.LISTEN_SMTP_PORT)
    logger.info("SMTPS (implicit TLS) %s:%d", config.LISTEN_SMTPS_HOST, config.LISTEN_SMTPS_PORT)

    if args.workers > 1:
        processes = []
        for _ in range(args.workers):
            p = multiprocessing.Process(target=_worker, args=(socks, ssl_ctx))
            p.start()
            processes.append(p)

        logger.info("Spawned %d workers (pids: %s).",
                    len(processes), ", ".join(str(p.pid) for p in processes))

        try:
            for p in processes:
                p.join()
        except KeyboardInterrupt:
            print("\nShutting down workers ...")
            for p in processes:
                p.terminate()
            for p in processes:
                p.join()

    else:
        try:
            uvloop.run(_serve(socks, ssl_ctx))
        except KeyboardInterrupt:
            print('\nShutting down.')

    for s in socks:
        s.close()


if __name__ == "__main__":
    main()
