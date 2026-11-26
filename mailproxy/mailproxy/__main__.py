import asyncio
import os
import signal
import socket
import ssl
import logging
import argparse
import multiprocessing
import uvloop

from . import auth, config
from .imap_proxy import ImapProxyServer
from .smtp_proxy import SmtpProxyServer
from .loadbalancer import LoadBalancer
from .metrics import start_metrics_server

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


def _load_certs(ssl_ctx: ssl.SSLContext) -> None:
    if not config.PROXY_CERTS:
        raise ValueError("No TLS certificates configured in [proxy].certs")
    for cert_path, key_path in config.PROXY_CERTS:
        ssl_ctx.load_cert_chain(cert_path, key_path)


async def _serve(
    socks: tuple[socket.socket, ...],
    ssl_ctx: ssl.SSLContext,
    metrics_host: str = "127.0.0.1",
    metrics_port: int | None = None,
) -> None:
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
    metrics_srv = (
        await start_metrics_server(metrics_host, metrics_port, [imap_lb, smtp_lb])
        if metrics_port
        else None
    )

    stop_event = asyncio.Event()

    def _request_stop() -> None:
        if not stop_event.is_set():
            logger.info("Shutdown requested.")
            stop_event.set()

    async def _do_hot_reload() -> None:
        logger.info("SIGHUP received: hot-reloading config, TLS certificates, and OIDC JWKS...")
        try:
            config.load_config()
        except Exception as e:
            logger.error("Hot reload failed while reading %s: %s (keeping previous config)", config.CONFIG_PATH, e)
            return

        try:
            _load_certs(ssl_ctx)
            logger.info("Reloaded %d TLS certificate chain(s).", len(config.PROXY_CERTS))
        except Exception as e:
            logger.error("Hot reload failed to load TLS certs: %s (keeping previous certs)", e)

        try:
            await loop.run_in_executor(None, auth.oidc.reload_from_config)
            logger.info("Reloaded OIDC settings and JWKS.")
        except Exception as e:
            logger.error("Hot reload failed to refresh OIDC/JWKS: %s (keeping previous JWKS)", e)

        try:
            await asyncio.gather(
                imap_lb.reload(config.IMAP_BACKENDS),
                smtp_lb.reload(config.SMTP_BACKENDS),
            )
        except Exception as e:
            logger.error("Hot reload failed to update backends: %s (keeping previous backends)", e)

    def _request_reload() -> None:
        asyncio.create_task(_do_hot_reload())

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _request_stop)
    loop.add_signal_handler(signal.SIGHUP, _request_reload)

    # Stop accepting new connections as soon as the stop event fires.
    async with imap_srv, imaps_srv, smtp_srv, smtps_srv:
        if metrics_srv is not None:
            async with metrics_srv:
                await stop_event.wait()
        else:
            await stop_event.wait()

    # Stop load balancers and shared HTTP client
    await asyncio.gather(
        imap_lb.cancel(),
        smtp_lb.cancel(),
        auth.oidc.aclose(),
        return_exceptions=True,
    )

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


def _worker(
    socks: tuple[socket.socket, ...],
    ssl_ctx: ssl.SSLContext,
    metrics_host: str = "127.0.0.1",
    metrics_port: int | None = None,
) -> None:
    # Workers must not react to ^C themselves — the parent catches it and
    # sends SIGTERM to each worker, which _serve() handles via its event loop.
    # Ignore SIGHUP until _serve() registers its async hot-reload handler.
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGHUP, signal.SIG_IGN)

    try:
        uvloop.run(_serve(socks, ssl_ctx, metrics_host, metrics_port))
    except Exception:
        logging.exception("Worker crashed")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="IMAP/SMTP authentication proxy")
    parser.add_argument(
        "--config", default=None,
        help=f"Path to mailproxy TOML config (default: {config.CONFIG_PATH})",
    )
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
        "--metrics-host", default="127.0.0.1",
        help="Bind host for Prometheus /metrics endpoint (default: %(default)s)",
    )
    parser.add_argument(
        "--metrics-port", type=int, default=None,
        help="Bind port for Prometheus /metrics endpoint (disabled if omitted)",
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

    if args.config:
        config.load_config(args.config, required=True)
        auth.oidc.reload_from_config()

    # Build TLS context once in the parent.  Workers inherit it via fork
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    _load_certs(ssl_ctx)

    # Bind all four sockets before forking so every worker shares the same
    # listening file descriptors.
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
        mp_ctx = multiprocessing.get_context("fork")
        processes = []
        for idx in range(args.workers):
            # Only worker 0 serves /metrics (counters are shared via multiprocessing.Value)
            w_metrics_port = args.metrics_port if idx == 0 else None
            p = mp_ctx.Process(
                target=_worker,
                args=(socks, ssl_ctx, args.metrics_host, w_metrics_port),
            )
            p.start()
            processes.append(p)

        def _forward_sighup(signum, frame):
            logger.info("Forwarding SIGHUP to %d worker(s)...", len(processes))
            for p in processes:
                if p.is_alive() and p.pid:
                    os.kill(p.pid, signal.SIGHUP)

        def _forward_sigterm(signum, frame):
            logger.info("SIGTERM received: shutting down %d worker(s)...", len(processes))
            for p in processes:
                if p.is_alive():
                    p.terminate()

        signal.signal(signal.SIGHUP, _forward_sighup)
        signal.signal(signal.SIGTERM, _forward_sigterm)

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
            uvloop.run(_serve(socks, ssl_ctx, args.metrics_host, args.metrics_port))
        except KeyboardInterrupt:
            print('\nShutting down.')

    for s in socks:
        s.close()


if __name__ == "__main__":
    main()
