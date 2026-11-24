"""
Lightweight, zero-dependency Prometheus metrics for mailproxy.

Uses multiprocessing.Value shared-memory counters so metrics aggregate cleanly
across forked worker processes without needing external packages.
"""
import asyncio
import contextlib
import logging
import multiprocessing

logger = logging.getLogger(__name__)


class MetricsRegistry:
    def __init__(self) -> None:
        self._counters = {
            ("imap", "conn_total"): multiprocessing.Value("Q", 0),
            ("smtp", "conn_total"): multiprocessing.Value("Q", 0),
            ("imap", "conn_active"): multiprocessing.Value("q", 0),
            ("smtp", "conn_active"): multiprocessing.Value("q", 0),
            ("imap", "auth_ok"): multiprocessing.Value("Q", 0),
            ("imap", "auth_failed"): multiprocessing.Value("Q", 0),
            ("imap", "auth_trusted_network_denied"): multiprocessing.Value("Q", 0),
            ("imap", "auth_error"): multiprocessing.Value("Q", 0),
            ("imap", "backend_error"): multiprocessing.Value("Q", 0),
            ("smtp", "auth_ok"): multiprocessing.Value("Q", 0),
            ("smtp", "auth_failed"): multiprocessing.Value("Q", 0),
            ("smtp", "auth_trusted_network_denied"): multiprocessing.Value("Q", 0),
            ("smtp", "auth_error"): multiprocessing.Value("Q", 0),
            ("smtp", "backend_error"): multiprocessing.Value("Q", 0),
        }

    def inc(self, protocol: str, name: str, delta: int = 1) -> None:
        counter = self._counters.get((protocol, name))
        if counter is not None:
            with counter.get_lock():
                counter.value += delta

    def dec(self, protocol: str, name: str, delta: int = 1) -> None:
        counter = self._counters.get((protocol, name))
        if counter is not None:
            with counter.get_lock():
                counter.value = max(0, counter.value - delta)

    def get(self, protocol: str, name: str) -> int:
        counter = self._counters.get((protocol, name))
        return int(counter.value) if counter is not None else 0

    def render(self, load_balancers: list | None = None) -> str:
        lines = [
            "# HELP mailproxy_connections_total Total client connections accepted.",
            "# TYPE mailproxy_connections_total counter",
            f'mailproxy_connections_total{{protocol="imap"}} {self.get("imap", "conn_total")}',
            f'mailproxy_connections_total{{protocol="smtp"}} {self.get("smtp", "conn_total")}',
            "# HELP mailproxy_connections_active Currently active client connections.",
            "# TYPE mailproxy_connections_active gauge",
            f'mailproxy_connections_active{{protocol="imap"}} {self.get("imap", "conn_active")}',
            f'mailproxy_connections_active{{protocol="smtp"}} {self.get("smtp", "conn_active")}',
            "# HELP mailproxy_auth_total Client authentication outcomes.",
            "# TYPE mailproxy_auth_total counter",
        ]
        for proto in ("imap", "smtp"):
            for result, key in (
                ("ok", "auth_ok"),
                ("failed", "auth_failed"),
                ("trusted_network_denied", "auth_trusted_network_denied"),
                ("error", "auth_error"),
            ):
                lines.append(
                    f'mailproxy_auth_total{{protocol="{proto}",result="{result}"}} {self.get(proto, key)}'
                )

        lines.extend([
            "# HELP mailproxy_backend_errors_total Backend connection or GSSAPI auth failures.",
            "# TYPE mailproxy_backend_errors_total counter",
            f'mailproxy_backend_errors_total{{protocol="imap"}} {self.get("imap", "backend_error")}',
            f'mailproxy_backend_errors_total{{protocol="smtp"}} {self.get("smtp", "backend_error")}',
        ])

        if load_balancers:
            lines.extend([
                "# HELP mailproxy_backend_up Health status of Exchange backends (1=UP, 0=DOWN).",
                "# TYPE mailproxy_backend_up gauge",
            ])
            for lb in load_balancers:
                pool = lb.name.lower().replace("-lb", "")
                for b in lb.backends:
                    val = 1 if b.is_up else 0
                    lines.append(
                        f'mailproxy_backend_up{{pool="{pool}",backend="{b.host}:{b.port}"}} {val}'
                    )

        return "\n".join(lines) + "\n"


metrics = MetricsRegistry()


async def start_metrics_server(
    host: str,
    port: int,
    load_balancers: list | None = None,
) -> asyncio.Server:
    async def handle_http(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            req_line = await asyncio.wait_for(reader.readline(), timeout=5.0)
            if not req_line:
                return
            # Drain remaining request headers
            while True:
                hdr = await asyncio.wait_for(reader.readline(), timeout=5.0)
                if not hdr or hdr in (b"\r\n", b"\n"):
                    break

            parts = req_line.decode("latin1", errors="replace").split()
            path = parts[1] if len(parts) >= 2 else "/"

            if path == "/metrics":
                body = metrics.render(load_balancers).encode("utf-8")
                resp = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n"
                    + f"Content-Length: {len(body)}\r\n".encode("ascii")
                    + b"Connection: close\r\n\r\n"
                    + body
                )
            else:
                body = b"Not Found\n"
                resp = (
                    b"HTTP/1.1 404 Not Found\r\n"
                    b"Content-Type: text/plain\r\n"
                    + f"Content-Length: {len(body)}\r\n".encode("ascii")
                    + b"Connection: close\r\n\r\n"
                    + body
                )

            writer.write(resp)
            await writer.drain()
        except Exception:
            pass
        finally:
            with contextlib.suppress(Exception):
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=1.0)

    server = await asyncio.start_server(handle_http, host, port)
    logger.info("Prometheus metrics listening on http://%s:%d/metrics", host, port)
    return server
