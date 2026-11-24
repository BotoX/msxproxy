import asyncio
import logging
import ssl
from itertools import cycle
from . import config

logger = logging.getLogger(__name__)


class Backend:
    def __init__(self, name: str, host: str, port: int, is_tls: bool):
        self.name = name
        self.host = host
        self.port = port
        self.is_tls = is_tls
        self.is_up = False
        self.failures = 0
        self.successes = 0

    @property
    def key(self) -> tuple[str, int, bool]:
        return (self.host, self.port, self.is_tls)

    def mark_failed(self, fall_threshold: int):
        self.failures += 1
        self.successes = 0
        if self.is_up and self.failures >= fall_threshold:
            self.is_up = False
            logger.warning(f"[{self.name}] Backend {self.host}:{self.port} is DOWN.")

    def mark_success(self, rise_threshold: int):
        self.successes += 1
        self.failures = 0
        if not self.is_up and self.successes >= rise_threshold:
            self.is_up = True
            logger.info(f"[{self.name}] Backend {self.host}:{self.port} is UP.")


class LoadBalancer:
    def __init__(self, name: str, backends: list[tuple[str, int, bool]]):
        self.name = name
        self.backends = [Backend(name, h, p, t) for h, p, t in backends]
        self._cycle = cycle(self.backends) if self.backends else iter(())
        self._ssl_ctx = ssl.create_default_context()
        self._task = None

    @classmethod
    async def create(cls, name: str, backends: list[tuple[str, int, bool]]):
        instance = cls(name, backends)
        await instance.worker(True)
        instance._task = asyncio.create_task(instance.worker(), name=name)
        return instance

    def cancel(self):
        if self._task:
            self._task.cancel()
            return self._task

    async def _probe(self, backend: Backend, init: bool = False) -> None:
        try:
            async with asyncio.timeout(config.LB_TIMEOUT):
                reader, writer = await asyncio.open_connection(
                    backend.host,
                    backend.port,
                    ssl=self._ssl_ctx if backend.is_tls else None,
                )
                writer.close()
                await writer.wait_closed()

            backend.mark_success(1 if init else config.LB_RISE)
        except Exception as e:
            logger.debug(f"[{self.name}] Health check failed for {backend.host}:{backend.port} - {e}")
            backend.mark_failed(config.LB_FALL)

    async def reload(self, backends: list[tuple[str, int, bool]]) -> None:
        """
        Hot-reload backend list for new connections without affecting active sessions.
        Preserves UP/DOWN state of unchanged backends and immediately probes newly added ones.
        """
        if not backends:
            logger.error(f"[{self.name}] Refusing to reload empty backend list; keeping existing backends.")
            return

        existing = {b.key: b for b in self.backends}
        updated: list[Backend] = []
        newly_added: list[Backend] = []

        for h, p, t in backends:
            key = (h, p, t)
            if key in existing:
                updated.append(existing[key])
            else:
                b = Backend(self.name, h, p, t)
                updated.append(b)
                newly_added.append(b)

        if newly_added:
            await asyncio.gather(*(self._probe(b, init=True) for b in newly_added))

        removed = [b for b in self.backends if b.key not in {u.key for u in updated}]
        self.backends = updated
        self._cycle = cycle(self.backends)

        logger.info(
            f"[{self.name}] Reloaded backends: {len(updated)} total "
            f"(+{len(newly_added)} added, -{len(removed)} removed)."
        )

    async def connect(
        self,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, str, ssl.SSLContext]:
        """
        Attempts to connect to healthy backends in round-robin order.
        Returns (reader, writer, host, ssl_ctx) or raises ConnectionError if all fail.
        """
        backends = self.backends
        for _ in range(len(backends)):
            backend = next(self._cycle)
            if not backend.is_up:
                continue

            try:
                async with asyncio.timeout(config.LB_TIMEOUT):
                    reader, writer = await asyncio.open_connection(
                        backend.host,
                        backend.port,
                        ssl=self._ssl_ctx if backend.is_tls else None,
                    )

                backend.mark_success(config.LB_RISE)
                return reader, writer, backend.host, self._ssl_ctx

            except Exception as e:
                logger.warning(f"[{self.name}] Failed to connect to {backend.host}: {e}")
                backend.mark_failed(config.LB_FALL)
                continue

        raise ConnectionError(f"[{self.name}] All backends are currently unavailable or DOWN")

    async def worker(self, init=False):
        """Active health check: background task that probes servers."""
        while True:
            for backend in list(self.backends):
                await self._probe(backend, init=init)

            if init:
                break
            await asyncio.sleep(config.LB_CHECK_INTERVAL)
