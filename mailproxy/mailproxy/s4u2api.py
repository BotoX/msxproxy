import asyncio
import contextlib
import gssapi
import base64
import logging

from . import aionetstrings
from .config import (
    S4U2API_HOST,
    S4U2API_PORT
)

logger = logging.getLogger(__name__)

class S4U2ApiConnection:
    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        self.reader = reader
        self.writer = writer
        self.complete = False
        self.ctx = None

    async def impersonate(self, upn: str, jwt: str, spn: str):
        req = {
            'spn': 'http',
            'upn': upn,
            'jwt': jwt,
            'ctx': True
        }

        aionetstrings.write_dict(self.writer, req)
        await self.writer.drain()

        res = await asyncio.wait_for(
            aionetstrings.read_dict(self.reader), timeout=5
        )
        if res is None:
            raise ValueError('EOF / disconnect')
        if 'error' in res:
            raise ValueError(f'S4U2Api Error: {res["error"]}')

        token = res['token']
        self.complete = res['complete']

        if self.complete and 'ctx' in res:
            self.ctx = gssapi.SecurityContext(token=res['ctx'])

        return token

    async def step(self, token: bytes) -> bytes:
        """Perform a network-bound ctx.step() on the remote server."""
        req = {
            'step': base64.b64encode(token).decode(),
            'ctx': True
        }

        aionetstrings.write_dict(self.writer, req)
        await self.writer.drain()

        res = await asyncio.wait_for(
            aionetstrings.read_dict(self.reader), timeout=5
        )
        if res is None:
            raise ValueError('EOF / disconnect')
        if 'error' in res:
            raise ValueError(f'S4U2Api Error: {res["error"]}')

        token = res['token']
        self.complete = res['complete']

        if self.complete and 'ctx' in res:
            self.ctx = gssapi.SecurityContext(token=res['ctx'])

        return token


class S4U2ApiClient:
    def __init__(
        self,
        host: str,
        port: int
    ) -> None:
        self.host = host
        self.port = port

    @contextlib.asynccontextmanager
    async def connection(self):
        """Yields an active S4U2ApiConnection tied to a single socket."""
        reader, writer = await asyncio.open_connection(self.host, self.port)
        conn = S4U2ApiConnection(reader, writer)
        try:
            yield conn
        finally:
            writer.close()
            await writer.wait_closed()


s4u2api = S4U2ApiClient(
    host=S4U2API_HOST,
    port=S4U2API_PORT
)
