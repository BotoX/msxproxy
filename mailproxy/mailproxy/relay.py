import asyncio
import contextlib


async def relay(
    reader1: asyncio.StreamReader,
    writer1: asyncio.StreamWriter,
    reader2: asyncio.StreamReader,
    writer2: asyncio.StreamWriter,
    drain_timeout: float = 3.0,
) -> None:
    """
    Bidirectionally relay bytes between two asyncio stream pairs.

    When one direction reaches EOF, the other is given `drain_timeout` seconds
    to flush any in-flight data (e.g. a final IMAP untagged response sent
    by the server after the client exits IDLE) before being hard-cancelled.
    """

    async def pipe(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        try:
            while True:
                data = await r.read(4096)
                if not data:
                    break
                w.write(data)
                await w.drain()
        except (asyncio.CancelledError, ConnectionError, OSError):
            pass
        finally:
            # Signal EOF to the other side; do NOT await wait_closed() —
            # it blocks until the remote TCP peer acknowledges the FIN.
            with contextlib.suppress(Exception):
                w.close()

    t1 = asyncio.create_task(pipe(reader1, writer2))
    t2 = asyncio.create_task(pipe(reader2, writer1))

    try:
        _done, pending = await asyncio.wait(
            [t1, t2], return_when=asyncio.FIRST_COMPLETED
        )
        if pending:
            # One side closed; let the other drain remaining data gracefully.
            # asyncio.wait() with a timeout returns without cancelling tasks,
            # so the finally block below always runs regardless of outcome.
            await asyncio.wait(pending, timeout=drain_timeout)
    except asyncio.CancelledError:
        pass
    finally:
        for t in (t1, t2):
            t.cancel()
        await asyncio.gather(t1, t2, return_exceptions=True)
