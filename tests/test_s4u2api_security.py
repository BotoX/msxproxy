"""
Security, protocol fuzzing, TCP server integration, and concurrency tests for s4u2api.
"""
import asyncio
import base64
import random
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from s4u2api import __main__ as s4u_main
from s4u2api import aionetstrings, logic


# ── 1. aionetstrings adversarial fuzzing ─────────────────────────────────────

@pytest.mark.parametrize(
    "raw",
    [
        b"-1:,",
        b"-5:hello,",
        b"0000001:a,",            # header > 6 bytes
        b"abc:def,",              # non-integer length
        b"3:ab",                  # truncated payload
        b"3:abc;",                # wrong terminator
        b"4:test,1:x,",           # unknown type tag 'x'
        b"4:test,",               # missing value (EOF mid-pair)
        b"2:\xff\xfe,2:sa,",      # invalid UTF-8 key
        b"1:k,3:s\xff\xfe,0:,",   # invalid UTF-8 string value
        b"1:k,4:iabc,0:,",        # invalid int value
    ],
)
def test_aionetstrings_rejects_malformed_frames(raw):
    async def run():
        r = asyncio.StreamReader()
        r.feed_data(raw)
        r.feed_eof()
        with pytest.raises((ValueError, UnicodeDecodeError)):
            await aionetstrings.read_dict(r)

    asyncio.run(run())


def test_aionetstrings_random_fuzz_never_hangs_or_crashes():
    async def run():
        rng = random.Random(42)
        for _ in range(100):
            raw = bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 128)))
            r = asyncio.StreamReader()
            r.feed_data(raw)
            r.feed_eof()
            try:
                await aionetstrings.read_dict(r)
            except (ValueError, UnicodeDecodeError):
                pass

    asyncio.run(run())


# ── 2. Full TCP server integration: keepalive, multi-step GSSAPI, isolation ──

def test_s4u2api_tcp_server_multistep_and_concurrent_isolation():
    async def run():
        srv = await asyncio.start_server(s4u_main.client_connected, "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]

        def make_ctx(upn):
            ctx = MagicMock()
            ctx.complete = False
            def step_fn(tok):
                ctx.complete = True
                return f"step2:{upn}:{tok.decode()}".encode()
            ctx.step.side_effect = step_fn
            ctx.export.return_value = f"exported:{upn}".encode()
            return ctx

        async def fake_create_context(principal, fullspn):
            await asyncio.sleep(0.01)
            return make_ctx(principal), f"step1:{principal}".encode()

        async def fake_get_principal(jwt_str, oidc):
            return jwt_str  # test uses jwt == upn

        try:
            with patch.object(logic, "get_principal_cached", side_effect=fake_get_principal), \
                 patch.object(logic.kerberos.kerb_proxy, "create_context", side_effect=fake_create_context):

                async def run_client(cid: int):
                    upn = f"user{cid}@UNI.AT"
                    r, w = await asyncio.open_connection("127.0.0.1", port)
                    try:
                        # Request 1: initial impersonate with want_ctx=True (incomplete context)
                        aionetstrings.write_dict(w, {"spn": "http", "upn": upn, "jwt": upn, "ctx": True})
                        await w.drain()
                        res1 = await aionetstrings.read_dict(r)
                        assert res1["complete"] is False
                        assert base64.b64decode(res1["token"]) == f"step1:{upn}".encode()
                        assert "ctx" not in res1

                        # Request 2 on SAME connection: finish multi-step GSSAPI -> exported ctx
                        aionetstrings.write_dict(w, {"step": base64.b64encode(b"srv_tok").decode(), "ctx": True})
                        await w.drain()
                        res2 = await aionetstrings.read_dict(r)
                        assert res2["complete"] is True
                        assert base64.b64decode(res2["token"]) == f"step2:{upn}:srv_tok".encode()
                        assert res2["ctx"] == f"exported:{upn}".encode()

                        # Request 3: step again now that ctx was cleared -> error, connection stays usable
                        aionetstrings.write_dict(w, {"step": base64.b64encode(b"extra").decode()})
                        await w.drain()
                        res3 = await aionetstrings.read_dict(r)
                        assert "No context established" in res3["error"]
                    finally:
                        w.close()
                        await w.wait_closed()

                # 15 concurrent clients must never cross-contaminate GSSAPI security contexts
                await asyncio.gather(*(run_client(i) for i in range(15)))

                # Malformed client frame returns error dict and does NOT break the server
                r_bad, w_bad = await asyncio.open_connection("127.0.0.1", port)
                w_bad.write(b"99999:garbage,")
                await w_bad.drain()
                err_res = await aionetstrings.read_dict(r_bad)
                assert "error" in err_res
                w_bad.close()
                await w_bad.wait_closed()

                # Server still healthy after malformed client
                await run_client(99)
        finally:
            srv.close()
            await srv.wait_closed()

    asyncio.run(run())


# ── 3. Valkey leader/follower thundering-herd stampede test ──────────────────

class InMemoryValkey:
    def __init__(self):
        self.data = {}
        self.channels = {}

    async def get(self, key):
        return self.data.get(key)

    async def set(self, key, val, nx=False, ex=None):
        if nx and key in self.data:
            return False
        self.data[key] = val
        return True

    async def delete(self, key):
        self.data.pop(key, None)

    def pipeline(self, transaction=True):
        parent = self
        ops = []

        class Pipe:
            async def __aenter__(self):
                return self
            async def __aexit__(self, *args):
                return False
            def set(self, k, v, ex=None):
                ops.append(("set", k, v))
            def publish(self, ch, msg):
                ops.append(("pub", ch, msg))
            async def execute(self):
                for op in ops:
                    if op[0] == "set":
                        parent.data[op[1]] = op[2]
                    elif op[0] == "pub":
                        for q in list(parent.channels.get(op[1], [])):
                            await q.put({"type": "message", "data": op[2]})

        return Pipe()

    def pubsub(self):
        parent = self
        q = asyncio.Queue()
        subs = set()

        class PubSub:
            async def __aenter__(self):
                return self
            async def __aexit__(self, *args):
                for ch in list(subs):
                    await self.unsubscribe(ch)
                return False
            async def subscribe(self, ch):
                subs.add(ch)
                parent.channels.setdefault(ch, set()).add(q)
            async def unsubscribe(self, ch):
                subs.discard(ch)
                if ch in parent.channels:
                    parent.channels[ch].discard(q)
            async def listen(self):
                while True:
                    yield await q.get()

        return PubSub()


def test_valkey_leader_follower_stampede_verifies_jwt_once():
    """20 concurrent workers requesting the same uncached JWT must verify it exactly once."""
    async def run():
        fake_valkey = InMemoryValkey()
        verify_calls = 0

        class SlowOIDC:
            def verify(self, token):
                nonlocal verify_calls
                verify_calls += 1
                import time
                time.sleep(0.05)
                return {"krb5_principal": "alice@UNI.AT", "exp": int(time.time()) + 600}

        with patch.object(logic, "valkey_client", fake_valkey):
            results = await asyncio.gather(
                *(logic.get_principal_cached("same.jwt.token", SlowOIDC()) for _ in range(20))
            )

        assert all(r == "alice@UNI.AT" for r in results)
        assert verify_calls == 1, f"Expected 1 leader JWT verification, got {verify_calls}"
        # Lock key must be cleaned up after leader finishes
        assert not any(k.startswith("lock:") for k in fake_valkey.data)

    asyncio.run(run())


def test_valkey_leader_failure_caches_error_and_releases_lock():
    async def run():
        fake_valkey = InMemoryValkey()

        class FailingOIDC:
            def verify(self, token):
                raise ValueError("expired signature")

        with patch.object(logic, "valkey_client", fake_valkey):
            res = await logic.get_principal_cached("bad.jwt.token", FailingOIDC())

        assert res.startswith("ERROR: ")
        assert not any(k.startswith("lock:") for k in fake_valkey.data)

        # Tampering with the cached Valkey value must trigger cache poisoning error
        jwt_key = next(k for k in fake_valkey.data if k.startswith("jwt:"))
        fake_valkey.data[jwt_key] = "admin@UNI.AT::deadbeef"
        with patch.object(logic, "valkey_client", fake_valkey):
            with pytest.raises(ValueError, match="Cache signature invalid"):
                await logic.get_principal_cached("bad.jwt.token", FailingOIDC())

    asyncio.run(run())
