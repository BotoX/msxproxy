"""
Mock-Kerberos test wrapper for s4u2api.

Runs the real `s4u2api` TCP netstrings server, real Keycloak OIDC JWKS/JWT
verification (`s4u2api.auth`), and real Valkey HMAC-signed JWT cache + pub/sub
stampede lock (`s4u2api.logic`), substituting only the Kerberos S4U2Proxy ticket
acquisition step (`s4u2api.kerberos.kerb_proxy.create_context`) with a
deterministic mock Negotiate/GSSAPI token (`MOCK-KRB5:<upn>:<fullspn>`).
"""
from __future__ import annotations

import logging
import sys

# Ensure /opt/msxproxy/s4u2api is importable
sys.path.insert(0, "/opt/msxproxy/s4u2api")

from s4u2api import kerberos, logic, __main__ as s4u2_main  # noqa: E402

logger = logging.getLogger("mock_s4u2api")


class _MockGssContext:
    complete = True

    def step(self, _in_token: bytes | None = None) -> bytes:
        return b""

    def export(self) -> bytes:
        return b""


async def _mock_create_context(upn: str, spn: str):
    token = f"MOCK-KRB5:{upn}:{spn}".encode("utf-8")
    return _MockGssContext(), token


_orig_client_message = logic.client_message


async def _wrapped_client_message(msg, ctx, peername):
    res, next_ctx = await _orig_client_message(msg, ctx, peername)
    # Omit 'ctx' so mailproxy does not attempt to deserialize a real GSSAPI context
    res.pop("ctx", None)
    return res, next_ctx


def main() -> None:
    kerberos.kerb_proxy.create_context = _mock_create_context
    logic.client_message = _wrapped_client_message
    logger.info("Starting test s4u2api (real Keycloak JWT + Valkey cache, mock Kerberos token)")
    s4u2_main.main()


if __name__ == "__main__":
    main()
