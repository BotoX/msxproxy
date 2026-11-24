"""
Root pytest configuration & offline stubs so the full test suite (tests/ and
mailproxy/tests/) runs offline on any dev/CI machine without requiring Keycloak,
Exchange, AD KDC, Valkey, or optional C extensions.
"""
import importlib
import importlib.util
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parent
for sub in ("mailproxy", "s4u2api"):
    p = str(ROOT / sub)
    if p not in sys.path:
        sys.path.insert(0, p)


def _install_stub_if_missing(name: str, attrs: dict | None = None):
    if importlib.util.find_spec(name) is not None or name in sys.modules:
        return
    mod = types.ModuleType(name)
    if attrs:
        for k, v in attrs.items():
            setattr(mod, k, v)
    sys.modules[name] = mod


if importlib.util.find_spec("gssapi") is None:
    gss_exc = types.ModuleType("gssapi.exceptions")
    gss_exc.GSSError = type("GSSError", (Exception,), {})
    gss_raw = types.ModuleType("gssapi.raw")
    gss_raw_exc = types.ModuleType("gssapi.raw.exceptions")
    gss_raw_exc.ExpiredCredentialsError = type("ExpiredCredentialsError", (Exception,), {})
    gss_raw.exceptions = gss_raw_exc
    gss_raw.creds = MagicMock()
    gss_raw.ext_krb5 = MagicMock()
    sys.modules["gssapi.exceptions"] = gss_exc
    sys.modules["gssapi.raw"] = gss_raw
    sys.modules["gssapi.raw.exceptions"] = gss_raw_exc
    _install_stub_if_missing(
        "gssapi",
        {
            "SecurityContext": MagicMock,
            "Credentials": MagicMock,
            "Name": MagicMock(side_effect=lambda name, nt=None: name),
            "NameType": types.SimpleNamespace(kerberos_principal="kerberos_principal"),
            "exceptions": gss_exc,
            "raw": gss_raw,
        },
    )

if importlib.util.find_spec("filelock") is None:
    class _DummyAsyncLock:
        def __init__(self, path):
            self.path = path
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            return False

    _install_stub_if_missing("filelock", {"AsyncUnixFileLock": _DummyAsyncLock})

if importlib.util.find_spec("redis") is None:
    redis_async = types.ModuleType("redis.asyncio")
    redis_async.Redis = MagicMock
    sys.modules["redis.asyncio"] = redis_async
    _install_stub_if_missing("redis", {"asyncio": redis_async})

if importlib.util.find_spec("httpx") is None:
    class _HTTPError(Exception):
        pass
    class _HTTPStatusError(_HTTPError):
        def __init__(self, msg="", response=None):
            super().__init__(msg)
            self.response = response

    _install_stub_if_missing(
        "httpx",
        {
            "Client": MagicMock,
            "AsyncClient": MagicMock,
            "HTTPError": _HTTPError,
            "HTTPStatusError": _HTTPStatusError,
        },
    )

if importlib.util.find_spec("jwt") is None:
    jwt_exc = types.ModuleType("jwt.exceptions")
    jwt_exc.PyJWTError = type("PyJWTError", (Exception,), {})
    sys.modules["jwt.exceptions"] = jwt_exc
    _install_stub_if_missing(
        "jwt",
        {
            "PyJWKSet": MagicMock(),
            "exceptions": jwt_exc,
            "get_unverified_header": MagicMock(),
            "decode": MagicMock(),
        },
    )

if importlib.util.find_spec("uvloop") is None:
    _install_stub_if_missing("uvloop", {"run": MagicMock()})


DUMMY_JWKS = {"keys": [{"kty": "oct", "kid": "test-kid", "k": "c2VjcmV0"}]}


# Pre-import auth modules with mocked Keycloak OIDC discovery so tests never hit
# the network during collection (including mailproxy/tests/test_auth_payloads.py).
def _mock_oidc_import(module_name: str):
    if module_name in sys.modules:
        return
    resp_wk = MagicMock()
    resp_wk.json.return_value = {
        "issuer": "https://login.example/realms/test",
        "authorization_endpoint": "https://login.example/auth",
        "token_endpoint": "https://login.example/token",
        "jwks_uri": "https://login.example/jwks",
    }
    resp_jwks = MagicMock()
    resp_jwks.json.return_value = DUMMY_JWKS
    client = MagicMock()
    client.__enter__.return_value = client
    client.get.side_effect = [resp_wk, resp_jwks]
    with patch("httpx.Client", return_value=client):
        importlib.import_module(module_name)


_mock_oidc_import("mailproxy.auth")
_mock_oidc_import("s4u2api.auth")
