"""Unit and security tests for activesync-enroll."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sys
import tomllib
import types
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
APP_DIR = REPO_ROOT / "activesync-enroll"
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))


def _decode_hs256(token: str, key: str, audience: str, issuer: str) -> dict:
    """Verify an HS256/384/512 compact JWS using stdlib hmac/hashlib."""
    def _b64url_decode(text: str) -> bytes:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))

    def _b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    h, p, s = token.split(".")
    header = json.loads(_b64url_decode(h))
    alg = header["alg"]
    digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[alg]
    expected = _b64url(hmac.new(key.encode("utf-8"), f"{h}.{p}".encode("ascii"), digest).digest())
    assert hmac.compare_digest(s, expected), "JWT signature mismatch"
    payload = json.loads(_b64url_decode(p))
    assert payload.get("aud") == audience
    assert payload.get("iss") == issuer
    return payload


def _ensure_jwt_module():
    """Use real PyJWT if installed, otherwise provide HS256 encode."""
    try:
        import jwt  # type: ignore
        if hasattr(jwt, "encode") and callable(jwt.encode) and not type(jwt.encode).__name__.endswith("Mock"):
            return jwt
    except ImportError:
        jwt = types.ModuleType("jwt")
        sys.modules["jwt"] = jwt

    def _b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    def encode(payload: dict, key: str, algorithm: str = "HS256") -> str:
        header = {"alg": algorithm, "typ": "JWT"}
        h = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        p = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        signing_input = f"{h}.{p}".encode("ascii")
        digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[algorithm]
        sig = hmac.new(key.encode("utf-8"), signing_input, digest).digest()
        return f"{h}.{p}.{_b64url(sig)}"

    jwt.encode = encode  # type: ignore[attr-defined]
    return jwt


def _ensure_fastapi_and_wbxml_stubs():
    """Allow importing routes.py offline even when fastapi / python-wbxml are not installed."""
    if "wbxml" not in sys.modules:
        try:
            import wbxml  # type: ignore  # noqa: F401
        except ImportError:
            wb = types.ModuleType("wbxml")
            wb.xml_to_wbxml = lambda s: b"WBXML:" + s.encode("utf-8")
            wb.wbxml_to_xml = lambda b: b.decode("utf-8").removeprefix("WBXML:")
            sys.modules["wbxml"] = wb

    if "fastapi" not in sys.modules:
        try:
            import fastapi  # type: ignore  # noqa: F401
        except ImportError:
            fa = types.ModuleType("fastapi")
            fa_resp = types.ModuleType("fastapi.responses")

            class HTTPException(Exception):
                def __init__(self, status_code: int, detail: str = "", headers=None):
                    super().__init__(detail)
                    self.status_code = status_code
                    self.detail = detail
                    self.headers = headers or {}

            class _Router:
                def get(self, *a, **kw):
                    return lambda fn: fn

                def api_route(self, *a, **kw):
                    return lambda fn: fn

            class _Status:
                HTTP_400_BAD_REQUEST = 400
                HTTP_403_FORBIDDEN = 403
                HTTP_405_METHOD_NOT_ALLOWED = 405
                HTTP_413_REQUEST_ENTITY_TOO_LARGE = 413
                HTTP_500_INTERNAL_SERVER_ERROR = 500
                HTTP_501_NOT_IMPLEMENTED = 501

            fa.APIRouter = _Router
            fa.HTTPException = HTTPException
            fa.Request = object
            fa.Response = object
            fa.status = _Status
            fa_resp.HTMLResponse = object
            fa_resp.PlainTextResponse = object

            sys.modules["fastapi"] = fa
            sys.modules["fastapi.responses"] = fa_resp


_ensure_jwt_module()
_ensure_fastapi_and_wbxml_stubs()

from activesync_enroll.config import Config, EnrollConfig, MailConfig, ServerConfig, load_config
from activesync_enroll.activesync import OnGetItemEstimate, OnHTTPOptions, OnSync
from activesync_enroll.enroll import generate_enroll_mail, generate_enroll_token, keycloak_enroll_link
from activesync_enroll.routes import (
    EnrollUser,
    decode_enroll_user,
    dispatch_activesync_command,
    verify_preview_secret,
)
from fastapi import HTTPException


def _sample_config(preview_secret: str = "") -> Config:
    return Config(
        server=ServerConfig(host="127.0.0.1", port=8000, preview_secret=preview_secret),
        enroll=EnrollConfig(
            authorization_endpoint="https://login.example/realms/Test/protocol/openid-connect/auth",
            client_id="webmail_Enroll",
            redirect_uri="https://webmail.example/ActiveSync_Enroll_Complete",
            jwt_issuer="https://webmail.example",
            jwt_audience="deviceid-enroll-authenticator",
            jwt_secret="0123456789abcdef0123456789abcdef",
            jwt_algorithm="HS256",
            token_ttl=3600,
        ),
        mail=MailConfig(
            subject="*** ACTION REQUIRED ***",
            from_name="Exchange ActiveSync MFA",
            from_address="noreply@example.org",
        ),
    )


def test_example_toml_parses_cleanly_and_validates(tmp_path: Path):
    example_path = REPO_ROOT / "deploy" / "etc" / "activesync-enroll.toml.example"
    raw = example_path.read_text(encoding="utf-8")
    parsed = tomllib.loads(raw)
    assert parsed["server"]["host"] == "127.0.0.1"
    assert parsed["server"]["port"] == 8000
    assert parsed["server"]["preview_secret"] == ""
    assert "{{mfa_link}}" in parsed["mail"]["plain_template"]
    assert "{{mfa_link}}" in parsed["mail"]["html_template"]

    valid_toml = tmp_path / "activesync-enroll.toml"
    valid_toml.write_text(raw.replace("CHANGE_ME", "0123456789abcdef0123456789abcdef"), encoding="utf-8")
    cfg = load_config(valid_toml)
    assert cfg.server.port == 8000
    assert "uniLOGIN" in cfg.mail.html_template

    # Systemd LoadCredential=config:... via CREDENTIALS_DIRECTORY
    cred_dir = tmp_path / "creds"
    cred_dir.mkdir()
    (cred_dir / "config").write_text(
        raw.replace("CHANGE_ME", "0123456789abcdef0123456789abcdef"), encoding="utf-8"
    )
    import os
    old_cred = os.environ.get("CREDENTIALS_DIRECTORY")
    old_env = os.environ.pop("ACTIVESYNC_ENROLL_CONFIG", None)
    try:
        os.environ["CREDENTIALS_DIRECTORY"] = str(cred_dir)
        cred_cfg = load_config()
        assert cred_cfg.server.port == 8000
    finally:
        if old_cred is None:
            os.environ.pop("CREDENTIALS_DIRECTORY", None)
        else:
            os.environ["CREDENTIALS_DIRECTORY"] = old_cred
        if old_env is not None:
            os.environ["ACTIVESYNC_ENROLL_CONFIG"] = old_env

    short_jwt = Config(
        server=ServerConfig(),
        enroll=EnrollConfig(
            authorization_endpoint="https://login.example/auth",
            client_id="c",
            redirect_uri="https://webmail.example/done",
            jwt_issuer="iss",
            jwt_audience="aud",
            jwt_secret="too-short",
        ),
    )
    with pytest.raises(ValueError, match="32 bytes"):
        short_jwt.validate()


def test_verify_preview_secret_disabled_wrong_and_valid():
    # Disabled when empty -> 405
    with pytest.raises(HTTPException) as exc_disabled:
        verify_preview_secret("anything", _sample_config(preview_secret=""))
    assert exc_disabled.value.status_code == 405

    # Wrong or missing when enabled -> 403
    cfg = _sample_config(preview_secret="my-preview-secret")
    with pytest.raises(HTTPException) as exc_wrong:
        verify_preview_secret("wrong", cfg)
    assert exc_wrong.value.status_code == 403

    with pytest.raises(HTTPException) as exc_none:
        verify_preview_secret(None, cfg)
    assert exc_none.value.status_code == 403

    # Exact match passes
    verify_preview_secret("my-preview-secret", cfg)


def test_decode_enroll_user_supports_utf8_umlauts_and_rejects_bad_input():
    payload = {"subject": "jmueller", "email": "juergen.mueller@example.org", "name": "Jürgen Müller"}
    b64 = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
    user = decode_enroll_user(b64)
    assert user == EnrollUser(
        subject="jmueller",
        email="juergen.mueller@example.org",
        name="Jürgen Müller",
    )

    for bad in (None, "", "not-valid-base64!!!", base64.b64encode(b"{}").decode("ascii")):
        with pytest.raises(HTTPException) as exc:
            decode_enroll_user(bad)
        assert exc.value.status_code == 400


def test_enroll_token_and_link_generation():
    cfg = _sample_config()
    tok = generate_enroll_token("alice", "APPL1234", "iPhone", expires_in=600, config=cfg)
    claims = _decode_hs256(
        tok,
        cfg.enroll.jwt_secret,
        audience=cfg.enroll.jwt_audience,
        issuer=cfg.enroll.jwt_issuer,
    )
    assert claims["sub"] == "alice"
    assert claims["DeviceId"] == "APPL1234"
    assert claims["DeviceType"] == "iPhone"
    assert claims["exp"] - claims["iat"] == 600
    assert claims["jti"]

    link = keycloak_enroll_link("alice", "APPL1234", "iPhone", config=cfg)
    assert link.startswith(cfg.enroll.authorization_endpoint + "?")
    assert "client_id=webmail_Enroll" in link
    assert "enroll_token=" in link


def test_enroll_mail_template_escaping_css_braces_and_single_pass():
    cfg = Config(
        server=_sample_config().server,
        enroll=_sample_config().enroll,
        mail=MailConfig(
            plain_template="Hi {{name}} dev={{device_id}} link={{mfa_link}}",
            html_template="<style>body { color: #000; }</style><p>{{name}} {{device_type}} {{ua}}</p><a href=\"{{mfa_link}}\">go</a>",
        ),
    )
    plain, html_body = generate_enroll_mail(
        subject="alice",
        email="alice@example.org",
        name="<b>Alice</b>",
        device_id="{{mfa_link}}",
        device_type="<img src=x onerror=alert(1)>",
        protocol_version="16.1",
        ip="203.0.113.5",
        ua="<script>evil()</script>",
        config=cfg,
    )
    assert "dev={{mfa_link}} link=https://" in plain
    assert "body { color: #000; }" in html_body
    assert "<img src=x" not in html_body
    assert "&lt;img src=x onerror=alert(1)&gt;" in html_body
    assert "<script>evil()</script>" not in html_body
    assert "&lt;script&gt;evil()&lt;/script&gt;" in html_body
    assert "&lt;b&gt;Alice&lt;/b&gt;" in html_body

    est_xss = OnGetItemEstimate("<GetItemEstimate><CollectionId>a&b</CollectionId></GetItemEstimate>")
    assert "<CollectionId>a&amp;b</CollectionId>" in est_xss

    sync_xml = OnSync(
        xml="<Sync><SyncKey>0</SyncKey><CollectionId>fakeinbox</CollectionId></Sync>",
        subject="alice",
        email="alice&bob@example.org",
        name="Alice",
        device_id="DEV1",
        device_type="iPhone",
        protocol_version="16.1",
        ip="203.0.113.5",
        ua="Apple-iPhone",
        config=cfg,
    )
    assert "<Email:To>alice&amp;bob@example.org</Email:To>" in sync_xml
    assert "<SyncKey>1</SyncKey>" in sync_xml


def test_activesync_command_dispatch_lifecycle():
    cfg = _sample_config()
    user = EnrollUser(subject="alice", email="alice@example.org", name="Alice")

    opts = OnHTTPOptions()
    assert opts["MS-Server-ActiveSync"] == "15.1"
    assert "POST" in opts["Allow"]

    p1 = dispatch_activesync_command("Provision", "<Provision/>", "", user, "D1", "iPhone", "16.1", "1.2.3.4", "UA", cfg)
    assert "<PolicyKey>0</PolicyKey>" in p1

    p2 = dispatch_activesync_command(
        "Provision", "<Provision><PolicyKey>0</PolicyKey><Status>1</Status></Provision>", "0",
        user, "D1", "iPhone", "16.1", "1.2.3.4", "UA", cfg,
    )
    assert "<PolicyKey>1337</PolicyKey>" in p2

    wp = dispatch_activesync_command("Sync", "<Sync/>", "9999", user, "D1", "iPhone", "16.1", "1.2.3.4", "UA", cfg)
    assert "<Status>144</Status>" in wp

    st = dispatch_activesync_command("Settings", "<Settings/>", "1337", user, "D1", "iPhone", "16.1", "1.2.3.4", "UA", cfg)
    assert '<Settings xmlns="Settings:">' in st

    fs = dispatch_activesync_command("FolderSync", "<FolderSync><SyncKey>0</SyncKey></FolderSync>", "1337", user, "D1", "iPhone", "16.1", "1.2.3.4", "UA", cfg)
    assert "<ServerId>fakeinbox</ServerId>" in fs and "<SyncKey>1337</SyncKey>" in fs

    sy = dispatch_activesync_command(
        "Sync", "<Sync><SyncKey>0</SyncKey><CollectionId>fakeinbox</CollectionId></Sync>", "1337",
        user, "D1", "iPhone", "16.1", "1.2.3.4", "UA", cfg,
    )
    assert "<ServerId>fakemail</ServerId>" in sy
    assert "enroll_token" in sy

    mv = dispatch_activesync_command("MoveItems", "<MoveItems/>", "1337", user, "D1", "iPhone", "16.1", "1.2.3.4", "UA", cfg)
    assert "<SrcMsgId>fakemail</SrcMsgId>" in mv

    assert dispatch_activesync_command("Ping", "", "1337", user, "D1", "iPhone", "16.1", "1.2.3.4", "UA", cfg) is None


def test_activesync_enroll_hot_reload_config(tmp_path):
    from activesync_enroll.config import get_config, reload_config, set_config

    cfg_file = tmp_path / "activesync-enroll.toml"
    cfg_file.write_text(
        """\
[server]
host = "127.0.0.1"
port = 8000
preview_secret = "secret-v1"

[enroll]
authorization_endpoint = "https://idp.example/auth"
client_id = "enroll-client"
redirect_uri = "https://webmail.example/ActiveSync_Enroll_Complete"
jwt_issuer = "https://webmail.example"
jwt_audience = "deviceid-enroll-authenticator"
jwt_secret = "0123456789abcdef0123456789abcdef"

[mail]
subject = "Subject V1"
""",
        encoding="utf-8",
    )

    try:
        cfg1 = reload_config(cfg_file)
        assert get_config().mail.subject == "Subject V1"
        assert cfg1.server.preview_secret == "secret-v1"

        # Update file on disk and hot-reload
        cfg_file.write_text(
            cfg_file.read_text(encoding="utf-8")
            .replace("Subject V1", "Subject V2")
            .replace("secret-v1", "secret-v2"),
            encoding="utf-8",
        )
        cfg2 = reload_config(cfg_file)
        assert get_config().mail.subject == "Subject V2"
        assert cfg2.server.preview_secret == "secret-v2"

        # Invalid update must raise and keep the previous valid cached config intact
        cfg_file.write_text(
            cfg_file.read_text(encoding="utf-8").replace(
                "0123456789abcdef0123456789abcdef", "too-short"
            ),
            encoding="utf-8",
        )
        with pytest.raises(ValueError, match="at least 32 bytes"):
            reload_config(cfg_file)
        assert get_config().mail.subject == "Subject V2"
        assert get_config().server.preview_secret == "secret-v2"
    finally:
        set_config(None)
