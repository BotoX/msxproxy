"""Unit tests for s4u2api (offline, no Keycloak/KDC/Valkey required)."""
import asyncio
import importlib
import os
import shutil
import struct
import subprocess
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _import_s4u2api_modules():
    if "s4u2api.auth" not in sys.modules:
        mock_resp_wk = MagicMock()
        mock_resp_wk.json.return_value = {
            "issuer": "https://login.example/realms/test",
            "authorization_endpoint": "https://login.example/auth",
            "token_endpoint": "https://login.example/token",
            "jwks_uri": "https://login.example/jwks",
        }
        mock_resp_jwks = MagicMock()
        mock_resp_jwks.json.return_value = {"keys": [{"kty": "oct", "kid": "test-kid", "k": "c2VjcmV0"}]}
        mock_client = MagicMock()
        mock_client.__enter__.return_value = mock_client
        mock_client.get.side_effect = [mock_resp_wk, mock_resp_jwks]
        with patch("httpx.Client", return_value=mock_client):
            importlib.import_module("s4u2api.auth")

    aionetstrings = importlib.import_module("s4u2api.aionetstrings")
    logic = importlib.import_module("s4u2api.logic")
    kerberos = importlib.import_module("s4u2api.kerberos")
    return aionetstrings, logic, kerberos


aionetstrings, logic, kerberos = _import_s4u2api_modules()


class BufferWriter:
    def __init__(self):
        self.buf = bytearray()

    def writelines(self, chunks):
        for c in chunks:
            self.buf.extend(c)


# ── aionetstrings tests ──────────────────────────────────────────────────────

def test_aionetstrings_dict_roundtrip():
    async def run():
        payload = {
            "none": None,
            "true": True,
            "false": False,
            "bytes": b"a\x00byte\x01string",
            "str": "hello unicode üöä",
            "int": 12345,
        }
        w = BufferWriter()
        aionetstrings.write_dict(w, payload)

        r = asyncio.StreamReader()
        r.feed_data(bytes(w.buf))
        r.feed_eof()

        decoded = await aionetstrings.read_dict(r)
        assert decoded == payload
        # Clean EOF returns None
        assert await aionetstrings.read_dict(r) is None

    asyncio.run(run())


def test_aionetstrings_rejects_oversize_and_corrupt():
    async def run():
        r1 = asyncio.StreamReader()
        r1.feed_data(b"99999:abc,")
        r1.feed_eof()
        with pytest.raises(ValueError, match="exceeds limit"):
            await aionetstrings.read(r1)

        r2 = asyncio.StreamReader()
        r2.feed_data(b"3:abcX")
        r2.feed_eof()
        with pytest.raises(ValueError, match="Missing delimiter"):
            await aionetstrings.read(r2)

    asyncio.run(run())


# ── HMAC cache signing & client_message validation ───────────────────────────

def test_cache_hmac_signing_and_poisoning_detection():
    signed = logic.sign_cache_value("alice@EXAMPLE.COM", "hash1")
    assert logic.verify_cache_value(signed, "hash1") == "alice@EXAMPLE.COM"

    # Cross-key replay must fail
    with pytest.raises(ValueError, match="Cache signature invalid"):
        logic.verify_cache_value(signed, "hash2")

    # Tampered principal must fail
    tampered = signed.replace("alice", "admin")
    with pytest.raises(ValueError, match="Cache signature invalid"):
        logic.verify_cache_value(tampered, "hash1")


def test_client_message_validation():
    async def run():
        # Finding #13: step without ctx must RAISE ValueError (not return it)
        with pytest.raises(ValueError, match="No context established"):
            await logic.client_message({"step": "YQ=="}, None, "127.0.0.1")

        # Invalid SPN rejected
        with pytest.raises(ValueError, match="Invalid spn"):
            await logic.client_message(
                {"spn": "evil", "upn": "a@B", "jwt": "tok"}, None, "127.0.0.1"
            )

        # UPN mismatch rejected
        with patch.object(logic, "get_principal_cached", AsyncMock(return_value="bob@EXAMPLE.COM")):
            with pytest.raises(ValueError, match="upn missmatch"):
                await logic.client_message(
                    {"spn": "http", "upn": "alice@EXAMPLE.COM", "jwt": "tok"}, None, "127.0.0.1"
                )

        # Cached ERROR principal raises ValueError
        with patch.object(logic, "get_principal_cached", AsyncMock(return_value="ERROR: bad token")):
            with pytest.raises(ValueError, match="ERROR: bad token"):
                await logic.client_message(
                    {"spn": "http", "upn": "alice@EXAMPLE.COM", "jwt": "tok"}, None, "127.0.0.1"
                )

    asyncio.run(run())


# ── KerberosProxy UPN path & atomic ccache replacement (finding #14) ─────────

def test_upn_ccache_path_validation(tmp_path):
    kp = kerberos.KerberosProxy("FILE:/tmp/fake.keytab", "svc@EXAMPLE.COM", str(tmp_path))

    path = kp._upn_ccache_path("alice@PERS.AD.UNI-GRAZ.AT")
    assert path.startswith(str(tmp_path) + "/PERS_alice_")

    with pytest.raises(ValueError, match="Invalid UPN"):
        kp._upn_ccache_path("no-at-sign")

    with pytest.raises(ValueError, match="Invalid UPN"):
        kp._upn_ccache_path("a@b@c")


def test_store_ccache_atomic_success_and_cleanup_on_failure(tmp_path):
    kp = kerberos.KerberosProxy("FILE:/tmp/fake.keytab", "svc@EXAMPLE.COM", str(tmp_path))
    target = str(tmp_path / "PERS_alice_12345678")

    # Simulate creds.store writing to the temp path
    creds_ok = MagicMock()
    def fake_store(usage, store, overwrite):
        tmp_file = store["ccache"].removeprefix("FILE:")
        assert tmp_file != target
        assert tmp_file.endswith(".tmp")
        with open(tmp_file, "wb") as f:
            f.write(b"KRB5_CCACHE_V4_DATA")
    creds_ok.store.side_effect = fake_store

    kp._store_ccache_atomic(creds_ok, target)
    assert os.path.isfile(target)
    assert open(target, "rb").read() == b"KRB5_CCACHE_V4_DATA"
    # No leftover .tmp files
    assert [p for p in os.listdir(tmp_path) if p.endswith(".tmp")] == []

    # Simulate creds.store failing midway -> original file untouched, temp file removed
    creds_fail = MagicMock()
    creds_fail.store.side_effect = RuntimeError("disk full")
    with pytest.raises(RuntimeError, match="disk full"):
        kp._store_ccache_atomic(creds_fail, target)

    assert open(target, "rb").read() == b"KRB5_CCACHE_V4_DATA"
    assert [p for p in os.listdir(tmp_path) if p.endswith(".tmp")] == []


def test_s4u2api_toml_config_and_credential_precedence(tmp_path, monkeypatch):
    from s4u2api import config as s4u_cfg

    cfg_file = tmp_path / "s4u2api.toml"
    cfg_file.write_text(
        """
[oidc]
audience = "aud_s4u"

[valkey]
socket = "/tmp/test_valkey.sock"

[kerberos]
principal = "svc@TEST.LOCAL"
ccache_dir = "/tmp/test_ccache"
keytab = "FILE:/tmp/toml.keytab"

[valid_spns]
http = "http/mail.test.local@TEST.LOCAL"
imap = "imap/mail.test.local@TEST.LOCAL"
""",
        encoding="utf-8",
    )

    orig_path = s4u_cfg.CONFIG_PATH
    orig_spns = dict(s4u_cfg.VALID_SPNS)
    orig_kt = s4u_cfg.KRB5_CLIENT_KTNAME
    orig_aud = s4u_cfg.OIDC_AUDIENCE
    orig_sock = s4u_cfg.VALKEY_SOCK
    orig_princ = s4u_cfg.KRB5_PRINCIPAL
    orig_cc = s4u_cfg.KRB5_CCACHE_DIR
    try:
        monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
        assert s4u_cfg.load_config(cfg_file, required=True) is True
        assert s4u_cfg.OIDC_AUDIENCE == "aud_s4u"
        assert s4u_cfg.VALKEY_SOCK == "/tmp/test_valkey.sock"
        assert s4u_cfg.KRB5_CLIENT_KTNAME == "FILE:/tmp/toml.keytab"
        assert "imap" in s4u_cfg.VALID_SPNS

        # systemd LoadCredential overrides keytab path from TOML
        cred_dir = tmp_path / "creds"
        cred_dir.mkdir()
        (cred_dir / "krb5_keytab").write_bytes(b"KT")
        monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(cred_dir))
        assert s4u_cfg.load_config(cfg_file, required=True) is True
        assert s4u_cfg.KRB5_CLIENT_KTNAME == str(cred_dir / "krb5_keytab")
    finally:
        s4u_cfg.CONFIG_PATH = orig_path
        s4u_cfg.VALID_SPNS.clear()
        s4u_cfg.VALID_SPNS.update(orig_spns)
        s4u_cfg.KRB5_CLIENT_KTNAME = orig_kt
        s4u_cfg.OIDC_AUDIENCE = orig_aud
        s4u_cfg.VALKEY_SOCK = orig_sock
        s4u_cfg.KRB5_PRINCIPAL = orig_princ
        s4u_cfg.KRB5_CCACHE_DIR = orig_cc


# ── Pure-Python MIT krb5 ccache v3/v4 parser tests ───────────────────────────

def _pack_counted(b: bytes) -> bytes:
    return struct.pack(">I", len(b)) + b


def _pack_principal(name: str, name_type: int = 1) -> bytes:
    body, realm = name.split("@", 1)
    comps = body.split("/")
    out = struct.pack(">II", name_type, len(comps)) + _pack_counted(realm.encode())
    for c in comps:
        out += _pack_counted(c.encode())
    return out


def _build_ccache(version: int, default_princ: str, creds: list[tuple[str, str, int]], header: bytes = b"") -> bytes:
    buf = bytearray(struct.pack(">H", version))
    if version == 0x0504:
        buf += struct.pack(">H", len(header)) + header
    buf += _pack_principal(default_princ)
    for client, server, endtime in creds:
        buf += _pack_principal(client)
        buf += _pack_principal(server, name_type=2)
        # keyblock: enctype 18 (aes256-cts-hmac-sha1-96), counted_octet_string (uint32 len) 32-byte key
        if version == 0x0503:
            buf += struct.pack(">HH", 18, 18) + _pack_counted(b"\xaa" * 32)
        else:
            buf += struct.pack(">H", 18) + _pack_counted(b"\xaa" * 32)
        # times: authtime, starttime, endtime, renew_till
        authtime = max(0, endtime - 36000) if endtime else 0
        renew = (endtime + 86400) if endtime else 0
        buf += struct.pack(">IIII", authtime, authtime, endtime, renew)
        buf += struct.pack(">BI", 0, 0x40A00000)  # is_skey=0, ticket_flags
        # 1 address + 1 authdata entry to exercise skipping logic
        buf += struct.pack(">IH", 1, 2) + _pack_counted(b"\x7f\x00\x00\x01")
        buf += struct.pack(">IH", 1, 1) + _pack_counted(b"ad_payload")
        buf += _pack_counted(b"TICKET_ASN1_BYTES") + _pack_counted(b"")
    return bytes(buf)


def test_ccache_parser_v4_v3_config_entries_and_klist_compat(tmp_path):
    from s4u2api.ccache import CCACHE_V3, CCACHE_V4, get_ticket_endtime, iter_ccache_tickets

    spn = "http/email.uni-graz.at@PERS.AD.UNI-GRAZ.AT"
    client = "alice@PERS.AD.UNI-GRAZ.AT"
    deltatime_hdr = struct.pack(">HHII", 1, 8, 0, 0)  # standard v4 DeltaTime tag

    # Include TGT, X-CACHECONF entry (endtime=0), older expired SPN ticket, and newer renewed SPN ticket
    v4_bytes = _build_ccache(
        CCACHE_V4,
        client,
        [
            (client, "krbtgt/PERS.AD.UNI-GRAZ.AT@PERS.AD.UNI-GRAZ.AT", 1900000000),
            (client, "krb5_ccache_conf_data/fast_avail/krbtgt@X-CACHECONF:", 0),
            (client, spn, 1800000000),
            (client, spn, 1950000000),
        ],
        header=deltatime_hdr,
    )
    v4_file = tmp_path / "cc_v4"
    v4_file.write_bytes(v4_bytes)

    assert get_ticket_endtime(v4_file, spn) == 1950000000
    assert get_ticket_endtime(v4_file, "imap/other@PERS.AD.UNI-GRAZ.AT") is None
    assert get_ticket_endtime(tmp_path / "missing", spn) is None

    # Cross-verify byte-level compatibility against real MIT Kerberos `klist` when available!
    klist = shutil.which("klist")
    if klist:
        res = subprocess.run([klist, "-c", f"FILE:{v4_file}"], capture_output=True, text=True)
        assert res.returncode == 0, f"MIT klist rejected our v4 ccache: {res.stderr}"
        assert client in res.stdout
        assert spn in res.stdout

    # Version 3 (0x0503) compatibility
    v3_bytes = _build_ccache(CCACHE_V3, client, [(client, spn, 1960000000)])
    v3_file = tmp_path / "cc_v3"
    v3_file.write_bytes(v3_bytes)
    assert get_ticket_endtime(v3_file, spn) == 1960000000

    # Corrupt / truncated / unsupported version rejected cleanly
    with pytest.raises(ValueError, match="Unsupported ccache version"):
        list(iter_ccache_tickets(b"\x05\x01\x00\x00"))
    with pytest.raises(ValueError, match="Truncated or corrupt"):
        list(iter_ccache_tickets(v4_bytes[:30]))


def test_kerberos_get_creds_uses_pure_python_ccache_and_gssapi(tmp_path):
    import time as _time
    from s4u2api.ccache import CCACHE_V4

    spn = "http/email.uni-graz.at@PERS.AD.UNI-GRAZ.AT"
    client = "alice@PERS.AD.UNI-GRAZ.AT"
    kp = kerberos.KerberosProxy("FILE:/tmp/fake.keytab", "svc@PERS.AD.UNI-GRAZ.AT", str(tmp_path), min_lifetime=300)

    # Fresh ticket (valid > 300s) -> loads gssapi.Credentials and returns (creds, True)
    cc_fresh = tmp_path / "fresh"
    cc_fresh.write_bytes(_build_ccache(CCACHE_V4, client, [(client, spn, int(_time.time()) + 3600)]))
    with patch("s4u2api.kerberos.gssapi.Credentials", return_value="MOCK_GSS_CREDS") as mock_creds:
        creds, valid = kp._krb5_get_creds(str(cc_fresh), client, spn)
        assert creds == "MOCK_GSS_CREDS" and valid is True
        mock_creds.assert_called_once()

    # Expiring ticket (< 300s left) -> returns (None, False) without touching gssapi.Credentials
    cc_exp = tmp_path / "expiring"
    cc_exp.write_bytes(_build_ccache(CCACHE_V4, client, [(client, spn, int(_time.time()) + 60)]))
    with patch("s4u2api.kerberos.gssapi.Credentials") as mock_creds:
        creds, valid = kp._krb5_get_creds(str(cc_exp), client, spn)
        assert creds is None and valid is False
        mock_creds.assert_not_called()


def test_s4u2api_oidc_and_kerberos_hot_reload(tmp_path):
    import s4u2api.auth as s4u_auth
    import s4u2api.config as s4u_cfg

    # 1. OIDC reload: swaps config + JWKS atomically on success, preserves previous state on failure
    mock_resp_wk_1 = MagicMock()
    mock_resp_wk_1.json.return_value = {
        "issuer": "https://login.example/realms/r1",
        "jwks_uri": "https://login.example/jwks1",
    }
    mock_resp_jwks_1 = MagicMock()
    mock_resp_jwks_1.json.return_value = {"keys": [{"kty": "oct", "kid": "k1", "k": "c2VjcmV0"}]}
    client_1 = MagicMock()
    client_1.__enter__.return_value = client_1
    client_1.get.side_effect = [mock_resp_wk_1, mock_resp_jwks_1]

    with patch("httpx.Client", return_value=client_1):
        oidc = s4u_auth.KeycloakOIDCClient("https://login.example/wk1", "aud1")
    assert oidc.issuer == "https://login.example/realms/r1"
    assert oidc.audience == "aud1"

    orig_url, orig_aud = s4u_cfg.OIDC_WELL_KNOWN_URL, s4u_cfg.OIDC_AUDIENCE
    try:
        s4u_cfg.OIDC_WELL_KNOWN_URL = "https://login.example/wk2"
        s4u_cfg.OIDC_AUDIENCE = "aud2"

        mock_resp_wk_2 = MagicMock()
        mock_resp_wk_2.json.return_value = {
            "issuer": "https://login.example/realms/r2",
            "jwks_uri": "https://login.example/jwks2",
        }
        mock_resp_jwks_2 = MagicMock()
        mock_resp_jwks_2.json.return_value = {"keys": [{"kty": "oct", "kid": "k2", "k": "c2VjcmV0"}]}
        client_2 = MagicMock()
        client_2.__enter__.return_value = client_2
        client_2.get.side_effect = [mock_resp_wk_2, mock_resp_jwks_2]

        with patch("httpx.Client", return_value=client_2):
            oidc.reload_from_config()
        assert oidc.issuer == "https://login.example/realms/r2"
        assert oidc.audience == "aud2"

        # Failure during reload preserves the previous valid issuer/audience/JWKS
        s4u_cfg.OIDC_WELL_KNOWN_URL = "https://login.example/broken"
        s4u_cfg.OIDC_AUDIENCE = "aud3"
        failing_client = MagicMock()
        failing_client.__enter__.return_value = failing_client
        failing_client.get.side_effect = RuntimeError("connection refused")
        with patch("httpx.Client", return_value=failing_client):
            with pytest.raises(RuntimeError, match="connection refused"):
                oidc.reload_from_config()
        assert oidc.issuer == "https://login.example/realms/r2"
        assert oidc.audience == "aud2"
    finally:
        s4u_cfg.OIDC_WELL_KNOWN_URL = orig_url
        s4u_cfg.OIDC_AUDIENCE = orig_aud

    # 2. KerberosProxy reload_from_config clears cached proxy_creds & updates keytab/ccache_dir
    dir1 = tmp_path / "cc1"
    dir2 = tmp_path / "cc2"
    kp = kerberos.KerberosProxy("FILE:/tmp/kt1", "svc1@EXAMPLE.COM", str(dir1))
    kp.proxy_creds = "CACHED_CREDS"

    orig_kt, orig_princ, orig_cc = s4u_cfg.KRB5_CLIENT_KTNAME, s4u_cfg.KRB5_PRINCIPAL, s4u_cfg.KRB5_CCACHE_DIR
    try:
        s4u_cfg.KRB5_CLIENT_KTNAME = "FILE:/tmp/kt2"
        s4u_cfg.KRB5_PRINCIPAL = "svc2@EXAMPLE.COM"
        s4u_cfg.KRB5_CCACHE_DIR = str(dir2)
        kp.reload_from_config()
        assert kp.keytab == "FILE:/tmp/kt2"
        assert kp.ccache_dir == str(dir2)
        assert kp.proxy_creds is None
        assert dir2.is_dir()
    finally:
        s4u_cfg.KRB5_CLIENT_KTNAME = orig_kt
        s4u_cfg.KRB5_PRINCIPAL = orig_princ
        s4u_cfg.KRB5_CCACHE_DIR = orig_cc

    # 3. KerberosProxy.prune_ccaches removes expired user ccaches, preserves fresh & _primary
    import time as _time
    old_user = dir2 / "EX_alice_12345678"
    fresh_user = dir2 / "EX_bob_87654321"
    primary = dir2 / "_primary"
    for p in (old_user, fresh_user, primary):
        p.write_bytes(b"data")
    old_mtime = _time.time() - 90000
    os.utime(old_user, (old_mtime, old_mtime))
    os.utime(primary, (old_mtime, old_mtime))

    removed = kp.prune_ccaches(max_age_seconds=86400)
    assert removed == 1
    assert not old_user.exists()
    assert fresh_user.exists()
    assert primary.exists()
