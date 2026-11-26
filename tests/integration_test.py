"""
End-to-end Docker integration test suite for msxproxy + keycloak-mail-passwords
+ ngx_http_upstream_ntlm_module.

Intended to run inside the `test-runner` container defined in
`docker-ci/docker-compose.yml` (via `./docker-ci/run-tests.sh`), where `webmail.localhost`,
`autodiscover.localhost`, `mailproxy.localhost`, and `keycloak.localhost`
are reachable and `SSL_CERT_FILE=/certs/ca.crt` trusts the Test Root CA.
"""
from __future__ import annotations

import base64
import html
import http.client
import os
import re
import socket
import ssl
import time
import urllib.parse

import httpx
import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("MSXPROXY_INTEGRATION") != "1",
    reason="Docker integration test (set MSXPROXY_INTEGRATION=1 or run ./docker-ci/run-tests.sh)",
)

WEBMAIL_URL = os.environ.get("WEBMAIL_URL", "https://webmail.localhost:18443").rstrip("/")
AUTODISCOVER_URL = os.environ.get("AUTODISCOVER_URL", "https://autodiscover.localhost:18443").rstrip("/")
MAILPROXY_HOST = os.environ.get("MAILPROXY_HOST", "mailproxy.localhost")

TEST_USER = os.environ.get("TEST_USER", "testuser")
TEST_REGULAR_PW = os.environ.get("TEST_REGULAR_PASSWORD", "TestRegularPass123!")
TEST_MAIL_PW = os.environ.get("TEST_MAIL_PASSWORD", "TestMailPass0123456789abcdefghij")
TEST_PREVIEW_SECRET = os.environ.get("TEST_PREVIEW_SECRET", "test-preview-secret-0123456789abcdef")

BF_USER = os.environ.get("BF_USER", "bftestuser")
BF_REGULAR_PW = os.environ.get("BF_REGULAR_PASSWORD", "TestBfPass123!")

SSL_CERT_FILE = os.environ.get("SSL_CERT_FILE", "/certs/ca.crt")


def _ssl_ctx() -> ssl.SSLContext:
    return ssl.create_default_context(cafile=SSL_CERT_FILE if os.path.isfile(SSL_CERT_FILE) else None)


def _client(**kwargs) -> httpx.Client:
    return httpx.Client(verify=_ssl_ctx(), timeout=15.0, **kwargs)


def _basic(user: str, pw: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{pw}".encode("utf-8")).decode("ascii")


def _extract_form_action(html_body: str) -> str:
    m = re.search(r'<form[^>]+action="([^"]+)"', html_body)
    assert m, f"No HTML <form action=...> found in:\n{html_body[:600]}"
    return html.unescape(m.group(1))


def test_e2e_activesync_deviceid_enrollment_flow():
    """
    Full interactive ActiveSync DeviceID enrollment:
      1. Unenrolled DeviceID hits activesync-enroll (both OPTIONS WBXML/headers and HTML preview).
      2. Follow the signed `enroll_token` URL to Keycloak (`https_webmail.test.local_Enroll`).
      3. Log in with username + regular password -> Keycloak displays `deviceid-enroll.ftl`.
      4. Confirm enrollment -> redirect to `/ActiveSync_Enroll_Complete` (200 OK, no error).
      5. Wait past short test cache_ttl, re-send OPTIONS with same DeviceID ->
         Keycloak now issues `acr=deviceId` and OpenResty proxies to mock-exchange!
    """
    dev_id = f"E2EDEV{int(time.time())}"
    dev_type = "TestPhone"

    with _client(follow_redirects=False) as c:
        # 1a. Unenrolled ActiveSync OPTIONS hits activesync-enroll
        r_opt = c.request(
            "OPTIONS",
            f"{WEBMAIL_URL}/Microsoft-Server-ActiveSync",
            params={"DeviceId": dev_id, "DeviceType": dev_type},
            headers={"Authorization": _basic(TEST_USER, TEST_REGULAR_PW)},
        )
        assert r_opt.status_code == 200
        assert r_opt.headers.get("x-activesync-enroll") == "true"

        # 1b. Fetch HTML preview and extract signed enroll_token link
        r_prev = c.get(
            f"{WEBMAIL_URL}/Microsoft-Server-ActiveSync",
            params={
                "preview_secret": TEST_PREVIEW_SECRET,
                "DeviceId": dev_id,
                "DeviceType": dev_type,
            },
            headers={"Authorization": _basic(TEST_USER, TEST_REGULAR_PW)},
        )
        assert r_prev.status_code == 200
        assert r_prev.headers.get("x-activesync-enroll") == "preview"
        m = re.search(r'href="(https?://[^"]+enroll_token=[^"]+)"', r_prev.text)
        assert m, "enroll_token link missing from HTML preview"
        enroll_url = html.unescape(m.group(1))

    # 2. Browser session with Keycloak to complete login + device enrollment
    with _client(follow_redirects=True) as browser:
        r_login_page = browser.get(enroll_url)
        assert r_login_page.status_code == 200
        login_action = _extract_form_action(r_login_page.text)

        # 3. Submit username & regular password -> lands on deviceid-enroll.ftl
        r_enroll_page = browser.post(
            login_action,
            data={"username": TEST_USER, "password": TEST_REGULAR_PW, "credentialId": ""},
        )
        assert r_enroll_page.status_code == 200
        assert dev_id in r_enroll_page.text, f"Expected DeviceId {dev_id} on enroll page"
        assert dev_type in r_enroll_page.text, f"Expected DeviceType {dev_type} on enroll page"

        # 4. Confirm device enrollment -> redirects to /ActiveSync_Enroll_Complete
        enroll_action = _extract_form_action(r_enroll_page.text)
        r_done = browser.post(
            enroll_action,
            data={"userLabel": "E2E Test Phone"},
        )
        assert r_done.status_code == 200
        assert "/ActiveSync_Enroll_Complete" in str(r_done.url)
        assert "error=" not in str(r_done.url)
        assert "state-ok" in r_done.text

    # 5. Wait for OpenResty's short test enroll cache TTL (1s) to expire
    time.sleep(2.0)

    with _client(follow_redirects=False) as c:
        r_after = c.request(
            "OPTIONS",
            f"{WEBMAIL_URL}/Microsoft-Server-ActiveSync",
            params={"DeviceId": dev_id, "DeviceType": dev_type},
            headers={"Authorization": _basic(TEST_USER, TEST_REGULAR_PW)},
        )
        assert r_after.status_code == 200
        assert not r_after.headers.get("x-activesync-enroll"), "Still hit activesync-enroll after enrollment!"
        assert r_after.headers.get("ms-server-activesync") == "15.1"
        assert r_after.headers.get("x-mock-principal") == f"{TEST_USER}@TEST.LOCAL"


def test_e2e_owa_oidc_pkce_login_and_logout():
    """
    Full browser OWA OIDC Authorization Code + PKCE flow:
      1. GET /owa/ redirects to Keycloak login.
      2. Submit credentials -> redirects through /owa/redirect_uri -> reaches mock-exchange /owa/.
      3. POST /owa/sessiondata.ashx & service.svc?action=GetOwaUserConfiguration have
         CloseWindowOnLogout rewritten from true to false (even with Accept-Encoding: gzip).
      4. GET /owa/logoff.owa, /owa/<mailbox>/logoff.owa, /ecp/logoff.owa redirect 302 -> /owa/logout
         with Connection: close.
      5. GET /owa/logout returns Connection: close.
    """
    with _client(follow_redirects=True) as browser:
        r_start = browser.get(f"{WEBMAIL_URL}/owa/")
        assert r_start.status_code == 200
        assert "keycloak.localhost" in str(r_start.url)

        login_action = _extract_form_action(r_start.text)
        r_owa = browser.post(
            login_action,
            data={"username": TEST_USER, "password": TEST_REGULAR_PW, "credentialId": ""},
        )
        assert r_owa.status_code == 200
        assert str(r_owa.url).startswith(f"{WEBMAIL_URL}/owa")
        assert f"Mock OWA OK for {TEST_USER}@TEST.LOCAL" in r_owa.text
        assert r_owa.headers.get("x-mock-principal") == f"{TEST_USER}@TEST.LOCAL"

        # Verify OpenResty strips Accept-Encoding upstream and rewrites CloseWindowOnLogout -> false
        r_sd = browser.post(
            f"{WEBMAIL_URL}/owa/sessiondata.ashx",
            params={"appcacheclient": "0"},
            headers={"Accept-Encoding": "gzip, deflate"},
        )
        assert r_sd.status_code == 200
        sd_data = r_sd.json()
        assert sd_data["owaUserConfig"]["ApplicationSettings"]["CloseWindowOnLogout"] is False

        r_svc = browser.post(
            f"{WEBMAIL_URL}/owa/service.svc",
            params={"action": "GetOwaUserConfiguration"},
            headers={"Accept-Encoding": "gzip"},
        )
        assert r_svc.status_code == 200
        svc_data = r_svc.json()
        assert svc_data["Body"]["ApplicationSettings"]["CloseWindowOnLogout"] is False

    # Verify logoff.owa redirects (standard, explicit logon, ECP) and /owa/logout Connection: close
    host = urllib.parse.urlsplit(WEBMAIL_URL).netloc
    for path in ("/owa/logoff.owa", "/owa/shared@test.local/logoff.owa", "/ecp/logoff.owa"):
        conn = http.client.HTTPSConnection(host, timeout=10, context=_ssl_ctx())
        try:
            conn.request("GET", path, headers={"Connection": "keep-alive"})
            resp = conn.getresponse()
            resp.read()
            assert resp.status == 302, f"{path}: expected 302, got {resp.status}"
            loc_path = urllib.parse.urlsplit(resp.getheader("Location") or "").path
            assert loc_path == "/owa/logout", f"{path}: expected /owa/logout, got {loc_path!r}"
            assert (resp.getheader("Connection") or "").lower() == "close", f"{path}: expected Connection: close"
        finally:
            conn.close()


def test_ntlm_upstream_connection_pinning():
    """
    Verify ngx_http_upstream_ntlm_module pins the upstream socket to the client
    keepalive connection and sets $ntlm_pinned_exchange_upstream:
      - Request #1 sends Negotiate token (X-Mock-Auth-Header-Present: yes).
      - Request #2 on the same TCP keepalive socket reuses the exact same
        upstream connection (same X-Mock-Conn-Id) with Authorization stripped
        (X-Mock-Auth-Header-Present: no).
    """
    host = urllib.parse.urlsplit(WEBMAIL_URL).netloc
    conn = http.client.HTTPSConnection(host, timeout=10, context=_ssl_ctx())
    try:
        headers = {
            "Authorization": _basic(TEST_USER, TEST_MAIL_PW),
            "Connection": "keep-alive",
        }
        conn.request("OPTIONS", "/Microsoft-Server-ActiveSync", headers=headers)
        r1 = conn.getresponse()
        r1.read()
        assert r1.status == 200
        conn_id_1 = r1.getheader("X-Mock-Conn-Id")
        assert conn_id_1
        assert r1.getheader("X-Mock-Principal") == f"{TEST_USER}@TEST.LOCAL"
        assert r1.getheader("X-Mock-Auth-Header-Present") == "yes"

        conn.request("OPTIONS", "/Microsoft-Server-ActiveSync", headers=headers)
        r2 = conn.getresponse()
        r2.read()
        assert r2.status == 200
        conn_id_2 = r2.getheader("X-Mock-Conn-Id")
        assert conn_id_2 == conn_id_1, f"Expected pinned upstream conn {conn_id_1}, got {conn_id_2}"
        assert r2.getheader("X-Mock-Principal") == f"{TEST_USER}@TEST.LOCAL"
        assert r2.getheader("X-Mock-Auth-Header-Present") == "no"

        # External client presenting NTLM on an already-pinned socket must still get 403
        conn.request(
            "OPTIONS",
            "/Microsoft-Server-ActiveSync",
            headers={
                "Authorization": "NTLM TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA=",
                "Connection": "keep-alive",
            },
        )
        r3 = conn.getresponse()
        r3.read()
        assert r3.status == 403
    finally:
        conn.close()

    # Unauthenticated healthcheck endpoint must strip Authorization and never prime an NTLM pin
    hc_conn = http.client.HTTPSConnection(host, timeout=10, context=_ssl_ctx())
    try:
        hc_conn.request(
            "GET",
            "/ews/healthcheck.htm",
            headers={
                "Authorization": "NTLM TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA=",
                "Connection": "keep-alive",
            },
        )
        rhc = hc_conn.getresponse()
        rhc.read()
        assert rhc.status == 200

        hc_conn.request("OPTIONS", "/Microsoft-Server-ActiveSync", headers={"Connection": "keep-alive"})
        r_unauth = hc_conn.getresponse()
        r_unauth.read()
        assert r_unauth.status == 401

        hc_conn.request(
            "OPTIONS",
            "/Microsoft-Server-ActiveSync",
            headers={
                "Authorization": "NTLM TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA=",
                "Connection": "keep-alive",
            },
        )
        r_ntlm = hc_conn.getresponse()
        r_ntlm.read()
        assert r_ntlm.status == 403
    finally:
        hc_conn.close()


def test_autodiscover_xml_rewrite():
    """Verify OpenResty rewrites internal Exchange hostnames in Autodiscover XML."""
    with _client() as c:
        r = c.post(
            f"{AUTODISCOVER_URL}/autodiscover/autodiscover.xml",
            headers={
                "Authorization": _basic(TEST_USER, TEST_MAIL_PW),
                "Content-Type": "text/xml",
            },
            content=b"<Autodiscover/>",
        )
        assert r.status_code == 200
        assert "webmail.localhost:18443" in r.text
        assert "email.uni-graz.at" not in r.text


def test_deviceid_bruteforce_lockout():
    """
    Verify DeviceIdDirectGrantAuthenticator locks out after 5 distinct unknown
    DeviceIDs (using SingleUseObjectProvider) and returns 401 on the 6th attempt.
    Uses dedicated `bftestuser` so `testuser` is unaffected.
    """
    prefix = f"BFDEV{int(time.time())}"
    with _client(follow_redirects=False) as c:
        for i in range(5):
            r = c.request(
                "OPTIONS",
                f"{WEBMAIL_URL}/Microsoft-Server-ActiveSync",
                params={"DeviceId": f"{prefix}{i}", "DeviceType": "BfPhone"},
                headers={"Authorization": _basic(BF_USER, BF_REGULAR_PW)},
            )
            assert r.status_code == 200
            assert r.headers.get("x-activesync-enroll") == "true"

        # 6th attempt with another DeviceId must trigger USER_TEMPORARILY_DISABLED -> 401
        r_locked = c.request(
            "OPTIONS",
            f"{WEBMAIL_URL}/Microsoft-Server-ActiveSync",
            params={"DeviceId": f"{prefix}LOCK", "DeviceType": "BfPhone"},
            headers={"Authorization": _basic(BF_USER, BF_REGULAR_PW)},
        )
        assert r_locked.status_code == 401, f"Expected 401 lockout, got {r_locked.status_code}"


def test_negative_auth_http_imap_smtp():
    """Wrong passwords and untrusted regular passwords on IMAP/SMTP must be rejected."""
    with _client(follow_redirects=False) as c:
        r_bad = c.request(
            "OPTIONS",
            f"{WEBMAIL_URL}/Microsoft-Server-ActiveSync",
            headers={"Authorization": _basic(TEST_USER, "definitely-wrong-password")},
        )
        assert r_bad.status_code == 401

    ctx = _ssl_ctx()
    # IMAPS with regular password from untrusted network -> NO
    with socket.create_connection((MAILPROXY_HOST, 993), timeout=10) as raw:
        with ctx.wrap_socket(raw, server_hostname=MAILPROXY_HOST) as tls:
            rf = tls.makefile("rb")
            assert b"IMAP4 service ready" in rf.readline()
            plain = base64.b64encode(f"\x00{TEST_USER}\x00{TEST_REGULAR_PW}".encode()).decode()
            tls.sendall(f"A001 AUTHENTICATE PLAIN {plain}\r\n".encode())
            lines = []
            while True:
                line = rf.readline()
                if not line:
                    break
                lines.append(line)
                if line.startswith(b"A001 "):
                    break
            joined = b"".join(lines)
            assert b"A001 NO" in joined or b"A001 BAD" in joined, f"Expected IMAP rejection, got {joined!r}"

    # SMTPS with regular password from untrusted network -> 5xx
    with socket.create_connection((MAILPROXY_HOST, 465), timeout=10) as raw:
        with ctx.wrap_socket(raw, server_hostname=MAILPROXY_HOST) as tls:
            rf = tls.makefile("rb")
            assert rf.readline().startswith(b"220 ")
            tls.sendall(b"EHLO test.local\r\n")
            while True:
                l = rf.readline()
                if len(l) >= 4 and l[3:4] == b" ":
                    break
            plain = base64.b64encode(f"\x00{TEST_USER}\x00{TEST_REGULAR_PW}".encode()).decode()
            tls.sendall(f"AUTH PLAIN {plain}\r\n".encode())
            resp = rf.readline()
            assert resp.startswith(b"5"), f"Expected SMTP 5xx rejection, got {resp!r}"
