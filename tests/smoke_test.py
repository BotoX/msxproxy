#!/usr/bin/env python3
"""
Live staging / production smoke test suite for msxproxy (Python stdlib only).

Reads endpoints and optional test credentials from environment variables or a
local gitignored `tests/.env` file. Checks that require credentials are skipped
cleanly if the corresponding env var is unset.

Usage:
    cp tests/.env.example tests/.env   # fill in staging/test user credentials
    python3 tests/smoke_test.py
"""
import base64
import http.client
import json
import os
import socket
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path


def load_dotenv(path: Path) -> None:
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def make_ssl_context(verify: bool) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def http_req(url: str, method: str = "GET", headers: dict | None = None, verify_tls: bool = True):
    ctx = make_ssl_context(verify_tls)
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx),
        NoRedirect(),
    )
    req = urllib.request.Request(url, method=method, headers=headers or {})
    try:
        with opener.open(req, timeout=10) as resp:
            return resp.status, dict(resp.headers.items()), resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers.items()), e.read().decode("utf-8", errors="replace")


def basic_header(user: str, pw: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{pw}".encode("utf-8")).decode("ascii")


def read_imap_until_tag(rfile, tag: bytes) -> bytes:
    lines = []
    while True:
        line = rfile.readline()
        if not line:
            break
        lines.append(line)
        if line.startswith(tag + b" "):
            break
    return b"".join(lines)


def read_smtp_reply(rfile) -> bytes:
    lines = []
    while True:
        line = rfile.readline()
        if not line:
            break
        lines.append(line)
        # Final SMTP reply line has space at index 3 (e.g. b"250 OK\r\n")
        if len(line) >= 4 and line[:3].isdigit() and line[3:4] == b" ":
            break
    return b"".join(lines)


def main() -> int:
    load_dotenv(Path(__file__).resolve().parent / ".env")

    webmail_url = os.environ.get("WEBMAIL_URL", "https://webmail.uni-graz.at").rstrip("/")
    autodiscover_url = os.environ.get("AUTODISCOVER_URL", "https://autodiscover.uni-graz.at").rstrip("/")
    mailproxy_host = os.environ.get("MAILPROXY_HOST", "")
    verify_tls = os.environ.get("VERIFY_TLS", "true").lower() not in ("0", "false", "no")

    test_user = os.environ.get("TEST_USER", "")
    test_mail_pw = os.environ.get("TEST_MAIL_PASSWORD", "")
    test_regular_pw = os.environ.get("TEST_REGULAR_PASSWORD", "")
    check_internal = os.environ.get("CHECK_INTERNAL_ENDPOINTS", "false").lower() in ("1", "true", "yes")

    failures = 0

    def run_check(name, fn):
        nonlocal failures
        try:
            msg = fn()
            print(f"[PASS] {name}" + (f" ({msg})" if msg else ""))
        except SkipCheck as s:
            print(f"[SKIP] {name}: {s}")
        except Exception as e:
            failures += 1
            print(f"[FAIL] {name}: {e}")

    class SkipCheck(Exception):
        pass

    # 1. Autodiscover JSON
    def chk_autodiscover_json():
        st, _, body = http_req(
            f"{autodiscover_url}/autodiscover/autodiscover.json?Protocol=ActiveSync",
            verify_tls=verify_tls,
        )
        assert st == 200, f"expected 200, got {st}"
        data = json.loads(body)
        assert "Url" in data and "Microsoft-Server-ActiveSync" in data["Url"], f"unexpected body: {body}"

        st_bad, _, _ = http_req(
            f"{autodiscover_url}/autodiscover/autodiscover.json",
            verify_tls=verify_tls,
        )
        assert st_bad == 400, f"missing Protocol should return 400, got {st_bad}"
        return data["Url"]

    run_check("Autodiscover JSON endpoint", chk_autodiscover_json)

    # 2. OWA unauthenticated redirect & /owa/logout Connection: close
    def chk_owa_redirect_and_logout():
        st, hdrs, _ = http_req(f"{webmail_url}/owa/", verify_tls=verify_tls)
        assert st in (302, 303), f"expected redirect to Keycloak, got {st}"
        loc = next((v for k, v in hdrs.items() if k.lower() == "location"), "")
        assert loc, "missing Location header on /owa/ redirect"

        host = webmail_url.split("://", 1)[1].split("/", 1)[0]
        conn = http.client.HTTPSConnection(host, timeout=10, context=make_ssl_context(verify_tls))
        conn.request("GET", "/owa/logout", headers={"Connection": "keep-alive"})
        resp = conn.getresponse()
        resp.read()
        conn_hdr = (resp.getheader("Connection") or "").lower()
        conn.close()
        assert conn_hdr == "close", f"expected Connection: close on /owa/logout, got {conn_hdr!r}"
        return f"redirect={st}, logout Connection: close"

    run_check("OWA OIDC redirect & /owa/logout Connection: close", chk_owa_redirect_and_logout)

    # 3. Unauthenticated ActiveSync returns 401 with WWW-Authenticate
    def chk_unauth_401():
        st, hdrs, _ = http_req(f"{webmail_url}/Microsoft-Server-ActiveSync", method="OPTIONS", verify_tls=verify_tls)
        assert st == 401, f"expected 401, got {st}"
        wa = next((v for k, v in hdrs.items() if k.lower() == "www-authenticate"), "")
        assert "Basic" in wa, f"missing Basic challenge in WWW-Authenticate: {wa!r}"
        return wa

    run_check("Unauthenticated /Microsoft-Server-ActiveSync -> 401", chk_unauth_401)

    # 4. Basic Auth with Mail Password
    def chk_basic_mail_password():
        if not (test_user and test_mail_pw):
            raise SkipCheck("set TEST_USER and TEST_MAIL_PASSWORD")
        st, _, body = http_req(
            f"{webmail_url}/Microsoft-Server-ActiveSync",
            method="OPTIONS",
            headers={"Authorization": basic_header(test_user, test_mail_pw)},
            verify_tls=verify_tls,
        )
        assert st == 200, f"expected 200 from Exchange ActiveSync OPTIONS, got {st}: {body[:200]}"
        return "Exchange OPTIONS 200 OK"

    run_check("HTTP Basic Auth with Mail Password -> Exchange", chk_basic_mail_password)

    # 5. Basic Auth external regular password -> 403
    def chk_basic_regular_password_external():
        if not (test_user and test_regular_pw):
            raise SkipCheck("set TEST_USER and TEST_REGULAR_PASSWORD (run from untrusted network)")
        st, _, body = http_req(
            f"{webmail_url}/Microsoft-Server-ActiveSync",
            method="OPTIONS",
            headers={"Authorization": basic_header(test_user, test_regular_pw)},
            verify_tls=verify_tls,
        )
        assert st == 403, f"expected 403 for external regular password, got {st}: {body[:200]}"
        return "blocked with 403"

    run_check("HTTP Basic Auth external regular password -> 403", chk_basic_regular_password_external)

    # 6. Internal /status and /metrics
    def chk_status_and_metrics():
        if not check_internal:
            raise SkipCheck("set CHECK_INTERNAL_ENDPOINTS=true when running from an allowed IP")
        st1, _, b1 = http_req(f"{webmail_url}/status", verify_tls=verify_tls)
        assert st1 == 200 and "Nginx Worker PID" in b1, f"/status failed: {st1}"
        st2, _, b2 = http_req(f"{webmail_url}/metrics", verify_tls=verify_tls)
        assert st2 == 200 and "msxproxy_" in b2, f"/metrics failed: {st2}"
        return "/status & /metrics 200 OK"

    run_check("OpenResty /status and /metrics", chk_status_and_metrics)

    # 7. IMAP STARTTLS pipelining rejection & optional login
    def chk_imap():
        if not mailproxy_host:
            raise SkipCheck("set MAILPROXY_HOST")
        # 7a: Check STARTTLS pipelining rejection on port 143
        with socket.create_connection((mailproxy_host, 143), timeout=10) as s:
            greeting = s.recv(4096)
            assert b"IMAP4 service ready" in greeting, f"unexpected greeting: {greeting!r}"
            s.sendall(b"A001 STARTTLS\r\nA002 CAPABILITY\r\n")
            resp = s.recv(4096)
            assert b"BAD" in resp, f"expected BAD on pipelined STARTTLS, got {resp!r}"

        # 7b: Check IMAPS 993 + CAPABILITY + optional LOGIN
        ctx = make_ssl_context(verify_tls)
        with socket.create_connection((mailproxy_host, 993), timeout=10) as raw:
            with ctx.wrap_socket(raw, server_hostname=mailproxy_host) as tls:
                rf = tls.makefile("rb")
                greeting = rf.readline()
                assert b"IMAP4 service ready" in greeting, f"unexpected greeting: {greeting!r}"
                tls.sendall(b"A001 CAPABILITY\r\n")
                cap = read_imap_until_tag(rf, b"A001")
                assert b"AUTH=XOAUTH2" in cap and b"AUTH=PLAIN" in cap, f"unexpected caps: {cap!r}"
                if test_user and test_mail_pw:
                    plain = base64.b64encode(f"\x00{test_user}\x00{test_mail_pw}".encode()).decode()
                    tls.sendall(f"A002 AUTHENTICATE PLAIN {plain}\r\n".encode())
                    auth_resp = read_imap_until_tag(rf, b"A002")
                    assert b"A002 OK" in auth_resp, f"IMAP AUTH PLAIN failed: {auth_resp!r}"
                    tls.sendall(b"A003 LOGOUT\r\n")
                    return "STARTTLS guard OK + IMAPS AUTH PLAIN OK"
                tls.sendall(b"A002 LOGOUT\r\n")
                return "STARTTLS guard OK + IMAPS CAPABILITY OK"

    run_check("Mailproxy IMAP (143/993)", chk_imap)

    # 8. SMTP STARTTLS pipelining rejection & SMTPS 465
    def chk_smtp():
        if not mailproxy_host:
            raise SkipCheck("set MAILPROXY_HOST")
        with socket.create_connection((mailproxy_host, 587), timeout=10) as s:
            rf = s.makefile("rb")
            greeting = read_smtp_reply(rf)
            assert greeting.startswith(b"220 "), f"unexpected SMTP greeting: {greeting!r}"
            s.sendall(b"EHLO smoketest.local\r\n")
            ehlo = read_smtp_reply(rf)
            assert b"STARTTLS" in ehlo and b"PIPELINING" not in ehlo, f"unexpected pre-TLS EHLO: {ehlo!r}"
            s.sendall(b"STARTTLS\r\nNOOP\r\n")
            resp = read_smtp_reply(rf)
            assert b"501 5.5.4" in resp, f"expected 501 on pipelined STARTTLS, got {resp!r}"

        ctx = make_ssl_context(verify_tls)
        with socket.create_connection((mailproxy_host, 465), timeout=10) as raw:
            with ctx.wrap_socket(raw, server_hostname=mailproxy_host) as tls:
                rf = tls.makefile("rb")
                greeting = read_smtp_reply(rf)
                assert greeting.startswith(b"220 "), f"unexpected SMTPS greeting: {greeting!r}"
                tls.sendall(b"EHLO smoketest.local\r\n")
                ehlo = read_smtp_reply(rf)
                assert b"AUTH " in ehlo and b"XOAUTH2" in ehlo, f"unexpected SMTPS EHLO: {ehlo!r}"
                if test_user and test_mail_pw:
                    plain = base64.b64encode(f"\x00{test_user}\x00{test_mail_pw}".encode()).decode()
                    tls.sendall(f"AUTH PLAIN {plain}\r\n".encode())
                    auth_resp = read_smtp_reply(rf)
                    assert auth_resp.startswith(b"235 "), f"SMTP AUTH PLAIN failed: {auth_resp!r}"
                    tls.sendall(b"QUIT\r\n")
                    return "STARTTLS guard OK + SMTPS AUTH PLAIN OK"
                tls.sendall(b"QUIT\r\n")
                return "STARTTLS guard OK + SMTPS EHLO OK"

    run_check("Mailproxy SMTP (587/465)", chk_smtp)

    print(f"\nSmoke test finished with {failures} failure(s).")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
