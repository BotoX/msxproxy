#!/usr/bin/env python3
"""
Live staging / production smoke test suite for msxproxy (Python stdlib only).

Reads endpoints and optional test credentials from `/etc/msxproxy/smoke_test.toml`
(override with `--config <path>` or `SMOKE_TEST_CONFIG`). Environment variables
override TOML values if set. Checks that require credentials are skipped cleanly
if the corresponding fields are blank.

Usage:
    sudo python3 tests/smoke_test.py
    python3 tests/smoke_test.py --config /path/to/smoke_test.toml
"""
import argparse
import base64
import html
import http.client
import json
import os
import re
import socket
import ssl
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

DEFAULT_CONFIG_PATH = "/etc/msxproxy/smoke_test.toml"


def load_toml_config(path: Path) -> dict:
    if not path.is_file():
        return {}
    with path.open("rb") as f:
        return tomllib.load(f)


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
    parser = argparse.ArgumentParser(description="msxproxy live smoke test suite")
    parser.add_argument(
        "--config",
        default=os.environ.get("SMOKE_TEST_CONFIG", DEFAULT_CONFIG_PATH),
        help=f"Path to smoke_test.toml (default: {DEFAULT_CONFIG_PATH})",
    )
    args = parser.parse_args()

    cfg = load_toml_config(Path(args.config))
    ep = cfg.get("endpoints", {})
    auth_cfg = cfg.get("auth", {})
    as_cfg = cfg.get("activesync_enroll", {})

    def _str(env_key: str, section: dict, key: str, default: str = "") -> str:
        if env_key in os.environ:
            return os.environ[env_key]
        val = section.get(key)
        return str(val) if val is not None else default

    def _bool(env_key: str, section: dict, key: str, default: bool) -> bool:
        if env_key in os.environ:
            return os.environ[env_key].lower() in ("1", "true", "yes")
        val = section.get(key)
        return bool(val) if val is not None else default

    webmail_url = _str("WEBMAIL_URL", ep, "webmail_url", "https://webmail.uni-graz.at").rstrip("/")
    autodiscover_url = _str("AUTODISCOVER_URL", ep, "autodiscover_url", "https://autodiscover.uni-graz.at").rstrip("/")
    mailproxy_host = _str("MAILPROXY_HOST", ep, "mailproxy_host", "")
    verify_tls = _bool("VERIFY_TLS", ep, "verify_tls", True)
    check_internal = _bool("CHECK_INTERNAL_ENDPOINTS", ep, "check_internal_endpoints", False)

    test_user = _str("TEST_USER", auth_cfg, "user", "")
    test_mail_pw = _str("TEST_MAIL_PASSWORD", auth_cfg, "mail_password", "")
    test_regular_pw = _str("TEST_REGULAR_PASSWORD", auth_cfg, "regular_password", "")
    as_enroll_enabled = _bool("ACTIVESYNC_ENROLL_ENABLED", as_cfg, "enabled", False)
    test_preview_secret = _str("TEST_PREVIEW_SECRET", as_cfg, "preview_secret", "")
    test_unenrolled_dev_id = _str("TEST_UNENROLLED_DEVICE_ID", as_cfg, "unenrolled_device_id", "SMOKETESTUNENROLLED")
    test_unenrolled_dev_type = _str("TEST_UNENROLLED_DEVICE_TYPE", as_cfg, "unenrolled_device_type", "SmokeTest")
    test_enrolled_dev_id = _str("TEST_ENROLLED_DEVICE_ID", as_cfg, "enrolled_device_id", "")
    test_enrolled_dev_type = _str("TEST_ENROLLED_DEVICE_TYPE", as_cfg, "enrolled_device_type", "SmokeTest")

    use_color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    c_reset  = "\033[0m"   if use_color else ""
    c_bold   = "\033[1m"   if use_color else ""
    c_dim    = "\033[2m"   if use_color else ""
    c_red    = "\033[1;31m" if use_color else ""
    c_green  = "\033[1;32m" if use_color else ""
    c_yellow = "\033[1;33m" if use_color else ""
    c_cyan   = "\033[36m"   if use_color else ""

    passed = 0
    warnings = 0
    skipped = 0
    failures = 0

    def run_check(name, fn):
        nonlocal passed, warnings, skipped, failures
        try:
            msg = fn()
            passed += 1
            detail = f" {c_dim}({msg}){c_reset}" if msg else ""
            print(f"{c_green}[PASS]{c_reset} {name}{detail}")
        except WarnCheck as w:
            warnings += 1
            print(f"{c_yellow}[WARN]{c_reset} {name} {c_dim}({w}){c_reset}")
        except SkipCheck as s:
            skipped += 1
            print(f"{c_yellow}[SKIP]{c_reset} {name}: {c_dim}{s}{c_reset}")
        except Exception as e:
            failures += 1
            print(f"{c_red}[FAIL]{c_reset} {name}: {c_red}{e}{c_reset}")

    class SkipCheck(Exception):
        pass

    class WarnCheck(Exception):
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

    # 5. Basic Auth external regular password on EWS -> 403
    def chk_basic_regular_password_external():
        if not (test_user and test_regular_pw):
            raise SkipCheck("set TEST_USER and TEST_REGULAR_PASSWORD (run from untrusted network)")
        st, _, body = http_req(
            f"{webmail_url}/EWS/Exchange.asmx",
            method="GET",
            headers={"Authorization": basic_header(test_user, test_regular_pw)},
            verify_tls=verify_tls,
        )
        assert st == 403, f"expected 403 for external regular password on EWS, got {st}: {body[:200]}"
        return "blocked with 403"

    run_check("HTTP Basic Auth external regular password (EWS) -> 403", chk_basic_regular_password_external)

    def fetch_enroll_preview(dev_id: str, dev_type: str) -> tuple[str, str]:
        """Fetch HTML preview from activesync-enroll and return (preview_url, enroll_url)."""
        qs = urllib.parse.urlencode({
            "preview_secret": test_preview_secret,
            "DeviceId": dev_id,
            "DeviceType": dev_type,
        })
        preview_url = f"{webmail_url}/Microsoft-Server-ActiveSync?{qs}"
        st, hdrs, body = http_req(
            preview_url,
            method="GET",
            headers={"Authorization": basic_header(test_user, test_regular_pw)},
            verify_tls=verify_tls,
        )
        assert st == 200, f"expected 200 HTML preview from activesync-enroll, got {st}: {body[:200]}"
        ct = next((v for k, v in hdrs.items() if k.lower() == "content-type"), "")
        assert "text/html" in ct.lower(), f"expected text/html response, got Content-Type: {ct!r}"
        marker = next((v for k, v in hdrs.items() if k.lower() == "x-activesync-enroll"), "")
        assert marker == "preview", f"expected X-ActiveSync-Enroll: preview header, got {marker!r}"

        m = re.search(r'href="(https?://[^"]+enroll_token=[^"]+)"', body)
        assert m, "rendered HTML preview does not contain an enroll_token link"
        return preview_url, html.unescape(m.group(1))

    # 5b. ActiveSync DeviceID enrollment checks (enabled vs disabled)
    def chk_activesync_disabled():
        if not (test_user and test_regular_pw):
            raise SkipCheck("set TEST_USER and TEST_REGULAR_PASSWORD (run from untrusted network)")
        qs = urllib.parse.urlencode({
            "DeviceId": test_unenrolled_dev_id,
            "DeviceType": test_unenrolled_dev_type,
        })
        st, hdrs, body = http_req(
            f"{webmail_url}/Microsoft-Server-ActiveSync?{qs}",
            method="OPTIONS",
            headers={"Authorization": basic_header(test_user, test_regular_pw)},
            verify_tls=verify_tls,
        )
        marker = next((v for k, v in hdrs.items() if k.lower() == "x-activesync-enroll"), "")
        assert not marker, (
            f"activesync_enroll.enabled is false in smoke_test.toml, but server routed to "
            f"activesync-enroll (X-ActiveSync-Enroll: {marker!r})"
        )
        assert st == 403, (
            f"expected 403 for external regular password on ActiveSync when activesync_enroll is disabled, "
            f"got {st}: {body[:200]}"
        )
        return "blocked with 403 (activesync-enroll not active)"

    def chk_activesync_unenrolled_preview():
        if not (test_user and test_regular_pw and test_preview_secret):
            raise SkipCheck("set TEST_USER, TEST_REGULAR_PASSWORD, and TEST_PREVIEW_SECRET")
        preview_url, _ = fetch_enroll_preview(test_unenrolled_dev_id, test_unenrolled_dev_type)
        print(f"       {c_dim}Browser preview URL:{c_reset}   {c_cyan}{preview_url}{c_reset}")
        return f"rendered HTML preview for unenrolled DeviceId={test_unenrolled_dev_id}"

    # 5c. ActiveSync DeviceID enrolled -> Exchange (acr=deviceId bypasses activesync-enroll)
    def chk_activesync_enrolled_device():
        if not (test_user and test_regular_pw and test_enrolled_dev_id):
            raise SkipCheck("set TEST_USER, TEST_REGULAR_PASSWORD, and TEST_ENROLLED_DEVICE_ID")
        qs = urllib.parse.urlencode({
            "DeviceId": test_enrolled_dev_id,
            "DeviceType": test_enrolled_dev_type,
        })
        st, hdrs, body = http_req(
            f"{webmail_url}/Microsoft-Server-ActiveSync?{qs}",
            method="OPTIONS",
            headers={"Authorization": basic_header(test_user, test_regular_pw)},
            verify_tls=verify_tls,
        )
        marker = next((v for k, v in hdrs.items() if k.lower() == "x-activesync-enroll"), "")
        if marker:
            if test_preview_secret:
                try:
                    _, enroll_url = fetch_enroll_preview(test_enrolled_dev_id, test_enrolled_dev_type)
                    print(f"       {c_yellow}Device '{test_enrolled_dev_id}' is not enrolled yet. Enroll it here and re-run:{c_reset}")
                    print(f"       {c_cyan}{enroll_url}{c_reset}")
                except Exception as exc:
                    print(f"       {c_dim}(Could not fetch enroll URL for {test_enrolled_dev_id}: {exc}){c_reset}")
            raise WarnCheck(
                f"DeviceId={test_enrolled_dev_id} is not enrolled yet (hit activesync-enroll) — enroll it via the link above and re-run"
            )
        assert st == 200, f"expected 200 from Exchange for enrolled DeviceID, got {st}: {body[:200]}"
        eas = next((v for k, v in hdrs.items() if k.lower() == "ms-server-activesync"), "")
        assert eas, "missing MS-Server-ActiveSync header from Exchange"
        return f"Exchange OPTIONS 200 OK (DeviceId={test_enrolled_dev_id}, MS-Server-ActiveSync={eas})"

    if as_enroll_enabled:
        run_check("ActiveSync unenrolled DeviceID -> activesync-enroll HTML preview", chk_activesync_unenrolled_preview)
        run_check("ActiveSync enrolled DeviceID (acr=deviceId) -> Exchange", chk_activesync_enrolled_device)
    else:
        run_check("ActiveSync regular password (activesync_enroll disabled) -> 403", chk_activesync_disabled)

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

    summary_counts = f"{passed} passed, {warnings} warnings, {skipped} skipped, {failures} failed"
    if failures:
        print(f"\n{c_red}Smoke test failed ({summary_counts}).{c_reset}")
    elif warnings:
        print(f"\n{c_yellow}Smoke test finished with warnings ({summary_counts}).{c_reset}")
    else:
        print(f"\n{c_green}Smoke test passed ({summary_counts}).{c_reset}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
