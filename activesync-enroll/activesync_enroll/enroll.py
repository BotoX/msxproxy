from __future__ import annotations

import html
import re
import secrets
import time
from urllib.parse import urlencode

import jwt

from .config import Config, get_config

_PLACEHOLDER_RE = re.compile(r"\{\{(\w+)\}\}")


def _render_template(template: str, values: dict[str, str]) -> str:
    """Single-pass {{key}} substitution (safe with CSS braces and untrusted values)."""
    return _PLACEHOLDER_RE.sub(lambda m: values.get(m.group(1), m.group(0)), template)


def generate_enroll_token(
    subject: str,
    device_id: str,
    device_type: str,
    expires_in: int | None = None,
    config: Config | None = None,
) -> str:
    cfg = config or get_config()
    ttl = cfg.enroll.token_ttl if expires_in is None else expires_in
    now = int(time.time())
    payload = {
        "iss": cfg.enroll.jwt_issuer,
        "aud": cfg.enroll.jwt_audience,
        "iat": now,
        "exp": now + ttl,
        "sub": subject,
        "jti": secrets.token_urlsafe(16),
        "DeviceId": device_id,
        "DeviceType": device_type,
    }
    return jwt.encode(payload, cfg.enroll.jwt_secret, algorithm=cfg.enroll.jwt_algorithm)


def keycloak_enroll_link(
    subject: str,
    device_id: str,
    device_type: str,
    expires_in: int | None = None,
    config: Config | None = None,
) -> str:
    cfg = config or get_config()
    token = generate_enroll_token(
        subject=subject,
        device_id=device_id,
        device_type=device_type,
        expires_in=expires_in,
        config=cfg,
    )

    query = {
        "client_id": cfg.enroll.client_id,
        "response_type": "code",
        "scope": "openid",
        "redirect_uri": cfg.enroll.redirect_uri,
        "enroll_token": token,
    }
    return f"{cfg.enroll.authorization_endpoint}?{urlencode(query)}"


def generate_enroll_mail(
    subject: str,
    email: str,
    name: str,
    device_id: str,
    device_type: str,
    protocol_version: str,
    ip: str,
    ua: str,
    config: Config | None = None,
) -> tuple[str, str]:
    cfg = config or get_config()
    mfa_link = keycloak_enroll_link(
        subject=subject,
        device_id=device_id,
        device_type=device_type,
        config=cfg,
    )

    values = {
        "name": name or subject,
        "subject": subject,
        "email": email,
        "timestamp": time.strftime("%d.%m.%Y %H:%M:%S", time.localtime()),
        "device_type": device_type,
        "device_id": device_id,
        "mfa_link": mfa_link,
        "protocol_version": protocol_version,
        "ua": ua,
        "ip": ip,
    }

    plain = _render_template(cfg.mail.plain_template, values)
    escaped_values = {k: html.escape(v, quote=True) for k, v in values.items()}
    html_body = _render_template(cfg.mail.html_template, escaped_values)
    return plain, html_body
