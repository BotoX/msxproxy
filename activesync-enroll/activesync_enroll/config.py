from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_CONFIG_PATH = "/etc/msxproxy/activesync-enroll.toml"
ALLOWED_JWT_ALGS = ("HS256", "HS384", "HS512")

DEFAULT_PLAIN_TEMPLATE = """\
Dear {{name}},

A login attempt without MFA from a new device ID was detected.
To enable email access, this device must be verified once.

Details:
- Timestamp: {{timestamp}}
- Device Type: {{device_type}}
- Device ID: {{device_id}}

Visit the following link to verify this device:
{{mfa_link}}

The link is valid for one hour from the timestamp.
Refresh your emails to get a new link.

---
MS-ASProtocolVersion: {{protocol_version}}
User-Agent: {{ua}}
IP Address: {{ip}}
"""

DEFAULT_HTML_TEMPLATE = """\
<html>
<body style="font-family: Arial, sans-serif; color: #000000; line-height: 1.6;">
  <h2>Exchange ActiveSync Multi-Factor Authentication</h2>
  <p>Dear {{name}},</p>
  <p>A login attempt without MFA from a new device ID was detected.
     To enable email access, this device must be verified once.</p>
  <ul>
    <li><strong>Timestamp:</strong> {{timestamp}}</li>
    <li><strong>Device Type:</strong> {{device_type}}</li>
    <li><strong>Device ID:</strong> {{device_id}}</li>
  </ul>
  <p><a href="{{mfa_link}}" target="_blank">Verify ActiveSync Device ID</a></p>
  <p style="font-size: 11px; color: #666666;">
    MS-ASProtocolVersion: {{protocol_version}}<br>
    User-Agent: {{ua}}<br>
    IP Address: {{ip}}
  </p>
</body>
</html>"""


@dataclass(frozen=True)
class ServerConfig:
    host: str = "127.0.0.1"
    port: int = 8000
    max_body_bytes: int = 1_048_576  # 1 MiB
    preview_secret: str = ""


@dataclass(frozen=True)
class EnrollConfig:
    authorization_endpoint: str = ""
    client_id: str = ""
    redirect_uri: str = ""
    jwt_issuer: str = ""
    jwt_audience: str = "deviceid-enroll-authenticator"
    jwt_secret: str = ""
    jwt_algorithm: str = "HS256"
    token_ttl: int = 3600


@dataclass(frozen=True)
class MailConfig:
    subject: str = "*** ACTION REQUIRED ***"
    from_name: str = "Exchange ActiveSync MFA"
    from_address: str = "noreply@example.org"
    plain_template: str = DEFAULT_PLAIN_TEMPLATE
    html_template: str = DEFAULT_HTML_TEMPLATE


@dataclass(frozen=True)
class Config:
    server: ServerConfig = field(default_factory=ServerConfig)
    enroll: EnrollConfig = field(default_factory=EnrollConfig)
    mail: MailConfig = field(default_factory=MailConfig)

    def validate(self) -> None:
        if not self.enroll.authorization_endpoint:
            raise ValueError("enroll.authorization_endpoint must be configured")
        if not self.enroll.client_id:
            raise ValueError("enroll.client_id must be configured")
        if not self.enroll.redirect_uri:
            raise ValueError("enroll.redirect_uri must be configured")
        if not self.enroll.jwt_issuer:
            raise ValueError("enroll.jwt_issuer must be configured")
        if not self.enroll.jwt_audience:
            raise ValueError("enroll.jwt_audience must be configured")
        if not self.enroll.jwt_secret or self.enroll.jwt_secret == "CHANGE_ME":
            raise ValueError("enroll.jwt_secret must be set to a strong non-placeholder secret")
        if len(self.enroll.jwt_secret.encode("utf-8")) < 32:
            raise ValueError("enroll.jwt_secret must be at least 32 bytes for HMAC-SHA256+")
        if self.enroll.jwt_algorithm not in ALLOWED_JWT_ALGS:
            raise ValueError(f"enroll.jwt_algorithm must be one of {ALLOWED_JWT_ALGS}")
        if self.enroll.token_ttl <= 0:
            raise ValueError("enroll.token_ttl must be positive")


def _build_section(cls, raw: dict | None):
    if not raw:
        return cls()
    valid_fields = cls.__dataclass_fields__.keys()
    filtered = {k: v for k, v in raw.items() if k in valid_fields}
    return cls(**filtered)


def _resolve_config_path(path: str | Path | None = None) -> Path:
    if path is not None:
        return Path(path)
    env_path = os.environ.get("ACTIVESYNC_ENROLL_CONFIG")
    if env_path:
        return Path(env_path)
    cred_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    if cred_dir:
        cred_cfg = Path(cred_dir) / "config"
        if cred_cfg.is_file():
            return cred_cfg
    return Path(DEFAULT_CONFIG_PATH)


def load_config(path: str | Path | None = None) -> Config:
    cfg_path = _resolve_config_path(path)
    with cfg_path.open("rb") as f:
        data = tomllib.load(f)

    cfg = Config(
        server=_build_section(ServerConfig, data.get("server")),
        enroll=_build_section(EnrollConfig, data.get("enroll")),
        mail=_build_section(MailConfig, data.get("mail")),
    )
    cfg.validate()
    return cfg


_cached_config: Config | None = None


def get_config() -> Config:
    global _cached_config
    if _cached_config is None:
        _cached_config = load_config()
    return _cached_config


def set_config(cfg: Config | None) -> None:
    """Override or clear the cached configuration (used at startup and in tests)."""
    global _cached_config
    _cached_config = cfg


def reload_config(path: str | Path | None = None) -> Config:
    """Reload and validate configuration from disk, swapping the cached config on success."""
    new_cfg = load_config(path)
    set_config(new_cfg)
    return new_cfg
