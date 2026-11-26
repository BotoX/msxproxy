# activesync-enroll

Optional ActiveSync DeviceID enrollment fake server for `msxproxy`.

OpenResty handles all Keycloak authentication and ACR policy evaluation (`mail-password` / `deviceId`).
When the optional ActiveSync DeviceID feature is enabled (`activesync_enroll.enabled = true` in `/etc/msxproxy/config.lua`) and an external ActiveSync client authenticates with a regular password from an unenrolled device, OpenResty forwards `/Microsoft-Server-ActiveSync` internally to `activesync-enroll` with:

- `X-Enroll-User`: Base64-encoded UTF-8 JSON `{"subject": "...", "email": "...", "name": "..."}`
- `X-Real-IP`: original client IP

`activesync-enroll` makes **zero requests to Keycloak**. It speaks just enough ActiveSync WBXML (`OPTIONS`, `Provision`, `Settings`, `FolderSync`, `GetItemEstimate`, `Sync`, `MoveItems`) to place a single enrollment email containing an HMAC-signed `enroll_token` JWT link into the user's fake Inbox.

## Dependencies

```bash
apt install python3-fastapi python3-uvicorn python3-jwt
apt install python3-pip python3-dev libwbxml2-dev
C_INCLUDE_PATH="$(dirname "$(dpkg -L libwbxml2-dev | grep '/wbxml\.h$' | head -n1)")" \
  pip install git+https://github.com/BotoX/python-wbxml.git --break-system-packages
```

## Configuration

Copy `deploy/etc/activesync-enroll.toml.example` to `/etc/msxproxy/activesync-enroll.toml` (`chmod 0600`, `root:root` — passed privately to the service via systemd `DynamicUser=yes` + `LoadCredential=config:...`) and configure:

- `[server]`: `host`, `port` (read directly by `python3 -m activesync_enroll`), and optional `preview_secret`
- `[enroll]`: `authorization_endpoint`, `client_id`, `redirect_uri`, `jwt_issuer`, `jwt_audience`, `jwt_secret` (must match Keycloak's `Enroll ActiveSync DeviceID` authenticator config)
- `[mail]`: `subject`, `from_name`, `from_address`, `plain_template`, and `html_template` (using `{{name}}`, `{{timestamp}}`, `{{device_type}}`, `{{device_id}}`, `{{mfa_link}}`, `{{protocol_version}}`, `{{ua}}`, `{{ip}}` placeholders)

Set `ACTIVESYNC_ENROLL_CONFIG=/path/to/activesync-enroll.toml` to override the config path outside systemd.

## HTML Preview & Smoke Testing

When `server.preview_secret` is set, raw rendered HTML (without WBXML) can be inspected directly in a browser or exercised by `tests/smoke_test.py`:

- End-to-end through OpenResty (prompts for Basic Auth with regular password + unenrolled DeviceID):
  `https://webmail.example.org/Microsoft-Server-ActiveSync?preview_secret=<secret>&DeviceId=TEST&DeviceType=iPhone`
- Directly on localhost (template preview without Basic Auth):
  `http://127.0.0.1:8000/preview?secret=<secret>&subject=alice&name=Alice`

Leave `preview_secret = ""` to keep both preview endpoints disabled (`405`).

## Systemd Service

A ready-to-use unit file is provided at [deploy/systemd/activesync-enroll.service](../deploy/systemd/activesync-enroll.service).
