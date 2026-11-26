# msxproxy Test Suite

## 1. Offline Unit Tests (CI / Dev Laptop)

No Keycloak, Exchange, AD KDC, or Valkey is required. Runs all Python (`mailproxy`, `s4u2api`, `activesync-enroll`) and OpenResty Lua (`authorization`, `netstrings`, `ratelimit`, `metrics`, `keycloak`, E2E) tests in a single command:

```bash
pytest -v
```

Or run the OpenResty Lua tests directly:

```bash
luajit tests/test_openresty.lua
```

## 2. Live Staging / Production Smoke Tests

Uses only Python stdlib. Copy `deploy/etc/smoke_test.toml.example` to `/etc/msxproxy/smoke_test.toml` (`chmod 0600`, or run `sudo ./deploy/deploy.sh install`) and fill in a dedicated test mailbox + Mail Password:

```bash
sudo python3 tests/smoke_test.py
# Or specify a custom path:
python3 tests/smoke_test.py --config /path/to/smoke_test.toml
```

Checks whose config fields are left blank (such as `auth.mail_password`, `endpoints.mailproxy_host`, or `activesync_enroll.preview_secret`) are skipped automatically.
