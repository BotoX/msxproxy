# msxproxy Test Suite

## 1. Offline Unit Tests (CI / Dev Laptop)

No Keycloak, Exchange, AD KDC, or Valkey is required. Runs all Python (`mailproxy`, `s4u2api`) and OpenResty Lua (`authorization`, `netstrings`, `ratelimit`, `metrics`, `keycloak`) tests in a single command:

```bash
pytest -v
```

Or run the OpenResty Lua tests directly:

```bash
luajit tests/test_openresty.lua
```

## 2. Live Staging / Production Smoke Tests

Uses only Python stdlib. Copy `tests/.env.example` to `tests/.env` (gitignored) and fill in a dedicated test mailbox + Mail Password:

```bash
cp tests/.env.example tests/.env
chmod 600 tests/.env
python3 tests/smoke_test.py
```

Checks whose environment variables are left blank (such as `TEST_MAIL_PASSWORD` or `MAILPROXY_HOST`) are skipped automatically.
