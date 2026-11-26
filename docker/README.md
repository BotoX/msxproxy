# Running `msxproxy` in Docker (Production)

Run the entire `msxproxy` stack in Docker against your external **Keycloak**, **Active Directory KDC**, and **Microsoft Exchange** servers — with **zero code/config duplication**, **production ports**, and **zero-downtime hot reloading**.

> Looking for the self-contained integration test environment (with containerized Keycloak and Mock Exchange)? See [`../docker-ci/README.md`](../docker-ci/README.md).

---

## Architecture & Services

All services run on a Linux host with `network_mode: host` (except `valkey`, which uses `network_mode: none` over a RAM-only tmpfs Unix socket):

- Real client IPv4/IPv6 addresses are preserved natively for `geo $is_trustedNetwork`, `ip_hash`, rate-limiting, `/status` & `/metrics` IP allowlists, and `mailproxy` `trusted_networks`.
- Production ports are bound directly on the host, while internal services stay strictly on `127.0.0.1`.
- Repo code, nginx configs, Lua modules, and static web assets (`openresty/www/`) are **directory bind-mounted read-only** — images contain only runtime dependencies and compiled C modules (`ngx_http_upstream_ntlm_module.so`, `python-wbxml`).

| Service | Profile | Ports / Socket | Role |
|---|---|---|---|
| `openresty` | default | `:443` (HTTPS) | OpenResty + `ngx_http_upstream_ntlm_module.so` + `lua-resty-openidc` |
| `mailproxy` | default | `:143`, `:993`, `:587`, `:465`; `127.0.0.1:9101` | IMAP/IMAPS/SMTP/SMTPS proxy + Prometheus `/metrics` (reverse-proxied at `https://<webmail>/metrics/mailproxy`) |
| `s4u2api` | default | `127.0.0.1:7777` | Kerberos S4U2Self/S4U2Proxy impersonation daemon (`/dev/shm` RAM ccache) |
| `valkey` | default | `/dev/shm/valkey.sock` (`network_mode: none`) | RAM-only JWT verification cache shared with `s4u2api` |
| `activesync-enroll` | `activesync-enroll` *(optional)* | `127.0.0.1:8000` | Optional ActiveSync DeviceID enrollment fake server |

---

## Quick Start

### 1. Initialize host configuration

```bash
./docker/msxproxy.sh init
```

This creates (without overwriting existing files):
- `/etc/msxproxy/{config.lua,s4u2api.toml,mailproxy.toml,activesync-enroll.toml,smoke_test.toml}`
- `/etc/msxproxy/ssl/` (place your TLS `.pem` / `.key` files here)
- `/etc/msxproxy/ca/` (optional: drop custom internal Root CA `.crt` files here)
- `docker/.env` (optional overrides for `MSXPROXY_ETC_DIR`, `KRB5_CONF`, worker counts, `COMPOSE_PROFILES`, etc.)

### 2. Populate secrets, TLS certificates, and Kerberos keytab

- Edit `/etc/msxproxy/config.lua`, `/etc/msxproxy/s4u2api.toml`, and `/etc/msxproxy/mailproxy.toml`.
- Place your Kerberos keytab at `/etc/msxproxy/krb5_keytab` and ensure `/etc/krb5.conf` is configured for your Active Directory realm.
- Place your TLS certificates in `/etc/msxproxy/ssl/` (matching `openresty/conf.d/webmail.conf` and `mailproxy.toml`).
- *(Optional)* Drop any internal Root CA certificates into `/etc/msxproxy/ca/*.crt` — container entrypoints automatically trust them via `update-ca-certificates`.

### 3. Validate and start

```bash
# Pre-flight validation
./docker/msxproxy.sh check

# Build images and start the core stack (valkey, s4u2api, mailproxy, openresty)
./docker/msxproxy.sh up --build

# Or start with optional activesync-enroll enabled
./docker/msxproxy.sh up --activesync-enroll --build
```

To keep `activesync-enroll` enabled permanently across `up`/`down`/`update`, set `COMPOSE_PROFILES=activesync-enroll` in `docker/.env` (and set `activesync_enroll.enabled = true` in `/etc/msxproxy/config.lua`).

---

## Hot Reloading (Zero Downtime, No Rebuild/Restart)

Because repo directories and `/etc/msxproxy` are mounted as directories (not single-file binds), edits saved directly on the host — including atomic editor saves, certbot renewals, and `git pull` — are immediately visible inside the running containers.

```bash
# Hot-reload ALL running services (zero downtime, no container restart)
./docker/msxproxy.sh reload

# Hot-reload a SINGLE component (or specific subset)
./docker/msxproxy.sh reload openresty
./docker/msxproxy.sh reload mailproxy s4u2api
./docker/msxproxy.sh reload activesync-enroll
```

What each service reloads without restarting its container:

| Service | Mechanism | Reloaded Without Restart |
|---|---|---|
| `openresty` | `openresty -t` then `openresty -s reload` | `docker/openresty/nginx.conf`, `deploy/openresty/msxproxy-http.conf`, `openresty/conf.d/*.conf`, **all Lua code (`openresty/lua/*.lua`)**, `/etc/msxproxy/config.lua`, TLS certs |
| `mailproxy` | `SIGHUP` | `/etc/msxproxy/mailproxy.toml`, TLS certs, OIDC credentials & JWKS, IMAP/SMTP backends |
| `s4u2api` | `SIGHUP` | `/etc/msxproxy/s4u2api.toml`, `valid_spns`, OIDC/JWKS, Kerberos principal & rotated `krb5_keytab` (flushes Valkey cache) |
| `activesync-enroll` | `SIGHUP` | `/etc/msxproxy/activesync-enroll.toml` (email templates, `preview_secret`, `jwt_secret`, `[enroll]` settings) |

Static web assets in `openresty/html/` and `openresty/www/autoconfig/` (`mail/config-v1.1.xml`) are served directly from the host repo — edits take effect immediately with no reload at all.

### Modifying Python code (`.py` files)

Python packages are bind-mounted from the repo, so **no Docker image rebuild is required**. Just restart the affected container:

```bash
./docker/msxproxy.sh restart mailproxy
```

### Updating from git

```bash
# Pull latest commits, run offline tests, hot-reload OpenResty, and restart Python containers (no rebuild)
./docker/msxproxy.sh update

# Pin or roll back to a specific tag/commit
./docker/msxproxy.sh update v1.2.0

# Also rebuild images (only needed when Python/Lua/OpenResty/NTLM C module dependencies change)
./docker/msxproxy.sh update --build
```

---

## Prometheus Metrics

Both OpenResty and `mailproxy` metrics are exposed over HTTPS on `:443` behind the same IP allowlist in `openresty/conf.d/webmail.conf` (no extra plaintext port needs to be exposed on your firewall):

- `https://<webmail>/metrics` — OpenResty auth/rate-limit/S4U2Api metrics
- `https://<webmail>/metrics/mailproxy` — `mailproxy` IMAP/SMTP/load-balancer metrics (proxied to `127.0.0.1:9101/metrics`)

---

## Day-2 Commands

```bash
./docker/msxproxy.sh status                   # Container & health status
./docker/msxproxy.sh logs [service...]        # Follow logs (e.g. logs openresty)
./docker/msxproxy.sh test --config /etc/msxproxy/smoke_test.toml
./docker/msxproxy.sh down                     # Stop and remove containers
```
