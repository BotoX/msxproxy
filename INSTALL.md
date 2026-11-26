# Installing msxproxy on Ubuntu 26.04

Complete step-by-step installation guide for deploying `msxproxy` (OpenResty + `s4u2api` + `mailproxy`, plus the optional `activesync-enroll` server) on **Ubuntu 26.04 LTS**.

> **Prefer Docker Compose?** See [`docker/README.md`](docker/README.md) to run the production stack in Docker (with bind-mounted repo code/configs and zero-downtime hot reload), or [`docker-ci/README.md`](docker-ci/README.md) for the self-contained integration test environment.

---

## 1. System Packages (Core)

Install the system packages required by `s4u2api`, `mailproxy`, Valkey, and Kerberos:

```bash
sudo apt update
sudo apt install -y \
  git curl wget gnupg lsb-release ca-certificates build-essential \
  luarocks luajit \
  valkey-server krb5-user \
  python3 python3-uvloop python3-gssapi python3-jwt python3-httpx \
  python3-redis python3-filelock python3-cryptography python3-pytest
```

---

## 2. Configure Valkey (RAM-Only JWT Cache)

`s4u2api` caches verified Keycloak JWTs in Valkey over a RAM-backed Unix socket (`/dev/shm/valkey.sock`).

Edit `/etc/valkey/valkey.conf` (or create a drop-in configuration):

```conf
port 0
unixsocket /dev/shm/valkey.sock
unixsocketperm 660

# Disable disk persistence for the JWT cache
save ""
appendonly no

maxmemory 64mb
maxmemory-policy allkeys-lru

loglevel notice
```

Enable and start Valkey:

```bash
sudo systemctl enable --now valkey-server
```

---

## 3. Configure Kerberos & Keytab

1. Configure `/etc/krb5.conf` for your Active Directory realm (e.g. `PERS.AD.UNI-GRAZ.AT`).
2. Create a service account in Active Directory with **Constrained Delegation (S4U2Self + S4U2Proxy)** to your Exchange HTTP/IMAP/SMTP SPNs, and export its keytab using `ktutil` (or `ktpass` on Windows):

   ```bash
   sudo mkdir -p /etc/msxproxy
   sudo ktutil
   # Inside ktutil:
   #   addent -password -p _msxproxy@PERS.AD.UNI-GRAZ.AT -k 1 -e aes256-cts-hmac-sha1-96
   #   wkt /etc/msxproxy/krb5_keytab
   #   quit

   sudo chown root:root /etc/msxproxy/krb5_keytab
   sudo chmod 0600 /etc/msxproxy/krb5_keytab
   ```

3. Verify the keytab against your KDC:

   ```bash
   sudo kinit -kt /etc/msxproxy/krb5_keytab _msxproxy@PERS.AD.UNI-GRAZ.AT
   sudo klist
   sudo kdestroy
   ```

---

## 4. Install OpenResty, `lua-resty-openidc` & `ngx_http_upstream_ntlm_module`

### 4.1 Install OpenResty from the Official Ubuntu Repository

Following the [official OpenResty Ubuntu instructions](https://openresty.org/en/linux-packages.html#ubuntu):

> **Note for Ubuntu 26.04 (`resolute`):** The official OpenResty APT repository does not yet publish packages for `resolute`. Use the Ubuntu 24.04 (`noble`) suite below instead — OpenResty bundles its own `openresty-openssl3`, `openresty-pcre2`, and `openresty-zlib` libraries, so the `noble` packages work cleanly on 26.04. Once OpenResty adds `resolute`, you can switch `noble` back to `$(lsb_release -sc)`.

```bash
wget -O - https://openresty.org/package/pubkey.gpg | sudo gpg --dearmor -o /usr/share/keyrings/openresty.gpg

# x86_64 / amd64 (using 'noble' until OpenResty publishes 'resolute' packages):
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/openresty.gpg] https://openresty.org/package/ubuntu noble main" \
  | sudo tee /etc/apt/sources.list.d/openresty.list > /dev/null

# (For arm64, use https://openresty.org/package/arm64/ubuntu instead.)

sudo apt update
sudo apt install -y openresty openresty-openssl3-dev openresty-pcre2-dev openresty-zlib-dev
```

### 4.2 Install `lua-resty-openidc` (via `luarocks`)

`luarocks` is installed via `apt` in Step 1 (`sudo apt install -y luarocks`). Install `lua-resty-openidc`:

```bash
sudo luarocks install lua-resty-openidc
```

### 4.3 Build the `ngx_http_upstream_ntlm_module` Dynamic Module

Compile only the dynamic `.so` module matching the installed OpenResty version (do **not** run `make install`, so the APT-managed OpenResty stays intact):

```bash
cd /usr/local/src
sudo git clone https://github.com/BotoX/upstream-ntlm-nginx-module.git

OPENRESTY_VER=$(/usr/local/openresty/bin/openresty -v 2>&1 | sed -n 's|.*openresty/\([0-9.]*\).*|\1|p')
curl -fsSLO "https://openresty.org/download/openresty-${OPENRESTY_VER}.tar.gz"
tar -xzf "openresty-${OPENRESTY_VER}.tar.gz"
cd "openresty-${OPENRESTY_VER}"

./configure \
  --prefix=/usr/local/openresty/nginx \
  --with-cc-opt='-O2 -DNGX_LUA_ABORT_AT_PANIC -I/usr/local/openresty/zlib/include -I/usr/local/openresty/pcre2/include -I/usr/local/openresty/openssl3/include' \
  --with-ld-opt='-Wl,-rpath,/usr/local/openresty/luajit/lib -L/usr/local/openresty/zlib/lib -L/usr/local/openresty/pcre2/lib -L/usr/local/openresty/openssl3/lib -Wl,-rpath,/usr/local/openresty/zlib/lib:/usr/local/openresty/pcre2/lib:/usr/local/openresty/openssl3/lib' \
  --with-pcre-jit \
  --with-stream \
  --without-mail_pop3_module \
  --without-mail_imap_module \
  --without-mail_smtp_module \
  --with-threads \
  --with-compat \
  --with-http_v2_module \
  --with-http_ssl_module \
  --add-dynamic-module=../upstream-ntlm-nginx-module \
  -j"$(nproc)"

make -j"$(nproc)"

sudo mkdir -p /usr/local/openresty/modules
sudo cp build/nginx-*/objs/ngx_http_upstream_ntlm_module.so /usr/local/openresty/modules/
```

### 4.4 Hook `msxproxy` into `nginx.conf`

Edit `/usr/local/openresty/nginx/conf/nginx.conf`:

- At the **top level** (before `events {}`):
  ```nginx
  load_module /usr/local/openresty/modules/ngx_http_upstream_ntlm_module.so;
  ```
- Inside **`http {}`**:
  ```nginx
  include /opt/msxproxy/deploy/openresty/msxproxy-http.conf;
  ```

---

## 5. Clone Repository & Run `deploy.sh install`

Clone `msxproxy` into `/opt/msxproxy` and run the idempotent installer:

```bash
sudo git clone <repo-url> /opt/msxproxy
cd /opt/msxproxy
sudo ./deploy/deploy.sh install
```

This creates:
- System users `s4u2api` (added to `valkey` group) and `mailproxy`
- Symlinks in `/etc/systemd/system/` for `s4u2api.service`, `mailproxy.service`, and `activesync-enroll.service`
- Starter configuration files in `/etc/msxproxy/` (preserving any existing files):
  - `/etc/msxproxy/config.lua` (`0640 root:nogroup`)
  - `/etc/msxproxy/mailproxy.toml` (`0640 root:mailproxy`)
  - `/etc/msxproxy/s4u2api.toml` (`0640 root:s4u2api`)
  - `/etc/msxproxy/activesync-enroll.toml` (`0600 root:root`, optional)
  - `/etc/msxproxy/smoke_test.toml` (`0600 root:root`, optional)

---

## 6. TLS Certificates

1. **OpenResty** (read as `root` on startup/reload): place your dual ECDSA + RSA certificates in `/etc/msxproxy/ssl/` (`chmod 0600` for `.key`, `chmod 0644` for `.pem`, owned by `root:root`) as referenced in `openresty/conf.d/webmail.conf`:
   - `/etc/msxproxy/ssl/webmail-ec-384.{pem,key}` and `/etc/msxproxy/ssl/webmail-rsa-3072.{pem,key}`
   - `/etc/msxproxy/ssl/autodiscover-ec-384.{pem,key}` and `/etc/msxproxy/ssl/autodiscover-rsa-3072.{pem,key}`
   - `/etc/msxproxy/ssl/autoconfig.{pem,key}`
2. **`mailproxy`** (read as user `mailproxy` so `SIGHUP` hot-reload works without root): place readable copies under `/etc/msxproxy/ssl/`:

   ```bash
   sudo chown mailproxy:root /etc/msxproxy/ssl/mailproxy*.key /etc/msxproxy/ssl/mailproxy*.pem
   sudo chmod 0600 /etc/msxproxy/ssl/mailproxy*.key
   sudo chmod 0644 /etc/msxproxy/ssl/mailproxy*.pem
   ```

---

## 7. Configure `/etc/msxproxy/*`

Generate random secrets as needed:

```bash
openssl rand -base64 32   # for config.lua mac_key_b64
openssl rand -hex 32      # for config.lua owa.session_secret, jwt_secret, preview_secret
```

Edit each configuration file:

1. **`/etc/msxproxy/config.lua`**: Set `hosts`, `oidc` (`local_issuer`, `audience`, `direct_grant`, `owa` client secrets & `session_secret`), `mac_key_b64`, and `s4u2api` settings.
2. **`/etc/msxproxy/s4u2api.toml`**: Set `[server]` (`host`/`port` or `uds`), `[oidc]`, `[valkey]`, `[kerberos]`, and `[valid_spns]`.
3. **`/etc/msxproxy/mailproxy.toml`**: Set `[oidc]` (`client_secret`), `[tls]` (`certificates = [{ cert = "...", key = "..." }, ...]`), `[imap]` / `[smtp]` backends, and `[network]` trusted CIDRs.

---

## 8. Optional: ActiveSync DeviceID Enrollment (`activesync-enroll`)

Skip this section if you only use Mail Passwords.

Install the additional Python packages and build `python-wbxml` (Ubuntu 26.04 ships `libwbxml2-dev` headers in a versioned directory, so pass `C_INCLUDE_PATH`):

```bash
sudo apt install -y python3-fastapi python3-uvicorn python3-pip python3-dev libwbxml2-dev
sudo C_INCLUDE_PATH="$(dirname "$(dpkg -L libwbxml2-dev | grep '/wbxml\.h$' | head -n1)")" \
  pip install git+https://github.com/BotoX/python-wbxml.git --break-system-packages
```

Configure and enable:

1. Edit `/etc/msxproxy/activesync-enroll.toml` (`0600 root:root` — loaded privately via systemd `DynamicUser=yes` + `LoadCredential`):
   - Set `[enroll]` (`authorization_endpoint`, `client_id`, `redirect_uri`, `jwt_issuer`, `jwt_audience`, `jwt_secret` matching Keycloak's `Enroll ActiveSync DeviceID` authenticator).
   - Customize `[mail]` (`subject`, `from_name`, `from_address`, `plain_template`, `html_template`).
   - Optionally set `server.preview_secret` (`openssl rand -hex 32`) for browser template preview and live smoke tests.
2. In `/etc/msxproxy/config.lua`, set `activesync_enroll.enabled = true`.
3. Enable and start the service:

   ```bash
   sudo systemctl enable --now activesync-enroll
   ```

---

## 9. Verify & Start Services

Run pre-flight checks (dependency check, offline test suite, and `nginx -t`):

```bash
sudo /opt/msxproxy/deploy/deploy.sh check
```

Enable and start the core services:

```bash
sudo systemctl enable --now s4u2api mailproxy openresty
```

### Live Smoke Tests

Optionally fill in `/etc/msxproxy/smoke_test.toml` with a dedicated staging/test mailbox and run:

```bash
sudo /opt/msxproxy/deploy/deploy.sh test
```

---

## 10. Day-2 Operations

```bash
# Zero-downtime reload after editing config.lua, mailproxy.toml, or renewing TLS certs
sudo /opt/msxproxy/deploy/deploy.sh reload

# Pull latest commits, run offline tests, validate nginx -t, and reload/restart services
sudo /opt/msxproxy/deploy/deploy.sh update

# Pin or roll back to a specific git tag/commit
sudo /opt/msxproxy/deploy/deploy.sh update v1.2.0
```
