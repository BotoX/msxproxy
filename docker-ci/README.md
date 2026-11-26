# Docker Compose Integration Test Environment

Self-contained end-to-end test stack for **`msxproxy`**, **`keycloak-mail-passwords`**, and **`ngx_http_upstream_ntlm_module`** using:

- **Real Keycloak `26.8.2`** with the `keycloak-mail-passwords` provider JAR and a pre-provisioned `TestRealm` (`realm-export.json`).
- **Real OpenResty** with `ngx_http_upstream_ntlm_module.so` compiled from source and `lua-resty-openidc` installed.
- **Real `activesync-enroll`** (FastAPI + `python-wbxml`).
- **Real `mailproxy`** (IMAP 143/993 + SMTP 587/465).
- **Real Valkey** (Unix socket JWT cache).
- **Test `s4u2api` wrapper** (`s4u2api/mock_s4u2api.py`): runs real Keycloak JWKS/JWT verification, real Valkey HMAC-signed caching + pub/sub lock, and real `aionetstrings` framing; mocks only the Kerberos S4U2Proxy ticket (`MOCK-KRB5:<upn>:<spn>`).
- **Mock Exchange** (`mock-exchange/mock_exchange.py`): TLS HTTPS/IMAPS/SMTP+STARTTLS backend verifying `MOCK-KRB5` tokens and connection pinning.
- **Test Root CA** (`certs/generate-certs.sh`): strict TLS verification (`verify_tls = true`) across every hop.

## Prerequisites

- Docker + Docker Compose
- Sibling `../keycloak-mail-passwords` checkout (override via `KEYCLOAK_MAIL_PASSWORDS_DIR` or `KEYCLOAK_MAIL_PASSWORDS_JAR`). If `target/keycloak-mail-passwords-1.0.0.jar` is missing, `run-tests.sh` automatically builds it (using local `mvn` if available, or a `maven:3.9-eclipse-temurin-21` container otherwise).
- Sibling `../ngx_http_upstream_ntlm_module` checkout (override via `NTLM_MODULE_DIR`).

## Quick Start

```bash
# Build images, boot stack, run smoke_test.py + integration_test.py, and tear down:
./docker-ci/run-tests.sh

# Reuse already-built images (fast ~25s run):
./docker-ci/run-tests.sh --no-build

# Keep containers running after tests for manual browser/CLI inspection (Ctrl+C stops & cleans up):
./docker-ci/run-tests.sh --keep-up

# Same as above, streaming live container logs until Ctrl+C:
./docker-ci/run-tests.sh --keep-up -v

# Stop and remove any leftover containers/volumes manually:
./docker-ci/run-tests.sh --stop
```

## Browser Access (`--keep-up`)

All browser-facing endpoints use RFC 6761 `*.localhost` hostnames on matching host/container ports so OIDC redirects (`webmail.localhost:18443` ↔ `keycloak.localhost:18444`) and ActiveSync enrollment links work directly in your browser without editing `/etc/hosts`.

*(Accept the self-signed Test Root CA warning in your browser on first visit, or import `/certs/ca.crt` from the `docker-ci_certs` volume.)*

| Service | URL / Port | Notes |
|---|---|---|
| OpenResty (Webmail / OWA) | `https://webmail.localhost:18443/owa/` | Also serves ActiveSync, EWS, `/status`, `/metrics`, `/ActiveSync_Enroll_Complete` |
| OpenResty (Autodiscover) | `https://autodiscover.localhost:18443` | Autodiscover JSON & XML rewrite |
| Keycloak Admin Console | `https://keycloak.localhost:18444/admin/` | `admin` / `admin` |
| Keycloak Account Console | `https://keycloak.localhost:18444/realms/TestRealm/account/` | Self-service Mail Passwords & DeviceIDs |
| Mailproxy IMAP / IMAPS | `mailproxy.localhost:10143` / `10993` | STARTTLS / implicit TLS |
| Mailproxy SMTP / SMTPS | `mailproxy.localhost:10587` / `10465` | STARTTLS / implicit TLS |

## Pre-Provisioned Test Credentials (`TestRealm`)

| User | Principal (`krb5_principal`) | Regular Password | Mail Password | Pre-Enrolled DeviceID |
|---|---|---|---|---|
| `testuser` | `testuser@TEST.LOCAL` | `TestRegularPass123!` | `TestMailPass0123456789abcdefghij` | `SMOKETESTENROLLED` (`SmokeTest`) |
| `bftestuser` | `bftestuser@TEST.LOCAL` | `TestBfPass123!` | *(none)* | *(none — used for brute-force lockout test)* |
