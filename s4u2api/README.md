# S4U2Api

Specialized Kerberos S4U2Self / S4U2Proxy impersonation daemon bridging modern OpenID Connect (OIDC) JWTs from **Keycloak** into Kerberos service tickets for Microsoft Exchange (HTTP, IMAP, and SMTP).

---

## Overview

```mermaid
graph TD
    A["OpenResty / Mailproxy"] -->|"Netstrings (SPN, UPN, JWT)<br/>over TCP or UDS"| B("S4U2Api Master Process")
    B -->|Distributes| C["S4U2Api Worker"]
    C <-->|"1. Check JWT Cache"| E[("Valkey in RAM<br/>(/dev/shm/valkey.sock)")]
    C <-->|"1a. Verify JWT"| D["PyJWT with keys from<br/>Keycloak OIDC JWKS"]
    C <-->|"2. Check Ticket Cache"| G[("KRB5 CCache in /dev/shm<br/>(atomic temp-file writes)")]
    C <-->|"2a. S4U2Self + S4U2Proxy"| F["Active Directory KDC"]
    C -->|"3. Return Base64 Token<br/>(+ optional GSSAPI ctx)"| A
```

### Executive Summary

S4U2Api translates verified Keycloak JWTs into Kerberos Service Tickets via Active Directory **Constrained Delegation (S4U2Self + S4U2Proxy)**.

- **Asyncio + ThreadPool bridge:** Uses `asyncio` + `uvloop` for high-concurrency netstrings framing while offloading blocking C-level GSSAPI / KDC operations to thread pools.
- **Stampede-resistant JWT cache:** Verified JWTs are cached in RAM-only **Valkey** with per-process HMAC-SHA256 integrity signatures and Redis `SET NX` + Pub/Sub leader/follower coordination so concurrent requests for the same token verify it once.
- **Lock-free fast path for Kerberos tickets:** Per-user tickets are stored in `/dev/shm` using atomic write-and-rename (`os.replace`), allowing lock-free reads via a pure-Python MIT KRB5 ccache parser (`ccache.py`) while serializing KDC renewals per UPN with `AsyncUnixFileLock`.

---

## Worker Sequence Diagram

```mermaid
sequenceDiagram
    participant C as OpenResty / Mailproxy
    participant L as S4U2Api Worker
    participant V as Valkey Cache
    participant K as Kerberos Proxy

    C->>L: Request (SPN, UPN, JWT, [ctx])
    L->>V: GET jwt:{hash}

    alt Cache Miss
        L->>V: SETNX lock:{hash}
        alt Acquired Lock (Leader Worker)
            L->>L: Verify JWT Signature & Claims<br/>with Keycloak JWKS
            Note over L: Extract krb5_principal from JWT claims
            L->>L: HMAC Sign Cache Payload (principal:jwt_hash)
            L->>V: Pipeline: SET cache + PUBLISH "READY"
        else Lock Denied (Follower Worker)
            L->>V: SUBSCRIBE pub:{hash}
            V-->>L: Wait for "READY" signal
            L->>V: GET jwt:{hash}
        end
    else Cache Hit
        V-->>L: Signed User Principal Payload
        L->>L: Verify HMAC Signature
    end

    L->>L: Verify requested UPN == JWT krb5_principal
    L->>K: kerb_proxy.create_context(UPN, full_SPN)
    K-->>L: Kerberos Service Ticket (+ optional GSSAPI ctx)
    L-->>C: Base64 Token (+ exported ctx if requested)
```

---

## Kerberos Sequence Diagram

```mermaid
sequenceDiagram
    participant EventLoop as Kerberos Proxy<br/>Asyncio Event Loop
    participant Executor as ThreadPool Executor
    participant UCache as User CCache<br/>/dev/shm
    participant PCache as Primary CCache<br/>/dev/shm
    participant KDC as Active Directory KDC

    EventLoop->>EventLoop: create_context(upn, spn)

    Note over EventLoop, UCache: 1. Fast Path (Lock-Free Read)
    EventLoop->>UCache: _krb5_get_creds(ccache_path, spn)

    alt User Creds found & valid > 5m
        EventLoop->>EventLoop: token, ctx = init_context(user_creds)
        Note over EventLoop, UCache: Return token from user ccache
    else User Creds missing or expiring
        Note over EventLoop, KDC: 2. Heavy Path (Per-UPN File Lock)
        EventLoop->>+UCache: Acquire AsyncUnixFileLock(user.lock)
        EventLoop->>UCache: Double-check _krb5_get_creds(ccache_path, spn)

        alt Another worker refreshed it first
            EventLoop->>EventLoop: token, ctx = init_context(user_creds)
            UCache->>EventLoop: Release AsyncUnixFileLock(user.lock)
        else Still missing or expired
            EventLoop->>EventLoop: proxy_creds = get_proxy_creds()
            alt Proxy Creds expired
                Note over EventLoop, PCache: 3. Master Proxy Credential Lock
                EventLoop->>+PCache: Acquire AsyncUnixFileLock(_primary.lock)
                EventLoop->>PCache: try gssapi.Credentials(_primary)
                alt Proxy creds still expired
                    EventLoop->>PCache: Remove stale _primary
                    EventLoop->>+Executor: run_in_executor(gssapi.Credentials)
                    Executor->>+KDC: Get Master TGT (using keytab)
                    KDC-->>-Executor: Master TGT
                    Executor->>PCache: Write _primary ccache
                    Executor-->>-EventLoop: proxy_creds
                end
                PCache-->>EventLoop: proxy_creds
                PCache->>-EventLoop: Release AsyncUnixFileLock(_primary.lock)
            end

            Note over EventLoop, KDC: 4. S4U2Self Impersonation
            EventLoop->>+Executor: run_in_executor(proxy_creds.impersonate)
            Executor->>+KDC: Get User Ticket (S4U2Self)
            KDC-->>-Executor: User Ticket
            Executor-->>-EventLoop: user_creds

            Note over EventLoop, KDC: 5. S4U2Proxy Service Ticket
            EventLoop->>+Executor: run_in_executor(init_context(user_creds))
            Executor->>+KDC: Get Service Ticket (S4U2Proxy)
            KDC-->>-Executor: Service Ticket
            Executor-->>-EventLoop: Token, gssapi.SecurityContext
            EventLoop->>UCache: Atomic write (_store_ccache_atomic)
            UCache->>-EventLoop: Release AsyncUnixFileLock(user.lock)
        end
    end
```

---

## Wire Protocol (`aionetstrings`)

Clients communicate over a persistent TCP or Unix Domain Socket connection using typed netstring dictionaries:

- **Initial request:** `{"spn": "http", "upn": "user@REALM", "jwt": "<keycloak_jwt>", "ctx": false}`
  - `spn` must match a short name configured under `[valid_spns]`.
  - `ctx: true` (used by `mailproxy`) keeps the `gssapi.SecurityContext` open on the connection for multi-round `{"step": "<base64>"}` exchanges and returns the exported context bytes once `complete` is `true`.
- **Response:** `{"token": "<base64>", "complete": true}` (plus `"ctx": <bytes>` when requested), or `{"error": "<message>"}` on failure.

---

## Configuration & Hot Reload

Configuration lives in `/etc/msxproxy/s4u2api.toml` (template: [`../deploy/etc/s4u2api.toml.example`](../deploy/etc/s4u2api.toml.example)), overridable via `S4U2API_CONFIG`. Under systemd, `LoadCredential=krb5_keytab:...` automatically takes precedence over `[kerberos].keytab`.

Sending `SIGHUP` (`systemctl reload s4u2api` or `./docker/msxproxy.sh reload s4u2api`) **hot-reloads without restarting**:
- `[valid_spns]` mapping
- `[oidc]` discovery metadata and Keycloak JWKS (atomic swap; preserves previous JWKS on error)
- `[kerberos]` principal, `ccache_dir`, and rotated `krb5_keytab` (clears cached `proxy_creds`)
- Flushes the Valkey JWT cache so stale entries do not linger

---

## CLI Options

```bash
python3 -m s4u2api --host 127.0.0.1 --port 7777 --workers 1 --log INFO
```

| Flag | Default | Description |
|---|---|---|
| `--host` / `--port` | From `s4u2api.toml` (`127.0.0.1:7777`) | TCP listen address and port |
| `--uds` | From `s4u2api.toml` (`None`) | Unix domain socket path with optional `:octal_mode` suffix (overrides TCP) |
| `--workers` | `1` | Number of worker processes |
| `--log` | `INFO` | Log level (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`) |
| `--cert` / `--key` | *(none)* | Optional TLS certificate & key for remote TCP listeners |

---

## CCache Cleanup

`s4u2api` automatically creates `ccache_dir` (default `/dev/shm/krb5_msxproxy`, mode `0700`) and runs a background hourly pruning task that removes per-user ccache and lock files older than 24 hours (while keeping `_primary`).

---

## Deployment

See [`../INSTALL.md`](../INSTALL.md) for Ubuntu bare-metal setup (Valkey, keytab creation with `ktutil`, and `deploy/systemd/s4u2api.service`) or [`../docker/README.md`](../docker/README.md) for Docker Compose deployment.
