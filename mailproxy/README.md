# Mailproxy (IMAP / SMTP Authentication Proxy)

Asynchronous Python (`asyncio` + `uvloop`) authentication and protocol-bridging proxy for **IMAP/IMAPS** (`143` / `993`) and **SMTP/SMTPS** (`587` / `465`) in front of Microsoft Exchange.

Mailproxy terminates client TLS, enforces modern authentication policies against **Keycloak**, obtains Kerberos S4U2Proxy service tickets from **`s4u2api`**, authenticates to Exchange backends using **GSSAPI**, and then relays traffic transparently in both directions.

---

## Architecture Overview

```mermaid
flowchart LR
    Client["Mail Clients\n(Thunderbird, Apple Mail, etc.)"]

    subgraph MP["mailproxy (asyncio / uvloop)"]
        direction TB
        Listeners["Listeners (Dual ECDSA + RSA TLS)\nIMAP :143 (STARTTLS) · IMAPS :993\nSMTP :587 (STARTTLS) · SMTPS :465"]
        Auth["SASL Auth & Policy\nXOAUTH2 · OAUTHBEARER · PLAIN · LOGIN\nACR + trusted_networks enforcement"]
        LB["LoadBalancer\nActive TCP/TLS health probes\nRound-robin across UP backends"]
        Relay["Bidirectional TCP Relay\nTCP keepalive + graceful drain"]
        Metrics["Prometheus /metrics\n127.0.0.1:9101"]
        Listeners --> Auth --> LB --> Relay
    end

    KC["Keycloak\n(JWKS + ROPC Direct Grant)"]
    S4U["s4u2api\n(Kerberos S4U2Proxy)"]
    EX["Microsoft Exchange\nIMAPS :993 · SMTP+STARTTLS :587"]

    Client -->|"TLS / STARTTLS"| Listeners
    Auth -->|"JWKS verify / ROPC"| KC
    LB -->|"GSSAPI impersonation"| S4U
    Relay <-->|"GSSAPI-authenticated TLS"| EX
```

---

## Sequence Diagrams

### 1. Client TLS, SASL Authentication & Policy Enforcement

Every client connection must be encrypted (implicit TLS on `993`/`465` or upgraded via `STARTTLS` on `143`/`587`) before any authentication mechanism is accepted. Pipelined commands after `STARTTLS` are rejected, and unauthenticated connections are closed after `auth_timeout`.

```mermaid
sequenceDiagram
    participant C as Mail Client
    participant P as mailproxy
    participant K as Keycloak

    C->>P: Connect (:993/:465 implicit TLS, or :143/:587 plain)
    P-->>C: Greeting (* OK / 220 ESMTP)

    opt Plaintext port (:143 or :587)
        C->>P: STARTTLS
        Note over P: Reject any pipelined bytes after STARTTLS
        P-->>C: OK / 220 Ready to start TLS
        Note over C,P: TLS handshake (dual ECDSA + RSA certs, TLS 1.2+)
    end

    C->>P: CAPABILITY / EHLO
    P-->>C: Advertise AUTH=XOAUTH2 AUTH=OAUTHBEARER AUTH=PLAIN AUTH=LOGIN

    alt OAuth2 Token (XOAUTH2 / OAUTHBEARER)
        C->>P: SASL payload (user + Bearer JWT)
        P->>P: Verify JWT signature, iss & aud via cached Keycloak JWKS
    else Password (PLAIN / LOGIN)
        C->>P: Username + Password
        P->>+K: ROPC Direct Grant (with X-Forwarded-For client IP for CrowdSec)
        alt Invalid credentials / CrowdSec block
            K-->>P: Error
            P-->>C: NO / 535 Authentication failed
        else Credentials valid
            K-->>-P: Access/ID Token (JWT)
            P->>P: Verify JWT via Keycloak JWKS
            Note over P: Policy check: client IP in trusted_networks<br/>OR token acr == "mail-password"
        end
    end

    Note over P: Extract krb5_principal (UPN) for backend impersonation
```

### 2. Backend Load Balancing, GSSAPI Impersonation & Relay

Once the client is authenticated, `mailproxy` picks the next healthy Exchange server from the protocol's `LoadBalancer`, establishes a TLS-verified backend session (`IMAPS` or mandatory `STARTTLS` for `SMTP`), performs the multi-step `GSSAPI` handshake through `s4u2api`, and hands the sockets off to the bidirectional relay.

```mermaid
sequenceDiagram
    participant C as Mail Client
    participant P as mailproxy
    participant LB as LoadBalancer
    participant T as s4u2api
    participant E as Exchange Backend

    P->>LB: next_backend() (round-robin over UP backends)
    LB-->>P: ex19ms0X (host, port, tls)

    P->>+E: Connect (IMAPS :993 or SMTP :587 + mandatory STARTTLS)
    E-->>P: Greeting & capabilities

    P->>+T: netstrings {spn, upn, jwt, ctx: true}
    T-->>P: {token, complete, [ctx]}

    P->>E: AUTHENTICATE GSSAPI / AUTH GSSAPI <initial-token>
    loop While GSSAPI handshake not complete
        E-->>P: + <server-challenge>
        P->>T: netstrings {step: challenge, ctx: true}
        T-->>P: {token, complete, [ctx]}
        P->>E: <response-token>
    end
    T-->>-P: Exported GSSAPI SecurityContext (ctx)

    Note over P,E: Final GSSAPI security-layer negotiation (ctx.unwrap / ctx.wrap)
    E-->>P: TAG OK / 235 Authentication successful
    P-->>C: TAG OK / 235 Authentication successful

    rect rgb(235, 245, 255)
        Note over C,E: Bidirectional TCP Relay (relay.py) — TCP keepalive + graceful EOF drain
        C<<->>P: Encrypted IMAP / SMTP stream
        P<<->>E: Encrypted IMAP / SMTP stream
    end
    deactivate E
```

---

## Security & Operational Highlights

- **Strict TLS enforcement:** Cleartext authentication is blocked; `STARTTLS` pipelining is rejected; backend SMTP requires `STARTTLS` (cleartext downgrade refused); TLS 1.2+ with dual ECDSA + RSA certificate support.
- **Pre-authentication isolation:** Post-auth IMAP commands (`SELECT`, `FETCH`, `IDLE`, etc.) and SMTP relay commands (`MAIL FROM`, `RCPT TO`, `DATA`, `BDAT`) are rejected before authentication succeeds.
- **Brute-force protection & built-in multi-worker rate limiting:** Client source IPs are forwarded via `X-Forwarded-For` on Keycloak ROPC requests for Keycloak / CrowdSec, AND a built-in shared-memory per-IP rate limiter (`ratelimit.py`, ~5.5 MiB fixed anonymous `mmap`, 131,072 slots) enforces incremental bans across all forked workers (`--workers > 1`) and all four ports (`143`, `993`, `587`, `465`) with zero external dependencies (completely isolated from `s4u2api`'s Valkey and Kerberos ccaches). `TrustedNetworkError` and upstream Keycloak outages are excluded from ban counts, matching OpenResty.
- **Active load balancing:** Background health probes mark backends `DOWN` after `fall` consecutive failures and `UP` after `rise` consecutive successes, without interrupting established connections.
- **Multi-worker scalability:** `--workers N` forks workers sharing pre-bound `SO_REUSEPORT` sockets, with shared-memory Prometheus counters and coordinated `SIGHUP` / `SIGTERM` handling.

---

## Configuration & Hot Reload

All settings and secrets live in `/etc/msxproxy/mailproxy.toml` (template: [`../deploy/etc/mailproxy.toml.example`](../deploy/etc/mailproxy.toml.example)), overridable via `--config` or `MAILPROXY_CONFIG`.

Sending `SIGHUP` (`systemctl reload mailproxy` or `./docker/msxproxy.sh reload mailproxy`) **hot-reloads without dropping active connections**:
- TLS certificate & key chains (`[proxy].certs`)
- `[oidc]` credentials, discovery metadata, and Keycloak JWKS
- `[proxy]` settings & `trusted_networks`, `[s4u2api]` target
- `[imap]` & `[smtp]` backend pools (for new connections, preserving existing backend health state) and capabilities
- `[loadbalancer]` probe thresholds and `[ratelimit]` settings (`enabled`, `base_bantime`, `findtime`, `maxretry`, `max_bantime`, `ignore_networks`)

*(Changing listening hosts or ports requires a restart.)*

---

## CLI Options

```bash
python3 -m mailproxy \
  --config /etc/msxproxy/mailproxy.toml \
  --workers 1 \
  --log INFO \
  --metrics-host 127.0.0.1 \
  --metrics-port 9101
```

| Flag | Default | Description |
|---|---|---|
| `--config` | `/etc/msxproxy/mailproxy.toml` | Path to TOML configuration file (also `MAILPROXY_CONFIG`) |
| `--log` | `INFO` | Log level (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`) |
| `--workers` | `1` | Number of forked worker processes |
| `--metrics-host` | `127.0.0.1` | Bind address for Prometheus HTTP `/metrics` endpoint |
| `--metrics-port` | *(disabled)* | Bind port for Prometheus `/metrics` (reverse-proxied by OpenResty at `/metrics/mailproxy`) |

---

## Prometheus Metrics

When `--metrics-port` is enabled, `GET /metrics` exposes Prometheus text format (`0.0.4`) aggregated across all workers:

| Metric | Type | Labels | Description |
|---|---|---|---|
| `mailproxy_connections_total` | counter | `protocol` (`imap`, `smtp`) | Total client connections accepted |
| `mailproxy_connections_active` | gauge | `protocol` | Currently active client connections |
| `mailproxy_auth_total` | counter | `protocol`, `result` (`ok`, `failed`, `trusted_network_denied`, `ratelimited`, `error`) | Client authentication outcomes |
| `mailproxy_ratelimit_bans_total` | counter | — | Total IP bans triggered by the mailproxy rate limiter |
| `mailproxy_backend_errors_total` | counter | `protocol` | Backend connection or GSSAPI auth failures |
| `mailproxy_backend_up` | gauge | `pool` (`imap`, `smtp`), `backend` | Exchange backend health (`1` = UP, `0` = DOWN) |

---

## Deployment

See [`../INSTALL.md`](../INSTALL.md) for Ubuntu bare-metal deployment (`deploy/systemd/mailproxy.service`) or [`../docker/README.md`](../docker/README.md) for Docker Compose deployment.
