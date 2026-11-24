# S4U2Api

Use [ktutil](https://web.mit.edu/kerberos/krb5-1.12/doc/admin/admin_commands/ktutil.html) to create the keytab file.

## Overview

```mermaid
graph TD
    A[OpenResty] -->|JWT over TCP/UDS| B(S4U2Api Master Process)
    B -->|Distributes| C[S4U2Api Worker]
    C <-->|1. Check JWT Cache| E[(Valkey/Redis in RAM)]
    C <-->|1a. Verify JWT| D[pyjwt with keys from<br>Keycloak OIDC]
    C <-->|2. Check Ticket Cache| G[(KRB5 CCache in /dev/shm)]
    C <-->|2a. S4U2Proxy Delegation| F[Active Directory KDC]
    C -->|3. Return Base64 Token| A
```

### Executive Summary

S4U2Api is a specialized middleware service acting as a bridge between modern OpenID Connect (OIDC) authentication and legacy Kerberos infrastructure.  
It is explicitly designed to translate Keycloak JWTs into Kerberos Service Tickets for Microsoft Exchange components like HTTP, IMAP, and SMTP.

The project leverages the Kerberos S4U2Proxy (Constrained Delegation) extension.  
When a user authenticates via OIDC, this API takes the provided JWT, cryptographically verifies it, and instructs the Kerberos Key Distribution Center (KDC) to issue a ticket on behalf of that user to the target service.

The architecture bridges modern asynchronous Python (asyncio) with synchronous, C-based Kerberos and GSSAPI libraries by offloading blocking network/crypto operations to thread pools.  
It implements an aggressive on-disk caching layer using the RAM-backed /dev/shm filesystem and file-based locking to prevent "thundering herd" scenarios against the Active Directory Key Distribution Center (KDC).

Overall, the codebase utilizes modern asynchronous Python (asyncio, uvloop) and an efficient caching mechanism to handle high loads.


## Worker Sequence Diagram

```mermaid
sequenceDiagram
    participant C as OpenResty
    participant L as S4U2Api Worker
    participant V as Valkey Cache
    participant K as Kerberos Proxy

    C->>L: Request (SPN, UPN, JWT)
    L->>V: GET jwt:{hash}

    alt Cache Miss
        L->>V: SETNX lock:{hash}
        alt Acquired Lock (Leader Worker)
            L->>L: Verify JWT Signature & Claims<br>with Keycloak keys
            Note over L: User Principal from JWT claims
            L->>L: HMAC Sign Cache Payload (User Principal)
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

    L->>K: kerb_proxy.create_context(UPN, SPN)
    K-->>L: Kerberos Service Ticket
    L-->>C: Base64 Encoded Token
```

## Kerberos Sequence Diagram

```mermaid
sequenceDiagram
    participant EventLoop as Kerberos Proxy<br>Asyncio Event Loop
    participant Executor as ThreadPool Executor
    participant UCache as User CCache<br>/dev/shm
    participant PCache as Primary CCache<br>/dev/shm
    participant KDC as Active Directory KDC

    EventLoop->>EventLoop: create_context(upn, spn)

    Note over EventLoop, UCache: 1. Try Fast Path (No Locking)
    EventLoop->>UCache: user_creds = _krb5_get_creds(ccache_path, spn)

    alt User Creds found & valid > 5m
        EventLoop->>EventLoop: token, ctx = init_context(user_creds)
        Note over EventLoop, UCache: RETURN Token from User CCache

    else User Creds missing or expired
        Note over EventLoop, KDC: 2. The Heavy Path (Locking)
        EventLoop->>+UCache: Acquire AsyncUnixFileLock(user.lock)

        EventLoop->>UCache: user_creds = _krb5_get_creds(ccache_path, spn)

        alt User Creds found & valid > 5m<br>(Another worker got the lock first)
            EventLoop->>EventLoop: token, ctx = init_context(user_creds)
            UCache->>EventLoop: Release AsyncUnixFileLock(user.lock)
            Note over EventLoop, UCache: RETURN Token from User CCache

        else User Creds still missing or expired after acquiring lock
            EventLoop->>EventLoop: proxy_creds = get_proxy_creds()
            alt Proxy Creds expired
                Note over EventLoop, PCache: 3. Master Proxy Credential Locking
                EventLoop->>+PCache: Acquire AsyncUnixFileLock(_primary.lock)
                EventLoop->>PCache: try: gssapi.Credentials(_primary)
                alt Proxy creds still expired
                    EventLoop->>PCache: delete _primary
                    EventLoop->>+Executor: run_in_executor(gssapi.Credentials(_primary))
                    Executor->>+KDC: Get Master TGT
                    KDC-->>-Executor: Master TGT
                    Executor->>PCache: Write _primary ccache
                    Executor-->>-EventLoop: proxy_creds
                end
                PCache-->>EventLoop: proxy_creds
                PCache->>-EventLoop: Release AsyncUnixFileLock(_primary.lock)
            end

            Note over EventLoop, KDC: 4. Impersonation (S4U2Proxy)
            EventLoop->>+Executor: run_in_executor(proxy_creds.impersonate)
            Executor->>+KDC: Get User Ticket
            KDC-->>-Executor: User Ticket
            Executor-->>-EventLoop: user_creds
        end

        EventLoop->>+Executor: run_in_executor(init_context(user_creds))
        Executor->>+KDC: Get Service Ticket
        KDC-->>-Executor: Service Ticket
        Executor-->>-EventLoop: Token, gssapi.SecurityContext
        EventLoop->>UCache: Write user ccache

        UCache->>-EventLoop: Release AsyncUnixFileLock(user.lock)

        Note over EventLoop, KDC: RETURN Token from KDC

    end
```


## Dependencies

```
apt install valkey-server
useradd -r -m -d /opt/s4u2api -s /usr/sbin/nologin -K UMASK=0077 s4u2api
usermod -aG valkey s4u2api
```

`/etc/valkey/valkey.conf`
```
# valkey.conf

port 0
unixsocket /dev/shm/valkey.sock
unixsocketperm 660

# Disable all disk persistence for the JWT cache
save ""
appendonly no

maxmemory 64mb
maxmemory-policy allkeys-lru

loglevel notice
```

```
apt install python3-uvloop python3-gssapi python3-jwt python3-httpx python3-redis python3-filelock krb5-user
```

## SystemD Service

`/etc/systemd/system/s4u2api.service`
```
[Unit]
Description=S4U2Proxy Python API
After=network.target valkey-server.service
Requires=valkey-server.service

[Service]
Type=simple
User=s4u2api
Group=s4u2api

LoadCredential=krb5_keytab:/root/_msxproxy.keytab

ProtectSystem=strict
PrivateTmp=yes
ReadWritePaths=/dev/shm

LimitNOFILE=65535
WorkingDirectory=/opt/s4u2api
ExecStart=/usr/bin/python3 -m s4u2api --host 127.0.0.1 --port 7777

Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

## CCache Cleanup (`systemd-tmpfiles`)

`/etc/tmpfiles.d/s4u2api.conf`
```
d /dev/shm/krb5_msxproxy 0700 s4u2api s4u2api 1d
```

Apply immediately with `systemd-tmpfiles --create /etc/tmpfiles.d/s4u2api.conf`. Files older than 24 hours (`1d`) are pruned automatically by `systemd-tmpfiles-clean.timer`.
