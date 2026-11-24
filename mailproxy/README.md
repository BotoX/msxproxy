# IMAP/SMTP Proxy

TODO


## Dependencies

```
useradd -r -m -d /opt/mailproxy -s /usr/sbin/nologin -K UMASK=0077 mailproxy

apt install python3-uvloop python3-jwt python3-httpx
```

## SystemD Service

`/etc/systemd/system/mailproxy.service`
```
[Unit]
Description=OAuth2Mail-Proxy Python IMAP/SMTP Server
After=network.target s4u2api.service
Wants=s4u2api.service

[Service]
Type=simple
User=mailproxy
Group=mailproxy

ProtectSystem=strict
PrivateTmp=yes

AmbientCapabilities=CAP_NET_BIND_SERVICE

WorkingDirectory=/opt/msxproxy/mailproxy
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart=/usr/bin/python3 -m mailproxy --config /etc/msxproxy/mailproxy.toml --metrics-host 127.0.0.1 --metrics-port 9101
ExecReload=/bin/kill -HUP $MAINPID

Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

All configuration and secrets live in `/etc/msxproxy/mailproxy.toml` (template at `deploy/etc/mailproxy.toml.example`, `chmod 0640 root:mailproxy`).

`systemctl reload mailproxy` (`SIGHUP`) hot-reloads `mailproxy.toml` (trusted networks, caps, timeouts, OIDC credentials), refreshes Keycloak JWKS, and reloads TLS certificates without dropping active IMAP/SMTP connections.

When `--metrics-port` is specified, Prometheus metrics are served at `http://<metrics-host>:<metrics-port>/metrics` (`mailproxy_connections_total`, `mailproxy_connections_active`, `mailproxy_auth_total`, `mailproxy_backend_errors_total`, `mailproxy_backend_up`).

## Fail2Ban

TODO: Something more modern like crowdsec or implement ban system into python app

`/etc/fail2ban/filter.d/mailproxy.conf`
```
[INCLUDES]
before = common.conf

[Definition]
_daemon = python3
failregex = ^%(__prefix_line)s\[\w+\] mailproxy\.\w+: \w+ \w+ authentication failed from '<HOST>':.*$

journalmatch = _SYSTEMD_UNIT=mailproxy.service
```

`/etc/fail2ban/jail.local`
```
[DEFAULT]
banaction = nftables
banaction_allports = nftables[type=allports]

bantime = 5m
findtime = 12h
maxretry = 15
bantime.increment = true
#bantime.multipliers = 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
#bantime.maxtime = 15m

[mailproxy]
enabled = true
port = 143,993,587,465
filter = mailproxy
backend = systemd
```
