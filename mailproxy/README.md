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

WorkingDirectory=/opt/mailproxy
ExecStart=/usr/bin/python3 -m mailproxy

Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

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
