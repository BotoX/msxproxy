# msxauthapi

## Dependencies

```
apt install python3-fastapi python3-uvicorn python3-jwt python3-httpx

apt install python3-pip python3-dev
pip install git+https://github.com/BotoX/python-wbxml.git --break-system-packages
```

## SystemD Service

`/etc/systemd/system/msxauthapi.service`
```
[Unit]
Description=Exchange Auth Python API @ 127.0.0.1:8000
After=network.target

[Service]
Type=simple
User=msxauthapi

WorkingDirectory=/opt/msxauthapi
ExecStart=/usr/bin/python3 -m uvicorn msxauthapi.main:app --host 127.0.0.1 --port 8000 --no-access-log

Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```
