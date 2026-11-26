#!/bin/sh
set -eu

# Trust any custom internal Root CA certificates dropped into /etc/msxproxy/ca/*.crt
if [ -d /etc/msxproxy/ca ]; then
    found=0
    for ca in /etc/msxproxy/ca/*.crt; do
        if [ -f "$ca" ]; then
            cp "$ca" "/usr/local/share/ca-certificates/msxproxy-$(basename "$ca")"
            found=1
        fi
    done
    if [ "$found" -eq 1 ]; then
        update-ca-certificates >/dev/null
    fi
fi

exec "$@"
