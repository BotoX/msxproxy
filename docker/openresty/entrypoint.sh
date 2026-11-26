#!/bin/sh
set -eu

# 1. Trust any custom internal Root CA certificates dropped into /etc/msxproxy/ca/*.crt
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

# 2. Generate /tmp/resolver.conf for Lua cosockets (lua-resty-openidc / healthcheck)
if [ -n "${OPENRESTY_RESOLVER:-}" ]; then
    printf 'resolver %s;\n' "${OPENRESTY_RESOLVER}" > /tmp/resolver.conf
else
    NAMESERVERS="$(awk '
        /^[[:space:]]*nameserver[[:space:]]+/ {
            ip = $2
            if (ip ~ /:/) {
                ip = "[" ip "]"
            }
            if (out != "") out = out " "
            out = out ip
        }
        END { print out }
    ' /etc/resolv.conf 2>/dev/null || true)"

    if [ -z "${NAMESERVERS}" ]; then
        NAMESERVERS="127.0.0.53"
    fi
    printf 'resolver %s valid=30s;\n' "${NAMESERVERS}" > /tmp/resolver.conf
fi

exec /usr/local/openresty/bin/openresty -c /etc/msxproxy-openresty/nginx.conf -g "daemon off;"
