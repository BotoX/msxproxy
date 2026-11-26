#!/bin/sh
set -eu

# 1. Trust the generated Test Root CA in the system bundle so the real
#    deploy/openresty/msxproxy-http.conf (/etc/ssl/certs/ca-certificates.crt)
#    verifies Keycloak and Mock Exchange TLS certificates verbatim.
cp /certs/ca.crt /usr/local/share/ca-certificates/msxproxy-test-ca.crt
update-ca-certificates >/dev/null

# 2. Populate /etc/msxproxy/ssl/ with the exact cert filenames expected by
#    openresty/conf.d/webmail.conf (including dual EC-384 + RSA certs).
mkdir -p /etc/msxproxy/ssl /opt/msxproxy/openresty/conf.d
ln -sf /certs/webmail-ec-384.pem   /etc/msxproxy/ssl/webmail-ec-384.pem
ln -sf /certs/webmail-ec-384.key   /etc/msxproxy/ssl/webmail-ec-384.key
ln -sf /certs/webmail-rsa-3072.pem /etc/msxproxy/ssl/webmail-rsa-3072.pem
ln -sf /certs/webmail-rsa-3072.key /etc/msxproxy/ssl/webmail-rsa-3072.key
ln -sf /certs/webmail-rsa-3072.pem /etc/msxproxy/ssl/autoconfig.pem
ln -sf /certs/webmail-rsa-3072.key /etc/msxproxy/ssl/autoconfig.key
ln -sf /certs/webmail-ec-384.pem   /etc/msxproxy/ssl/autodiscover-ec-384.pem
ln -sf /certs/webmail-ec-384.key   /etc/msxproxy/ssl/autodiscover-ec-384.key
ln -sf /certs/webmail-rsa-3072.pem /etc/msxproxy/ssl/autodiscover-rsa-3072.pem
ln -sf /certs/webmail-rsa-3072.key /etc/msxproxy/ssl/autodiscover-rsa-3072.key

# 3. Copy live repo openresty/conf.d/*.conf and adapt only environment-specific
#    bindings in webmail.conf (port, hostnames, container upstream for
#    @activesync_enroll, Docker CIDR on /status & /metrics, and is_testIP for
#    Autodiscover XML rewriting) so every edit to openresty/conf.d/webmail.conf
#    or deploy/openresty/msxproxy-http.conf is tested directly.
cp /opt/msxproxy/openresty/conf.d.src/*.conf /opt/msxproxy/openresty/conf.d/
/usr/local/openresty/luajit/bin/luajit - <<'LUA'
local src_path = "/opt/msxproxy/openresty/conf.d.src/webmail.conf"
local dst_path = "/opt/msxproxy/openresty/conf.d/webmail.conf"

local f = assert(io.open(src_path, "rb"))
local conf = f:read("*a")
f:close()

local function must_replace(pattern, repl, label)
    local out, n = conf:gsub(pattern, repl)
    if n == 0 then
        io.stderr:write("[openresty-entrypoint] ERROR: expected pattern not found in webmail.conf: " .. label .. "\n")
        os.exit(1)
    end
    conf = out
end

-- Listen on 18443 inside the container to match host port for browser OIDC redirects
must_replace("listen 443 ssl;", "listen 18443 ssl;", "listen 443 ssl")

-- Map production vhost server_names to RFC 6761 *.localhost test names
must_replace("server_name webmail%.uni%-graz%.at;", "server_name webmail.localhost localhost;", "webmail server_name")
must_replace("server_name autodiscover%.uni%-graz%.at autodiscover%.edu%.uni%-graz%.at;", "server_name autodiscover.localhost;", "autodiscover server_name")

-- Point @activesync_enroll to the activesync-enroll container
must_replace("proxy_pass http://127%.0%.0%.1:8000;", "proxy_pass http://activesync-enroll:8000;", "@activesync_enroll proxy_pass")

-- Point /metrics/mailproxy to the mailproxy container
must_replace("proxy_pass http://127%.0%.0%.1:9101/metrics;", "proxy_pass http://mailproxy:9101/metrics;", "/metrics/mailproxy proxy_pass")

-- Allow Docker bridge clients to reach /status and /metrics
must_replace("allow 127%.0%.0%.1;", "allow 127.0.0.1;\n        allow 172.16.0.0/12;\n        allow 192.168.0.0/16;", "/status & /metrics allow")

-- Rewrite Autodiscover XML URLs to test webmail host:port (triggered via ModernAuth=1)
must_replace("webmail%.uni%-graz%.at", "webmail.localhost:18443", "Autodiscover rewrite target")

local out_f = assert(io.open(dst_path, "wb"))
out_f:write(conf)
out_f:close()
LUA

exec /usr/local/openresty/bin/openresty -g "daemon off;"
