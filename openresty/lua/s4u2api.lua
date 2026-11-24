local _M = {}

local ngx = ngx
local netstrings = require("netstrings")
local metrics = require("metrics")
local ok_cfg, config = pcall(require, "config")
local s4u_cfg = (ok_cfg and config and config.s4u2api) or {}
local S4U_HOST    = s4u_cfg.host or "127.0.0.1"
local S4U_PORT    = s4u_cfg.port or 7777
local S4U_SPN     = s4u_cfg.spn or "http"
local S4U_TIMEOUT = s4u_cfg.timeout or 5000

function _M.impersonate(upn, jwt)
    if (ngx.var.http2 or "") ~= "" then
        -- Empty NTLM Authorization header for ntlm plugin HTTP/2->HTTP/1.1 connection downgrade
        ngx.req.set_header("Authorization", "NTLM")
        return
    end

    local sock = ngx.socket.tcp()
    sock:settimeouts(S4U_TIMEOUT, S4U_TIMEOUT, S4U_TIMEOUT)
    local ok, err = sock:connect(S4U_HOST, S4U_PORT)

    if not ok then
        ngx.log(ngx.ERR, "[s4u2api] Failed to connect: ", err)
        metrics.inc("msxproxy_s4u2api_requests_total", { result = "error" })
        return ngx.exit(500)
    end

    local req = {
        spn = S4U_SPN,
        upn = upn,
        jwt = jwt
    }

    local ok, err = netstrings.write_dict(sock, req)
    if not ok then
        ngx.log(ngx.ERR, "[s4u2api] Failed to send data: ", err)
        metrics.inc("msxproxy_s4u2api_requests_total", { result = "error" })
        return ngx.exit(500)
    end

    local res, err = netstrings.read_dict(sock)
    if not res then
        ngx.log(ngx.ERR, "[s4u2api] Failed to read data: ", err)
        metrics.inc("msxproxy_s4u2api_requests_total", { result = "error" })
        return ngx.exit(500)
    end

    if res["error"] then
        ngx.status = 500
        err = "S4U2Api returned error: " .. res["error"]
        ngx.log(ngx.ERR, err)
        metrics.inc("msxproxy_s4u2api_requests_total", { result = "error" })
        ngx.header.content_type = 'text/plain'
        ngx.say("Internal Server Error.\n" .. err)
        return ngx.exit(500)
    end

    local token = res["token"]
    ngx.req.set_header("Authorization", "Negotiate " .. token)
    metrics.inc("msxproxy_s4u2api_requests_total", { result = "ok" })

    sock:setkeepalive(60000)
    return
end

return _M
