local _M = {}

local ngx = ngx
local netstrings = require("netstrings")

function _M.impersonate(upn, jwt)
    if (ngx.var.http2 or "") ~= "" then
        -- Empty NTLM Authorization header for ntlm plugin HTTP/2->HTTP/1.1 connection downgrade
        ngx.req.set_header("Authorization", "NTLM")
        return
    end

    local sock = ngx.socket.tcp()
    sock:settimeouts(5000, 5000, 5000)
    local ok, err = sock:connect("127.0.0.1", 7777)

    if not ok then
        ngx.log(ngx.ERR, "[s4u2api] Failed to connect: ", err)
        return ngx.exit(500)
    end

    local req = {
        spn = "http",
        upn = upn,
        jwt = jwt
    }

    local ok, err = netstrings.write_dict(sock, req)
    if not ok then
        ngx.log(ngx.ERR, "[s4u2api] Failed to send data: ", err)
        return ngx.exit(500)
    end

    local res, err = netstrings.read_dict(sock)
    if not res then
        ngx.log(ngx.ERR, "[s4u2api] Failed to read data: ", err)
        return ngx.exit(500)
    end

    if res["error"] then
        ngx.status = 500
        err = "S4U2Api returned error: " .. res["error"]
        ngx.log(ngx.ERR, err)
        ngx.header.content_type = 'text/plain'
        ngx.say("Internal Server Error.\n" .. err)
        return ngx.exit(500)
    end

    local token = res["token"]
    ngx.req.set_header("Authorization", "Negotiate " .. token)

    sock:setkeepalive(60000)
    return
end

return _M
