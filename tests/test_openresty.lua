-- test_openresty.lua
--
-- Pure-LuaJIT unit tests for OpenResty modules:
--   authorization.lua, netstrings.lua, ratelimit.lua, metrics.lua, keycloak.lua
--
-- Run directly:  luajit tests/test_openresty.lua

local root = arg[0]:match("^(.*)/tests/test_openresty%.lua$") or "."
package.path = root .. "/openresty/lua/?.lua;" .. package.path

-- ── Minimal base64 + mock ngx runtime ────────────────────────────────────────

local b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local function decode_base64(data)
    if type(data) ~= "string" then return nil end
    data = data:gsub("%s+", "")
    if #data % 4 ~= 0 then return nil end
    if data:match("[^A-Za-z0-9+/=]") then return nil end
    local out = {}
    for i = 1, #data, 4 do
        local a, b, c, d = data:sub(i, i), data:sub(i+1, i+1), data:sub(i+2, i+2), data:sub(i+3, i+3)
        local ia = (b64chars:find(a, 1, true) or 1) - 1
        local ib = (b64chars:find(b, 1, true) or 1) - 1
        local ic = c == "=" and 0 or ((b64chars:find(c, 1, true) or 1) - 1)
        local id = d == "=" and 0 or ((b64chars:find(d, 1, true) or 1) - 1)
        local n = ia * 262144 + ib * 4096 + ic * 64 + id
        local b1 = math.floor(n / 65536) % 256
        local b2 = math.floor(n / 256) % 256
        local b3 = n % 256
        table.insert(out, string.char(b1))
        if c ~= "=" then table.insert(out, string.char(b2)) end
        if d ~= "=" then table.insert(out, string.char(b3)) end
    end
    return table.concat(out)
end

local fake_now = 1700000000

local function make_shared_dict()
    local store = {}
    local dict = {}
    function dict:get(k)
        local entry = store[k]
        if not entry then return nil, nil end
        if entry.exp and entry.exp <= fake_now then
            store[k] = nil
            return nil, nil
        end
        return entry.val, entry.flags
    end
    function dict:set(k, v, ttl, flags)
        local exp = (ttl and ttl > 0) and (fake_now + ttl) or nil
        store[k] = { val = v, flags = flags or 0, exp = exp }
        return true, nil, false
    end
    function dict:incr(k, delta, init, init_ttl)
        local cur = self:get(k)
        if cur == nil then
            if init == nil then return nil, "not found" end
            local nv = init + delta
            self:set(k, nv, init_ttl, 0)
            return nv, nil
        end
        local entry = store[k]
        entry.val = entry.val + delta
        return entry.val, nil
    end
    function dict:delete(k)
        store[k] = nil
    end
    function dict:get_keys()
        local keys = {}
        for k in pairs(store) do
            if self:get(k) ~= nil then
                table.insert(keys, k)
            end
        end
        return keys
    end
    function dict:_clear()
        store = {}
    end
    return dict
end

_G.ngx = {
    ERR = 4, WARN = 5, INFO = 7, ALERT = 2,
    shared = {
        auth_failures = make_shared_dict(),
        metrics       = make_shared_dict(),
    },
    time = function() return fake_now end,
    log = function() end,
    decode_base64 = decode_base64,
    encode_args = function(tbl)
        local parts = {}
        for k, v in pairs(tbl) do
            table.insert(parts, tostring(k) .. "=" .. tostring(v))
        end
        table.sort(parts)
        return table.concat(parts, "&")
    end,
}

-- Minimal JSON decoder for keycloak.lua tests
local mock_json_map = {}
package.loaded["cjson.safe"] = {
    decode = function(s)
        return mock_json_map[s]
    end,
}

-- Mock resty.http and resty.openidc for keycloak.lua tests
local mock_http_res, mock_http_err
local last_http_req_opts
local mock_discovery, mock_discovery_err
local mock_jwt_claims, mock_jwt_err

package.loaded["resty.http"] = {
    new = function()
        return {
            set_timeout = function() end,
            request_uri = function(_, url, opts)
                last_http_req_opts = opts
                return mock_http_res, mock_http_err
            end,
        }
    end,
}

package.loaded["resty.openidc"] = {
    get_discovery_doc = function(opts)
        if mock_discovery then
            opts.discovery = mock_discovery
        end
        return mock_discovery, mock_discovery_err
    end,
    jwt_verify = function(token, opts)
        return mock_jwt_claims, mock_jwt_err
    end,
}

local passed = 0
local function check(name, cond, msg)
    if not cond then
        error("[FAIL] " .. name .. (msg and (": " .. msg) or ""), 2)
    end
    passed = passed + 1
    print("[PASS] " .. name)
end

-- ── 1. authorization.lua ─────────────────────────────────────────────────────
local authorization = require("authorization")

do
    local m, p = authorization.split_header("Basic dXNlcjpwYXNzOndpdGg6Y29sb25z")
    check("authorization.split_header basic", m == "basic" and p == "dXNlcjpwYXNzOndpdGg6Y29sb25z")

    local u, pw, err = authorization.basic(p)
    check("authorization.basic decodes colon in password", u == "user" and pw == "pass:with:colons" and err == nil)

    local m2, p2 = authorization.split_header("Negotiate")
    check("authorization.split_header bare scheme", m2 == "negotiate" and p2 == nil)

    local u2, pw2, err2 = authorization.basic("%%%invalid%%%")
    check("authorization.basic rejects invalid base64", u2 == nil and pw2 == nil and err2 ~= nil)
end

-- ── 2. netstrings.lua ────────────────────────────────────────────────────────
local netstrings = require("netstrings")

do
    local wire = ""
    local fake_sock = {
        send = function(_, data)
            if type(data) == "table" then
                wire = wire .. table.concat(data)
            else
                wire = wire .. data
            end
            return #wire, nil
        end,
        receiveuntil = function(_, delim)
            return function()
                local idx = wire:find(delim, 1, true)
                if not idx then return nil, "closed" end
                local chunk = wire:sub(1, idx - 1)
                wire = wire:sub(idx + #delim)
                return chunk, nil
            end
        end,
        receive = function(_, n)
            if #wire < n then return nil, "closed" end
            local chunk = wire:sub(1, n)
            wire = wire:sub(n + 1)
            return chunk, nil
        end,
    }

    local input = { spn = "http", upn = "alice@UNI.AT", ctx = true, flag = false, count = 42 }
    local ok, err = netstrings.write_dict(fake_sock, input)
    check("netstrings.write_dict succeeds", ok and err == nil)

    local out, rerr = netstrings.read_dict(fake_sock)
    check("netstrings.read_dict round-trip",
        rerr == nil and out.spn == "http" and out.upn == "alice@UNI.AT"
        and out.ctx == true and out.flag == false and out.count == 42)
end

-- ── 3. ratelimit.lua & metrics.lua ───────────────────────────────────────────
local ratelimit = require("ratelimit")
local metrics   = require("metrics")

do
    ngx.shared.auth_failures:_clear()
    ngx.shared.metrics:_clear()

    local ip = "198.51.100.7"
    for i = 1, 14 do
        local banned = ratelimit.on_failure(ip)
        check("ratelimit failure #" .. i .. " not yet banned", not banned)
    end

    -- 15th failure triggers 60s ban (#1)
    local banned, dur = ratelimit.on_failure(ip)
    check("ratelimit 15th failure triggers 60s ban", banned == true and dur == 60)

    local is_b, rem = ratelimit.check(ip)
    check("ratelimit.check reports active ban", is_b == true and rem == 60)

    -- on_success while banned must NOT clear the active ban
    ratelimit.on_success(ip)
    local is_b2 = ratelimit.check(ip)
    check("ratelimit.on_success preserves active ban", is_b2 == true)

    -- Advance past ban expiry
    fake_now = fake_now + 61
    local is_b3 = ratelimit.check(ip)
    check("ratelimit.check clears after ban expires", is_b3 == false)

    -- 5 failures then on_success resets failure counter, but ban multiplier stays incremented
    for _ = 1, 5 do ratelimit.on_failure(ip) end
    ratelimit.on_success(ip)
    for _ = 1, 14 do
        local b = ratelimit.on_failure(ip)
        assert(not b, "expected reset after on_success")
    end
    local banned2, dur2 = ratelimit.on_failure(ip)
    check("ratelimit 2nd ban escalates to 120s after on_success", banned2 == true and dur2 == 120)

    -- Metrics check
    metrics.inc("msxproxy_auth_total", { method = "basic", result = "ok" })
    metrics.inc("msxproxy_auth_total", { method = "basic", result = "ok" })
    local prom = metrics.render()
    check("metrics.render emits Prometheus counters",
        prom:find('# TYPE msxproxy_auth_total counter', 1, true) ~= nil
        and prom:find('msxproxy_auth_total{method="basic",result="ok"} 2', 1, true) ~= nil
        and prom:find('msxproxy_ratelimit_bans_total 2', 1, true) ~= nil)
end

-- ── 4. keycloak.lua ──────────────────────────────────────────────────────────
local keycloak = require("keycloak")

do
    local cfg = {
        discovery     = "https://login.example/.well-known/openid-configuration",
        audience      = "https_webmail.uni-graz.at",
        client_id     = "https_webmail.uni-graz.at_DirectGrant",
        client_secret = "secret",
    }
    mock_discovery = {
        token_endpoint = "https://login.example/token",
        issuer         = "https://login.example/realms/UniGraz",
        jwks_uri       = "https://login.example/jwks",
    }
    mock_discovery_err = nil

    -- 4a. Valid external mail-password -> impersonate
    local ok_body = '{"access_token":"tok1"}'
    mock_json_map[ok_body] = { access_token = "tok1" }
    mock_http_res = { status = 200, headers = { ["Content-Type"] = "application/json" }, body = ok_body }
    mock_http_err = nil
    mock_jwt_claims = {
        iss = "https://login.example/realms/UniGraz",
        aud = { "account", "https_webmail.uni-graz.at" },
        exp = fake_now + 300,
        krb5_principal = "alice@PERS.AD.UNI-GRAZ.AT",
        acr = "mail-password",
    }
    mock_jwt_err = nil

    local res = keycloak.authenticate_basic(cfg, "alice", "pw", "203.0.113.1", false)
    check("keycloak external mail-password succeeds",
        res.impersonate and res.impersonate.upn == "alice@PERS.AD.UNI-GRAZ.AT" and res.impersonate.jwt == "tok1")

    -- 4b. External regular password (acr != mail-password) -> 403
    mock_jwt_claims.acr = "password"
    local res403 = keycloak.authenticate_basic(cfg, "alice", "pw", "203.0.113.1", false)
    check("keycloak external regular password returns 403", res403.abort and res403.abort.code == 403)

    -- 4c. Trusted network regular password -> allowed
    local res_trusted = keycloak.authenticate_basic(cfg, "alice", "pw", "10.0.0.5", true)
    check("keycloak trusted network regular password succeeds", res_trusted.impersonate ~= nil)

    -- 4d. Audience mismatch -> 401
    mock_jwt_claims.aud = "wrong_audience"
    local res_aud = keycloak.authenticate_basic(cfg, "alice", "pw", "10.0.0.5", true)
    check("keycloak audience mismatch returns 401", res_aud.abort and res_aud.abort.code == 401)
    mock_jwt_claims.aud = "https_webmail.uni-graz.at"

    -- 4e. Keycloak 400 invalid_grant -> 401
    local ig_body = '{"error":"invalid_grant","error_description":"Invalid user credentials"}'
    mock_json_map[ig_body] = { error = "invalid_grant", error_description = "Invalid user credentials" }
    mock_http_res = { status = 400, headers = { ["Content-Type"] = "application/json" }, body = ig_body }
    local res_ig = keycloak.authenticate_basic(cfg, "alice", "wrong", "203.0.113.1", false)
    check("keycloak invalid_grant maps to 401", res_ig.abort and res_ig.abort.code == 401)

    -- 4f. CrowdSec Ban HTML -> 403 + metric
    mock_http_res = { status = 403, headers = { ["Content-Type"] = "text/html" }, body = "<html><title>CrowdSec Ban</title></html>" }
    local res_cs_ban = keycloak.authenticate_basic(cfg, "alice", "pw", "203.0.113.1", false)
    check("keycloak CrowdSec Ban returns 403",
        res_cs_ban.abort and res_cs_ban.abort.code == 403 and res_cs_ban.abort.msg:find("CrowdSec BAN", 1, true) ~= nil)

    -- 4g. CrowdSec CAPTCHA HTML (HTTP 200) -> 403 + metric
    mock_http_res = { status = 200, headers = { ["Content-Type"] = "text/html" }, body = "<html><title>CrowdSec Captcha</title></html>" }
    local res_cs_cap = keycloak.authenticate_basic(cfg, "alice", "pw", "203.0.113.1", false)
    check("keycloak CrowdSec CAPTCHA returns 403",
        res_cs_cap.abort and res_cs_cap.abort.code == 403 and res_cs_cap.abort.msg:find("CrowdSec CAPTCHA", 1, true) ~= nil)

    local prom = metrics.render()
    check("keycloak CrowdSec metrics incremented",
        prom:find('msxproxy_crowdsec_blocks_total{type="ban"} 1', 1, true) ~= nil
        and prom:find('msxproxy_crowdsec_blocks_total{type="captcha"} 1', 1, true) ~= nil)

    -- 4h. ActiveSync DeviceID enroll mode: sends DeviceId/DeviceType/profile+email scope
    mock_http_res = { status = 200, headers = { ["Content-Type"] = "application/json" }, body = ok_body }
    mock_jwt_claims = {
        iss = "https://login.example/realms/UniGraz",
        aud = { "https_webmail.uni-graz.at" },
        exp = fake_now + 300,
        krb5_principal = "alice@PERS.AD.UNI-GRAZ.AT",
        preferred_username = "alice",
        email = "alice@uni-graz.at",
        name = "Alice Example",
        acr = "deviceId",
    }
    local res_dev = keycloak.authenticate_basic(cfg, "alice", "pw", "203.0.113.1", false, {
        activesync_enroll = true,
        device_id = "APPL999",
        device_type = "iPhone",
    })
    check("keycloak activesync deviceId ACR succeeds with impersonate",
        res_dev.impersonate ~= nil
        and last_http_req_opts.body:find("DeviceId=APPL999", 1, true) ~= nil
        and last_http_req_opts.body:find("DeviceType=iPhone", 1, true) ~= nil
        and last_http_req_opts.body:find("scope=openid profile email", 1, true) ~= nil)

    -- 4i. ActiveSync DeviceID enroll mode with unenrolled device (no acr) -> returns enroll payload
    mock_jwt_claims.acr = nil
    local res_enroll = keycloak.authenticate_basic(cfg, "alice", "pw", "203.0.113.1", false, {
        activesync_enroll = true,
        device_id = "NEWDEV",
        device_type = "Android",
    })
    check("keycloak activesync unenrolled device returns enroll payload",
        res_enroll.enroll ~= nil
        and res_enroll.enroll.subject == "alice"
        and res_enroll.enroll.email == "alice@uni-graz.at"
        and res_enroll.enroll.name == "Alice Example")
end

-- ── 5. owalogout.lua ─────────────────────────────────────────────────────────
local owalogout = require("owalogout")

do
    -- 5a. should_rewrite_request matching
    check("owalogout matches /owa/sessiondata.ashx",
        owalogout.should_rewrite_request("/owa/sessiondata.ashx", {}, {}))
    check("owalogout matches mixed-case /OWA/SessionData.ashx",
        owalogout.should_rewrite_request("/OWA/SessionData.ashx", {}, {}))
    check("owalogout matches explicit-logon /owa/other@uni-graz.at/sessiondata.ashx",
        owalogout.should_rewrite_request("/owa/other@uni-graz.at/sessiondata.ashx", {}, {}))
    check("owalogout matches /owa/service.svc?action=GetOwaUserConfiguration",
        owalogout.should_rewrite_request("/owa/service.svc", { action = "GetOwaUserConfiguration" }, {}))
    check("owalogout matches /owa/service.svc with mixed-case Action query arg & repeated table",
        owalogout.should_rewrite_request("/owa/service.svc", { Action = { "Other", "getowauserconfiguration" }, flag = true }, {}))
    check("owalogout matches /owa/service.svc with Action header",
        owalogout.should_rewrite_request("/owa/service.svc", {}, { Action = "GetOwaUserConfiguration" }))
    check("owalogout matches explicit-logon /owa/shared@uni-graz.at/service.svc with X-OWA-ActionName header",
        owalogout.should_rewrite_request("/owa/shared@uni-graz.at/service.svc", {}, { ["X-OWA-ActionName"] = "GetOwaUserConfiguration" }))

    -- Negative request matches
    check("owalogout skips /owa/",
        not owalogout.should_rewrite_request("/owa/", {}, {}))
    check("owalogout skips /owa/service.svc?action=FindItem",
        not owalogout.should_rewrite_request("/owa/service.svc", { action = "FindItem" }, { Action = "FindItem" }))
    check("owalogout skips /owa/prem/15.1.2507.71/scripts/boot.owaframe.2.mouse.js",
        not owalogout.should_rewrite_request("/owa/prem/15.1.2507.71/scripts/boot.owaframe.2.mouse.js", {}, {}))
    check("owalogout skips nil URI",
        not owalogout.should_rewrite_request(nil, {}, {}))

    -- 5b. header_filter guards
    local saved_ngx = _G.ngx

    local function run_header_filter(status, headers, flagged)
        local ctx = { owa_rewrite_logout = flagged }
        _G.ngx = { status = status, header = headers, ctx = ctx }
        owalogout.header_filter()
        return ctx, headers
    end

    local ctx1, h1 = run_header_filter(200, {
        ["Content-Type"] = "application/x-javascript",
        content_length = "129000",
        etag = '"abc"',
    }, true)
    check("header_filter keeps flag and clears content_length/etag on 200 application/x-javascript",
        ctx1.owa_rewrite_logout == true and h1.content_length == nil and h1.etag == nil)

    local ctx2, h2 = run_header_filter(200, {
        ["Content-Type"] = "application/json; charset=utf-8",
        content_length = "4096",
    }, true)
    check("header_filter keeps flag on 200 application/json",
        ctx2.owa_rewrite_logout == true and h2.content_length == nil)

    local ctx3, h3 = run_header_filter(200, {
        ["Content-Type"] = "application/x-javascript",
        ["Content-Encoding"] = "gzip",
        content_length = "1024",
    }, true)
    check("header_filter disables rewrite if upstream response is gzipped",
        ctx3.owa_rewrite_logout == false and h3.content_length == "1024")

    local ctx4, h4 = run_header_filter(500, {
        ["Content-Type"] = "application/json",
        content_length = "50",
    }, true)
    check("header_filter disables rewrite on non-200 status",
        ctx4.owa_rewrite_logout == false and h4.content_length == "50")

    local ctx5, h5 = run_header_filter(200, {
        ["Content-Type"] = "text/html; charset=utf-8",
        content_length = "500",
    }, true)
    check("header_filter disables rewrite on text/html",
        ctx5.owa_rewrite_logout == false and h5.content_length == "500")

    -- 5c. body_filter streaming rewrite across arbitrary chunk boundaries
    local function run_body_filter(chunks)
        local ctx = { owa_rewrite_logout = true }
        local out = {}
        for i = 1, #chunks do
            local is_eof = (i == #chunks)
            _G.ngx = { ctx = ctx, arg = { chunks[i], is_eof } }
            owalogout.body_filter()
            if _G.ngx.arg[1] and _G.ngx.arg[1] ~= "" then
                table.insert(out, _G.ngx.arg[1])
            end
        end
        return table.concat(out)
    end

    local sample = '{"owaUserConfig":{"ApplicationSettings":{"CheckForForgottenAttachmentsEnabled":true,"CloseWindowOnLogout":true,"ConsoleTracingEnabled":false,"IsLegacySignOut":true}},"Subject":"\\"CloseWindowOnLogout\\":true"}'
    local expected = '{"owaUserConfig":{"ApplicationSettings":{"CheckForForgottenAttachmentsEnabled":true,"CloseWindowOnLogout":false,"ConsoleTracingEnabled":false,"IsLegacySignOut":true}},"Subject":"\\"CloseWindowOnLogout\\":true"}'

    -- Single chunk
    check("body_filter single-chunk rewrite preserves escaped string literal",
        run_body_filter({ sample }) == expected)

    -- Final empty EOF chunk (typical nginx behavior)
    check("body_filter handles trailing empty EOF chunk",
        run_body_filter({ sample, "" }) == expected)

    -- Split at EVERY possible 2-chunk boundary
    local all_splits_ok = true
    for split = 1, #sample - 1 do
        local got = run_body_filter({ sample:sub(1, split), sample:sub(split + 1) })
        if got ~= expected then
            all_splits_ok = false
            break
        end
    end
    check("body_filter rewrites cleanly across every 2-chunk split boundary", all_splits_ok)

    -- 1-byte chunks (worst-case streaming fragmentation)
    local byte_chunks = {}
    for i = 1, #sample do
        byte_chunks[i] = sample:sub(i, i)
    end
    check("body_filter rewrites cleanly with 1-byte chunks",
        run_body_filter(byte_chunks) == expected)

    -- Whitespace + closing brace + already false + multiple occurrences
    local spaced = '{"a":1,"CloseWindowOnLogout" : true },{"CloseWindowOnLogout":false},{"CloseWindowOnLogout":true,"b":2}'
    local spaced_expected = '{"a":1,"CloseWindowOnLogout" : false },{"CloseWindowOnLogout":false},{"CloseWindowOnLogout":false,"b":2}'
    check("body_filter handles whitespace, closing brace, already-false, and multiple matches",
        run_body_filter({ spaced:sub(1, 25), "", spaced:sub(26, 70), spaced:sub(71) }) == spaced_expected)

    _G.ngx = saved_ngx
end

print("\nALL " .. passed .. " OPENRESTY LUA TESTS PASSED!")
