-- test_openresty_e2e.lua
--
-- End-to-end execution tests of openresty/lua/msxauth.lua and openresty/lua/owaauth.lua
-- under a full mocked OpenResty ngx runtime.
--
-- Exercises actual request dispatch, security boundaries, cache isolation between
-- trusted/untrusted networks, pinned socket header stripping, rate-limit interaction,
-- Bearer issuer routing, Autodiscover, and OWA session handling.

local root = arg[0]:match("^(.*)/tests/test_openresty_e2e%.lua$") or "."
package.path = root .. "/openresty/lua/?.lua;" .. package.path

local b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local function encode_base64(data)
    return ((data:gsub('.', function(x)
        local r, b = '', x:byte()
        for i = 8, 1, -1 do r = r .. (b % 2 ^ i - b % 2 ^ (i - 1) > 0 and '1' or '0') end
        return r
    end) .. '0000'):gsub('%d%d%d?%d?%d?%d?', function(x)
        if #x < 6 then return '' end
        local c = 0
        for i = 1, 6 do c = c + (x:sub(i, i) == '1' and 2 ^ (6 - i) or 0) end
        return b64chars:sub(c + 1, c + 1)
    end) .. ({ '', '==', '=' })[#data % 3 + 1])
end

local function decode_base64(data)
    if type(data) ~= "string" then return nil end
    data = data:gsub("%s+", "")
    if #data % 4 ~= 0 then return nil end
    if data:match("[^A-Za-z0-9+/=]") then return nil end
    local out = {}
    for i = 1, #data, 4 do
        local a, b, c, d = data:sub(i,i), data:sub(i+1,i+1), data:sub(i+2,i+2), data:sub(i+3,i+3)
        local ia = (b64chars:find(a, 1, true) or 1) - 1
        local ib = (b64chars:find(b, 1, true) or 1) - 1
        local ic = c == "=" and 0 or ((b64chars:find(c, 1, true) or 1) - 1)
        local id = d == "=" and 0 or ((b64chars:find(d, 1, true) or 1) - 1)
        local n = ia * 262144 + ib * 4096 + ic * 64 + id
        table.insert(out, string.char(math.floor(n / 65536) % 256))
        if c ~= "=" then table.insert(out, string.char(math.floor(n / 256) % 256)) end
        if d ~= "=" then table.insert(out, string.char(n % 256)) end
    end
    return table.concat(out)
end

-- Simple deterministic JSON encode/decode for test tables (supports nested objects/strings/numbers/bools)
local function json_encode(v)
    local t = type(v)
    if t == "string" then return string.format("%q", v)
    elseif t == "number" or t == "boolean" then return tostring(v)
    elseif t == "table" then
        local parts = {}
        for k, val in pairs(v) do
            table.insert(parts, string.format("%q:%s", tostring(k), json_encode(val)))
        end
        table.sort(parts)
        return "{" .. table.concat(parts, ",") .. "}"
    end
    return "null"
end

-- Store round-tripped objects by JSON string so decode returns exact tables
local json_registry = {}
local mock_cjson = {
    encode = function(obj)
        local s = json_encode(obj)
        json_registry[s] = obj
        return s
    end,
    decode = function(s)
        return json_registry[s]
    end,
}

local fake_now = 1700000000
local function make_shared_dict()
    local store = {}
    local dict = {}
    function dict:get(k)
        local e = store[k]
        if not e then return nil, nil end
        if e.exp and e.exp <= fake_now then store[k] = nil; return nil, nil end
        return e.val, e.flags
    end
    function dict:set(k, v, ttl, flags)
        store[k] = { val = v, flags = flags or 0, exp = (ttl and ttl > 0) and (fake_now + ttl) or nil }
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
        store[k].val = store[k].val + delta
        return store[k].val, nil
    end
    function dict:delete(k) store[k] = nil end
    function dict:get_keys()
        local ks = {}
        for k in pairs(store) do if self:get(k) ~= nil then table.insert(ks, k) end end
        return ks
    end
    function dict:_clear() store = {} end
    return dict
end

-- Sentinel exception thrown by ngx.exit() to accurately halt script execution like OpenResty
local EXIT_TAG = {}
local function make_ngx(vars)
    local req_headers = {}
    local resp_headers = {}
    local body_chunks = {}
    local exited_code = nil

    local n
    n = {
        ERR = 4, WARN = 5, INFO = 7, ALERT = 2, CRIT = 2,
        HTTP_OK = 200, HTTP_BAD_REQUEST = 400, HTTP_INTERNAL_SERVER_ERROR = 500,
        status = 200,
        var = vars,
        header = resp_headers,
        shared = _G._TEST_SHARED,
        time = function() return fake_now end,
        log = function() end,
        decode_base64 = decode_base64,
        encode_args = function(t) return "" end,
        say = function(s) table.insert(body_chunks, tostring(s) .. "\n"); return 1 end,
        print = function(s) table.insert(body_chunks, tostring(s)); return 1 end,
        exit = function(code)
            exited_code = code
            error({ tag = EXIT_TAG, code = code })
        end,
        req = {
            set_header = function(k, v) req_headers[k] = v end,
            get_headers = function() return req_headers end,
        },
        _state = function()
            return {
                exited = exited_code,
                status = n.status,
                resp_headers = resp_headers,
                req_headers = req_headers,
                body = table.concat(body_chunks),
            }
        end,
    }
    return n
end

_G._TEST_SHARED = {
    auth_cache    = make_shared_dict(),
    auth_failures = make_shared_dict(),
    metrics       = make_shared_dict(),
    locks         = make_shared_dict(),
}
_G.ngx = make_ngx({})

-- Deterministic hash / MAC / AES mocks (key-sensitive so wrong password NEVER decrypts!)
package.loaded["cjson"] = mock_cjson
package.loaded["cjson.safe"] = mock_cjson
package.loaded["resty.string"] = {
    to_hex = function(s)
        return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
    end,
}
package.loaded["resty.sha256"] = {
    new = function()
        local buf = {}
        return {
            update = function(_, s) table.insert(buf, s) end,
            final  = function() return "SHA(" .. table.concat(buf, "|") .. ")" end,
        }
    end,
}
package.loaded["resty.openssl.mac"] = {
    new = function(key)
        local buf = { tostring(key) }
        return {
            update = function(_, s) table.insert(buf, s) end,
            final  = function() return "MAC(" .. table.concat(buf, "|") .. ")" end,
        }
    end,
}
package.loaded["resty.aes"] = {
    new = function(_, key)
        return {
            encrypt = function(_, pt) return key .. "::ENC::" .. pt end,
            decrypt = function(_, ct)
                local prefix = key .. "::ENC::"
                if ct:sub(1, #prefix) == prefix then
                    return ct:sub(#prefix + 1)
                end
                return nil
            end,
        }
    end,
}
package.loaded["resty.lock"] = {
    new = function()
        return {
            lock   = function() return 0, nil end,
            unlock = function() return true, nil end,
        }
    end,
}
package.loaded["config"] = {
    hosts = {
        webmail      = "webmail.uni-graz.at",
        exchange     = "email.uni-graz.at",
        autodiscover = "autodiscover.uni-graz.at",
    },
    oidc = {
        msx_tenant_id = "a7c865db-16d5-4de3-8c05-b1e99d713376",
        local_issuer  = "https://login.uni-graz.at/auth/realms/UniGraz",
        audience      = "https_webmail.uni-graz.at",
        direct_grant  = {
            client_id     = "https_webmail.uni-graz.at_DirectGrant",
            client_secret = "test_direct_grant_secret",
            timeout       = 5000,
        },
        owa = {
            client_id      = "https_webmail.uni-graz.at",
            client_secret  = "test_owa_secret",
            redirect_uri   = "/owa/redirect_uri",
            logout_path    = "/owa/logout",
            session_secret = "test_session_secret",
        },
    },
    mac_key_b64 = encode_base64("0123456789abcdef0123456789abcdef"),
    s4u2api = { host = "127.0.0.1", port = 7777, spn = "http", timeout = 5000 },
}

-- Controllable mocks for s4u2api, keycloak, resty.jwt, resty.openidc
local impersonate_calls = {}
package.loaded["s4u2api"] = {
    impersonate = function(upn, jwt)
        table.insert(impersonate_calls, { upn = upn, jwt = jwt })
    end,
}

local kc_calls = 0
local kc_handler = nil
package.loaded["keycloak"] = {
    authenticate_basic = function(cfg, u, p, ip, trusted)
        kc_calls = kc_calls + 1
        return kc_handler(cfg, u, p, ip, trusted)
    end,
}

local mock_jwt_loaded = { valid = true, payload = {} }
package.loaded["resty.jwt"] = {
    load_jwt = function(_, tok) return mock_jwt_loaded end,
}

local mock_bearer_verify = nil
local mock_owa_auth = nil
package.loaded["resty.openidc"] = {
    bearer_jwt_verify = function(opts) return mock_bearer_verify(opts) end,
    authenticate = function(opts, target, unauth, sess_opts) return mock_owa_auth(opts, sess_opts) end,
}

local msxauth_chunk = assert(loadfile(root .. "/openresty/lua/msxauth.lua"))
local owaauth_chunk = assert(loadfile(root .. "/openresty/lua/owaauth.lua"))

local function run_script(chunk, vars)
    impersonate_calls = {}
    local n = make_ngx(vars)
    _G.ngx = n
    -- Reload ratelimit/metrics? They capture ngx in upvalues; update _G.ngx is not enough if cached!
    -- Clear modules that capture `local ngx = ngx` so they pick up the fresh per-request ngx mock.
    package.loaded["ratelimit"] = nil
    package.loaded["metrics"] = nil
    local ok, err = pcall(chunk)
    if not ok then
        if type(err) == "table" and err.tag == EXIT_TAG then
            return n._state(), impersonate_calls
        end
        error(err)
    end
    return n._state(), impersonate_calls
end

local passed = 0
local function check(name, cond, msg)
    if not cond then
        error("[FAIL] " .. name .. (msg and (": " .. msg) or ""), 2)
    end
    passed = passed + 1
    print("[PASS] " .. name)
end

-- ── 1. Unauthenticated 401 & WWW-Authenticate challenges ─────────────────────
do
    local st = run_script(msxauth_chunk, {
        remote_addr = "203.0.113.10",
        host = "webmail.uni-graz.at",
        http_user_agent = "AppleMail/1.0",
    })
    check("unauth external -> 401 Basic only",
        st.exited == 401 and #st.resp_headers["WWW-Authenticate"] == 1
        and st.resp_headers["WWW-Authenticate"][1]:find('Basic realm="webmail.uni-graz.at"', 1, true) ~= nil)

    local st2 = run_script(msxauth_chunk, {
        remote_addr = "10.1.2.3",
        is_trustedNetwork = "1",
        host = "webmail.uni-graz.at",
        http_user_agent = "Microsoft Office/16.0",
    })
    check("unauth trusted Outlook -> 401 with Negotiate, NTLM, Basic",
        st2.exited == 401 and #st2.resp_headers["WWW-Authenticate"] == 3)
end

-- ── 2. External NTLM / Negotiate smuggling blocked (403) ─────────────────────
for _, hdr in ipairs({ "NTLM dHlwZTE=", "nTlM dHlwZTE=", "Negotiate dGlja2V0" }) do
    local st, imp = run_script(msxauth_chunk, {
        remote_addr = "203.0.113.10",
        is_trustedNetwork = "0",
        http_authorization = hdr,
        http_user_agent = "curl/8.0",
    })
    check("external " .. hdr .. " -> 403", st.exited == 403 and #imp == 0)
end

-- ── 3. Trusted vs Untrusted Basic auth_cache isolation ───────────────────────
do
    _G._TEST_SHARED.auth_cache:_clear()
    _G._TEST_SHARED.auth_failures:_clear()
    kc_calls = 0

    kc_handler = function(cfg, u, p, ip, trusted)
        if trusted then
            return { impersonate = { upn = "alice@UNI.AT", jwt = "tok_internal", aud = cfg.audience, exp = fake_now + 600 } }
        else
            return { abort = { code = 403, msg = "Insufficient authentication: use special mail password", exp = fake_now + 60 } }
        end
    end

    local basic_alice = "Basic " .. encode_base64("alice:RegularPassword!")

    -- Login from trusted network succeeds and populates auth_cache
    local st_in, imp_in = run_script(msxauth_chunk, {
        remote_addr = "10.0.0.5",
        is_trustedNetwork = "1",
        http_authorization = basic_alice,
        http_user_agent = "GenericClient",
    })
    check("trusted Basic login succeeds & calls s4u2api", st_in.exited == nil and #imp_in == 1 and imp_in[1].upn == "alice@UNI.AT")

    -- SAME credentials from untrusted external network MUST NOT hit internal cache entry!
    local st_ext, imp_ext = run_script(msxauth_chunk, {
        remote_addr = "203.0.113.55",
        is_trustedNetwork = "0",
        http_authorization = basic_alice,
        http_user_agent = "GenericClient",
    })
    check("external Basic with same regular password blocked (403, no cache bleed!)",
        st_ext.exited == 403 and #imp_ext == 0 and kc_calls == 2)

    -- Repeat trusted request hits cache (kc_calls stays 2)
    local st_hit, imp_hit = run_script(msxauth_chunk, {
        remote_addr = "10.0.0.5",
        is_trustedNetwork = "1",
        http_authorization = basic_alice,
        http_user_agent = "GenericClient",
    })
    check("repeat trusted Basic hits encrypted cache without calling Keycloak",
        st_hit.exited == nil and #imp_hit == 1 and kc_calls == 2)
end

-- ── 4. Pinned connection header stripping & rate-limit ban enforcement ───────
do
    _G._TEST_SHARED.auth_failures:_clear()

    -- Pinned with Basic header -> strips Authorization before proxy_pass
    local st_pin, imp_pin = run_script(msxauth_chunk, {
        remote_addr = "203.0.113.77",
        ntlm_pinned_exchange_upstream = "42",
        http_authorization = "Basic " .. encode_base64("alice:pw"),
    })
    check("pinned conn strips Basic Authorization header",
        st_pin.exited == nil and st_pin.req_headers["Authorization"] == "" and #imp_pin == 0)

    -- Pinned with NTLM header -> preserves Authorization (does NOT clear it)
    local st_pin_ntlm = run_script(msxauth_chunk, {
        remote_addr = "203.0.113.77",
        ntlm_pinned_exchange_upstream = "42",
        http_authorization = "NTLM dHlwZTM=",
    })
    check("pinned conn preserves NTLM Authorization header",
        st_pin_ntlm.exited == nil and st_pin_ntlm.req_headers["Authorization"] == nil)

    -- Trigger 15 fresh 401s (distinct bad passwords so cache misses) -> 15th becomes 429
    kc_handler = function()
        return { abort = { code = 401, msg = "Unauthorized: Incorrect username or password.", exp = fake_now + 60 } }
    end
    local attacker_ip = "198.51.100.99"
    for i = 1, 14 do
        local st_f = run_script(msxauth_chunk, {
            remote_addr = attacker_ip,
            http_authorization = "Basic " .. encode_base64("alice:bad" .. i),
        })
        assert(st_f.exited == 401, "expected 401 on attempt " .. i)
    end
    local st_15 = run_script(msxauth_chunk, {
        remote_addr = attacker_ip,
        http_authorization = "Basic " .. encode_base64("alice:bad15"),
    })
    check("15th Basic auth failure triggers 429 with Retry-After",
        st_15.exited == 429 and st_15.resp_headers["Retry-After"] ~= nil)

    -- Even with ntlm_pinned_exchange_upstream set, banned IP MUST get 429!
    local st_banned_pin = run_script(msxauth_chunk, {
        remote_addr = attacker_ip,
        ntlm_pinned_exchange_upstream = "10",
        http_authorization = "Basic " .. encode_base64("alice:good"),
    })
    check("banned IP blocked with 429 even on pinned socket", st_banned_pin.exited == 429)
end

-- ── 5. Bearer JWT routing (Entra ID vs Keycloak vs Unknown/nil issuer) ───────
do
    -- Unknown/nil issuer -> 401 (no nil concatenation crash!)
    mock_jwt_loaded = { valid = true, payload = {} }
    local st_nil = run_script(msxauth_chunk, {
        remote_addr = "203.0.113.10",
        http_authorization = "Bearer fake.jwt.nil",
    })
    check("Bearer with nil iss returns 401 without crashing", st_nil.exited == 401)

    -- Microsoft Entra ID -> verified & passed through WITHOUT s4u2api
    mock_jwt_loaded = { valid = true, payload = { iss = "https://sts.windows.net/a7c865db-16d5-4de3-8c05-b1e99d713376/" } }
    mock_bearer_verify = function() return { sub = "msxuser" }, nil end
    local st_msx, imp_msx = run_script(msxauth_chunk, {
        remote_addr = "203.0.113.10",
        http_authorization = "Bearer msx.jwt.tok",
    })
    check("Bearer Entra ID passes through without s4u2api", st_msx.exited == nil and #imp_msx == 0)

    -- Local Keycloak JWT -> verified & calls s4u2api.impersonate
    mock_jwt_loaded = { valid = true, payload = { iss = "https://login.uni-graz.at/auth/realms/UniGraz" } }
    mock_bearer_verify = function() return { krb5_principal = "bob@UNI.AT" }, nil, "kc.jwt.tok" end
    local st_kc, imp_kc = run_script(msxauth_chunk, {
        remote_addr = "203.0.113.10",
        http_authorization = "Bearer kc.jwt.tok",
    })
    check("Bearer Keycloak calls s4u2api.impersonate",
        st_kc.exited == nil and #imp_kc == 1 and imp_kc[1].upn == "bob@UNI.AT")
end

-- ── 6. Autodiscover Thunderbird XML must call ngx.exit(200) ──────────────────
do
    local st_tb = run_script(msxauth_chunk, {
        remote_addr = "203.0.113.10",
        is_AutoDiscover = "xml",
        http_user_agent = "Mozilla/5.0 Thunderbird/128.0",
    })
    check("Autodiscover Thunderbird XML exits cleanly with 200 (no proxy_pass fallthrough)",
        st_tb.exited == 200 and st_tb.body:find("<Autodiscover", 1, true) ~= nil)
end

-- ── 7. owaauth.lua end-to-end ────────────────────────────────────────────────
do
    -- Unpinned OWA -> calls s4u2api.impersonate
    mock_owa_auth = function() return { access_token = "owa.tok" }, nil end
    mock_jwt_loaded = { valid = true, payload = { krb5_principal = "carol@UNI.AT" } }
    local st_owa1, imp_owa1 = run_script(owaauth_chunk, { ntlm_pinned_owa_upstream = "" })
    check("owaauth unpinned calls s4u2api.impersonate",
        st_owa1.exited == nil and #imp_owa1 == 1 and imp_owa1[1].upn == "carol@UNI.AT")

    -- Pinned OWA -> strips Authorization & skips s4u2api
    local st_owa2, imp_owa2 = run_script(owaauth_chunk, { ntlm_pinned_owa_upstream = "150" })
    check("owaauth pinned strips Authorization and skips s4u2api",
        st_owa2.exited == nil and st_owa2.req_headers["Authorization"] == "" and #imp_owa2 == 0)

    -- Missing krb5_principal -> 500
    mock_jwt_loaded = { valid = true, payload = {} }
    local st_owa3, imp_owa3 = run_script(owaauth_chunk, { ntlm_pinned_owa_upstream = "" })
    check("owaauth missing krb5_principal returns 500", st_owa3.exited == 500 and #imp_owa3 == 0)

    -- OIDC error -> 500
    mock_owa_auth = function() return nil, "discovery failed" end
    local st_owa4 = run_script(owaauth_chunk, { ntlm_pinned_owa_upstream = "" })
    check("owaauth OIDC error returns 500", st_owa4.exited == 500)
end

print("\nALL " .. passed .. " OPENRESTY E2E TESTS PASSED!")
