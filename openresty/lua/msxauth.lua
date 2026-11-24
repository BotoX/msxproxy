-- msxauth.lua

-- Modules
local authorization = require("authorization")
local s4u2api       = require("s4u2api")
local resty_sha256  = require("resty.sha256")
local resty_aes     = require("resty.aes")
local openssl_mac   = require("resty.openssl.mac")
local resty_string  = require("resty.string")
local resty_http    = require("resty.http")
local resty_jwt     = require("resty.jwt")
local resty_openidc = require("resty.openidc")
local resty_lock    = require("resty.lock")
local cjson         = require("cjson")
local bit           = require("bit")
local ratelimit     = require("ratelimit")

-- Locals for performance
local ngx           = ngx
local tostring      = tostring
local tonumber      = tonumber
local string_sub    = string.sub
local string_lower  = string.lower
local string_format = string.format
local string_match  = string.match
local string_find   = string.find
local band, bor     = bit.band, bit.bor
local min, max      = math.min, math.max

-- Secrets
local OIDC_MSX = "https://sts.windows.net/a7c865db-16d5-4de3-8c05-b1e99d713376/"
local OIDC_LOCAL = "https://login.uni-graz.at/auth/realms/UniGraz"

local MAC_KEY = ngx.decode_base64("***")
local API_SECRET = "***"

-- Are we inside the corporate network or VPN?
local is_trustedNetwork = ((ngx.var.is_trustedNetwork or "") == "1")

-- Test users
local is_testIP = ((ngx.var.is_testIP or "") == "1")

-- Is the client talking to the AutoDiscover endpoint?
local is_AutoDiscover = ((ngx.var.is_AutoDiscover or "") ~= "")
local is_AutoDiscoverXML = ((ngx.var.is_AutoDiscover or "") == "xml")
local is_AutoDiscoverJSON = ((ngx.var.is_AutoDiscover or "") == "json")
local is_AutoDiscoverSVC = ((ngx.var.is_AutoDiscover or "") == "svc")

-- Is the client talking to the ActiveSync endpoint?
local is_ActiveSync = ((ngx.var.is_ActiveSync or "") == "1")

local is_RPC = ((ngx.var.is_RPC or "") == "1")

-- Is the client connection NTLM pinned? (already authorized on TCP level)
local is_pinned = ((ngx.var.ntlm_pinned_exchange_upstream or "") ~= "")

local bearer_local = ((ngx.var.bearer_local or "") == "1")

local AUTH_BEARER_MSX = 1
local AUTH_BEARER_LOCAL = 2
local AUTH_NTLM = 4
local AUTH_BASIC = 8

local CHALLENGES = {
    bearer_msx = 'Bearer client_id="00000002-0000-0ff1-ce00-000000000000", trusted_issuers="00000001-0000-0000-c000-000000000000@a7c865db-16d5-4de3-8c05-b1e99d713376", token_types="app_asserted_user_v1 service_asserted_app_v1", authorization_uri="https://login.windows.net/common/oauth2/authorize"',
    bearer_local = 'Bearer client_id="not_implemented", authorization_uri="https://login.uni-graz.at/common/v2.0/auth"',
    basic  = 'Basic realm="%s"',
    negotiate = 'Negotiate',
    ntlm = 'NTLM'
}

local function string_startswith(str, start)
   return string_sub(str, 1, #start) == start
end

local function abort(status, auth, msg, failed)
    ngx.status = status

    ngx.log(ngx.ERR, "abort(" .. (status or "") .. "," .. (auth or "") .. "," .. (msg or "") .. ")")

    if failed then
        local banned, retry_after = ratelimit.on_failure(ngx.var.remote_addr)
        if banned then
            local retry_str = tostring(math.ceil(retry_after))
            ngx.status = 429
            ngx.header["Retry-After"] = retry_str
            ngx.header.content_type = "text/plain"
            ngx.say("Too many failed attempts. Try again in " .. retry_str .. " seconds.")
            return ngx.exit(429)
        end
    end

    if status == 401 and auth then
        local auth_headers = {}
        if band(auth, AUTH_BEARER_MSX) ~= 0 then
            table.insert(auth_headers, CHALLENGES.bearer_msx)
        end
        if band(auth, AUTH_BEARER_LOCAL) ~= 0 then
            table.insert(auth_headers, CHALLENGES.bearer_local)
        end
        if band(auth, AUTH_NTLM) ~= 0 then
            table.insert(auth_headers, CHALLENGES.negotiate)
            table.insert(auth_headers, CHALLENGES.ntlm)
        end
        if band(auth, AUTH_BASIC) ~= 0 then
            local basic_auth = string_format(CHALLENGES.basic, ngx.var.host)
            table.insert(auth_headers, basic_auth)
        end
        ngx.header["WWW-Authenticate"] = auth_headers
    end

    if msg then
        ngx.header.content_type = "text/plain"
        ngx.say(msg)
    end

    return ngx.exit(status)
end

-- User-Agent parsing
local ua = ngx.var.http_user_agent or ""

--
if false then
    local req = {}
    req["host"] = ngx.var.host
    req["uri"] = ngx.var.uri
    req["headers"] = ngx.req.get_headers()
    req["time"] = ngx.req.start_time()
    req["method"] = ngx.req.get_method()
    req["get_args"] = ngx.req.get_uri_args()
    ngx.req.read_body()

    ngx.log(ngx.CRIT, cjson.encode(req));
    ngx.log(ngx.CRIT, ngx.req.get_body_data(2048));
end
--

-- Skype for Business
local ua_Skype = string_find(ua, "Skype for Business", 1, true) or string_startswith(ua, "Yealink")
if ua_Skype and is_trustedNetwork then
    return
end

if is_AutoDiscoverSVC and is_trustedNetwork then
    return
end

-- Microsoft Office/Outlook
local ua_Microsoft = string_startswith(ua, "Microsoft ") or string_startswith(ua, "ExchangeServicesClient") or ua == "MSRPC"
local ua_MacOutlook = string_startswith(ua, "MacOutlook")

local ModernAuth = not (is_RPC or ua_Microsoft or ua_MacOutlook or ua_Skype)
if ModernAuth then
    ngx.header["X-OAuth-Enabled"] = "True"
    ngx.var.ModernAuth = "1"
end

if is_AutoDiscoverXML then
    local ua_Thunderbird = string_find(ua, "Thunderbird", 1, true)
    if ua_Thunderbird then
        ngx.status = 200
        ngx.header.content_type = 'text/xml; charset=utf-8'
        return ngx.say([[<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">
  <Response xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
    <Account>
      <AccountType>email</AccountType>
      <Action>settings</Action>
    </Account>
  </Response>
</Autodiscover>]])
    end
end

if is_AutoDiscoverJSON then
    local raw_proto = ngx.var.arg_protocol
    ngx.header.content_type = "application/json; charset=utf-8"

    if (raw_proto or "") == "" then
        ngx.status = ngx.HTTP_BAD_REQUEST
        ngx.say([[{"ErrorCode":"MandatoryParameterMissing","ErrorMessage":"A valid value must be provided for the query parameter \u0027Protocol\u0027"}]])
        return ngx.exit(ngx.HTTP_BAD_REQUEST)
    end

    local proto_key = string_lower(raw_proto)
    local templates
    if ModernAuth or is_testIP then
        templates = {
            default = [[{"Protocol":"%s","Url":"https://webmail.uni-graz.at/api"}]],
            ews = [[{"Protocol":"%s","Url":"https://webmail.uni-graz.at/EWS/Exchange.asmx"}]],
            activesync = [[{"Protocol":"%s","Url":"https://webmail.uni-graz.at/Microsoft-Server-ActiveSync"}]],
            autodiscoverv1 = [[{"Protocol":"%s","Url":"https://autodiscover.uni-graz.at/autodiscover/autodiscover.xml"}]]
        }
    else
        templates = {
            default = [[{"Protocol":"%s","Url":"https://email.uni-graz.at/api"}]],
            ews = [[{"Protocol":"%s","Url":"https://email.uni-graz.at/EWS/Exchange.asmx"}]],
            activesync = [[{"Protocol":"%s","Url":"https://email.uni-graz.at/Microsoft-Server-ActiveSync"}]],
            autodiscoverv1 = [[{"Protocol":"%s","Url":"https://autodiscover.uni-graz.at/autodiscover/autodiscover.xml"}]]
        }
    end

    local template = templates[proto_key] or templates.default
    local response = string_format(template, raw_proto)

    ngx.say(response)
    return ngx.exit(ngx.HTTP_OK)
end

-- Check if ip address is banned (before is_pinned so banned IPs cannot reuse pinned sockets)
local banned, retry_after = ratelimit.check(ngx.var.remote_addr)
if banned then
    local retry_str = tostring(math.ceil(retry_after))
    ngx.header["Retry-After"] = retry_str
    return abort(429, nil, "Too many failed attempts. Try again in " .. retry_str .. " seconds.")
end

-- Authorization Header
local auth_method, auth_payload = authorization.split_header(ngx.var.http_authorization)

-- Skip re-auth logic if we already have an NTLM-pinned upstream for this connection.
if is_pinned then
    if auth_method ~= "ntlm" and auth_method ~= "negotiate" then
        -- Clear Authorization from client unless it's NTLM or Negotiate
        ngx.req.set_header("Authorization", "")
    end
    return
end

-- Basic Auth = Mail Password
local auth_flags = AUTH_BASIC

-- NTLM/Negotiate within trusted networks
if is_trustedNetwork and not ModernAuth then
    auth_flags = bor(auth_flags, AUTH_NTLM)
end

-- Bearer if client requests it
if auth_method == "bearer" and ModernAuth then
--  local ua_Apple = string_find(ua, "Mac OS X", 1, true) or (string_find(ua, "Mail", 1, true) == 1 and string_find(ua, "Darwin", 1, true))
    auth_flags = bor(auth_flags, AUTH_BEARER_MSX)
end

if (auth_method or "") == "" then
    return abort(401, auth_flags, "Unauthorized: No credentials")
end

if (auth_payload or "") == "" then
    return abort(401, auth_flags, "Unauthorized: empty auth payload")
end

--
-- Authorization: Bearer
--
if auth_method == "bearer" then
    local jwt_obj = resty_jwt:load_jwt(auth_payload)
    if not jwt_obj.valid then
        return abort(401, auth_flags, "Unauthorized: Invalid JWT", false)
    end
    local jwt_iss = jwt_obj.payload["iss"]

    -- Our Microsoft tenant (Entra ID) issued this token ->
    if jwt_iss == OIDC_MSX then
        local opts = {
            discovery = OIDC_MSX:gsub("/+$", "") .. "/.well-known/openid-configuration",
            token_signing_alg_values_expected = { "RS256" },
            accept_unsupported_alg = false,
            introspection_enable_negative_cache = true,
            cache_segment = "msxauth:msx"
        }
        local res, err = resty_openidc.bearer_jwt_verify(opts)

        if err then
            return abort(401, auth_flags, "Unauthorized:" .. err, false)
        end

        -- Microsoft issued JWT is valid, passthrough to exchange.
        return
    end

    -- Our on-premise OIDC IdP (Keycloak) issued this token ->
    if jwt_iss == OIDC_LOCAL then
        local opts = {
            discovery = OIDC_LOCAL:gsub("/+$", "") .. "/.well-known/openid-configuration",
            token_signing_alg_values_expected = { "RS256" },
            accept_unsupported_alg = false,
            introspection_enable_negative_cache = true,
            cache_segment = "msxauth:uni"
        }
        local res, err, access_token = resty_openidc.bearer_jwt_verify(opts)

        if err then
            return abort(401, auth_flags, "Unauthorized:" .. err, false)
        end

        local upn = res.krb5_principal
        if not upn then
            return abort(500, nil, "Internal Server Error.\nkrb5_principal not found in claims.")
        end

        s4u2api.impersonate(upn, access_token)
        return
    end

    return abort(401, auth_flags, "Unauthorized: Unknown Issuer\niss: " .. tostring(jwt_iss), false)
end


--
-- Authorization: Negotiate / NTLM
--
if auth_method == "negotiate" or auth_method == "ntlm" then
    -- Passthrough legacy auth to exchange on trusted networks
    if is_trustedNetwork then
        return
    end

    return abort(403, nil, "Legacy authentication not allowed from this network.")
end


--
-- Authorization: Basic
--
local username, password, err = authorization.basic(auth_payload)
if not username or not password then
    return abort(401, auth_flags, "Unauthorized: " .. err)
end

-- Keep this function up2date with msxauthapi API behaviour / functionality
local function enc_and_cache_keys(trustedNetwork, username, password, activeSync, deviceId, deviceType)
    local mac, err = openssl_mac.new(MAC_KEY, "HMAC", nil, "sha256")
    if not mac then
        return nil, nil, err
    end

    mac:update(trustedNetwork and "T" or "t")
    mac:update(activeSync and "A" or "a")
    mac:update("\0")
    mac:update(username)
    mac:update("\0")
    mac:update(password)
    mac:update("\0")

    if activeSync then
        mac:update(deviceId)
        mac:update("\0")
        mac:update(deviceType)
        mac:update("\0")
    end

    local raw_mac, err = mac:final()
    if not raw_mac then
        return nil, nil, err
    end

    local enc_key = resty_sha256:new()
    enc_key:update(raw_mac)
    enc_key:update("encryption_key")
    enc_key = enc_key:final()

    local cache_key = resty_sha256:new()
    cache_key:update(raw_mac)
    cache_key:update("cache_key")
    cache_key = cache_key:final()
    cache_key = resty_string.to_hex(cache_key)

    return enc_key, cache_key, nil
end

local deviceId = nil
local deviceType = nil
if is_ActiveSync then
    deviceId = ngx.var.arg_deviceid or ""
    deviceType = ngx.var.arg_devicetype or ""
end

local cache = ngx.shared.auth_cache
local enc_key, cache_key, err = enc_and_cache_keys(
    is_trustedNetwork,
    username,
    password,
    false, --is_ActiveSync,
    deviceId,
    deviceType
)

if not enc_key or not cache_key or err then
    ngx.log(ngx.ERR, "Failed to generate security keys: ", err)
    return abort(500, nil, "Internal Server Error.")
end

-- Create AES object using enc_key
-- Note: resty.aes automatically handles salt generation and prepending
local aes_obj, err = resty_aes:new(enc_key)
if not aes_obj then
    ngx.log(ngx.ERR, "Failed to init AES for decryption: ", err)
    return abort(500, nil, "Internal Server Error.")
end

local http_res
local api_json
local api_obj
local cached = false
local api_lock
local api_locked

-- Helper function to attempt cache lookup and decryption
local function get_from_cache(key, aes)
    local encrypted_json = cache:get(key)
    if encrypted_json then
        local json_str = aes:decrypt(encrypted_json)
        if json_str then
            local obj = cjson.decode(json_str)
            return json_str, obj
        else
            ngx.log(ngx.ERR, "Failed to decrypt data. Key mismatch or corrupted cache.")
        end
    end
    return nil, nil
end

local function release_lock()
    if api_lock and api_locked then
        api_lock:unlock()
        api_locked = nil
    end
end

local function unlock_and_abort(status, flags, msg)
    release_lock()
    return abort(status, flags, msg)
end

-- 1. Cached: Decrypt json from cache and use it as api response
api_json, api_obj = get_from_cache(cache_key, aes_obj)
if api_obj then
    cached = true
end

-- 2. Not cached: lock for cache misses
if not cached then
    api_lock, err = resty_lock:new("locks", {
        timeout = 5,  -- Wait up to 5s for lock
        exptime = 10  -- Lock expires automatically after 10s if process dies
    })

    if api_lock then
        api_locked, err = api_lock:lock("msxauth:" .. cache_key)
    end

    if api_locked then
        -- 3. Double-Check Cache (Another request might have populated it while we waited)
        api_json, api_obj = get_from_cache(cache_key, aes_obj)
        if api_obj then
            cached = true
            release_lock()
        end
    else
        ngx.log(ngx.WARN, "Failed to acquire lock for ", cache_key, ": ", err)
    end
end

-- 4. Really not cached: forward full request to Python fake/auth server ONCE
if not cached then
    local headers = ngx.req.get_headers()
    local body = nil
    if is_ActiveSync and false then
        ngx.req.read_body()
        body = ngx.req.get_body_data(1048576)
    end

    -- API Authorization
    headers["X-API-Secret"] = API_SECRET
    headers["X-Forwarded-For"] = ngx.var.remote_addr
    headers["X-Trusted-Network"] = is_trustedNetwork

    -- Strip headers
    headers["content-length"] = nil
    headers["content-type"] = nil
    headers["transfer-encoding"] = nil

    local httpc = resty_http.new()
    httpc:set_timeout(5000)

    -- Forward full/original request to Python Auth API
    http_res, err = httpc:request_uri("http://127.0.0.1:8000" .. ngx.var.uri, {
        method = ngx.req.get_method(),
        --body = body,
        query = ngx.var.args,
        headers = headers
    })

    if not http_res then
        err = "Auth API error: " .. (err or "unknown failure")
        ngx.log(ngx.ERR, err)
        return unlock_and_abort(500, nil, "Internal Server Error.\n" .. err)
    end

    local api_res = http_res.headers["X-API-Result"]
    if not api_res or api_res == "" then
        err = "Auth API error: Empty result"
        ngx.log(ngx.ERR, err)
        return unlock_and_abort(500, nil, "Internal Server Error.\n" .. err)
    end

    api_json = ngx.decode_base64(api_res)
    if not api_json then
        err = "Auth API error: Invalid result (base64 decode failure)"
        ngx.log(ngx.ERR, err)
        return unlock_and_abort(500, nil, "Internal Server Error.\n" .. err)
    end

    api_obj, err = cjson.decode(api_json)
    if err then
        err = "Auth API JSON error: " .. err
        ngx.log(ngx.ERR, err)
        return unlock_and_abort(500, nil, "Internal Server Error.\n" .. err)
    end

    if api_obj["error"] then
        err = "Auth API returned error: " .. api_obj["error"]
        ngx.log(ngx.ERR, err)
        return unlock_and_abort(500, nil, "Internal Server Error.\n" .. err)
    end
end

local impersonate = api_obj["impersonate"]
if impersonate then
    -- Cache impersonate result
    if not cached then
        local ttl = impersonate["exp"] - ngx.time()
        if ttl > 0 then
            ttl = min(ttl, 3600)
            local encrypted_json = aes_obj:encrypt(api_json)
            local ok, err = cache:set(cache_key, encrypted_json, ttl)
            if not ok then
                ngx.log(ngx.ERR, "Failed to store encrypted data in cache: ", err)
            end
        end

        release_lock()
        ratelimit.on_success(ngx.var.remote_addr)
    end

    s4u2api.impersonate(impersonate["upn"], impersonate["jwt"])
    return

elseif api_obj["abort"] then
    local abort_ = api_obj["abort"]
    -- Cache abort result
    if not cached then
        local ttl = abort_["exp"] - ngx.time()
        if ttl > 0 then
            ttl = min(ttl, 3600)
            local encrypted_json = aes_obj:encrypt(api_json)
            local ok, err = cache:set(cache_key, encrypted_json, ttl)
            if not ok then
                ngx.log(ngx.ERR, "Failed to store encrypted data in cache: ", err)
            end
        end

        release_lock()
    end

    return abort(abort_["code"], auth_flags, abort_["msg"], (not cached and abort_["code"] == 401))

elseif api_obj["return"] then
    release_lock()

    -- Return response from Auth Proxy
    -- Use case: ActiveSync fake mail server for MFA device verification
    ngx.status = http_res.status
    for k, v in pairs(http_res.headers) do
        local lk = string_lower(k)
        if lk ~= "transfer-encoding" and lk ~= "connection" and k ~= "X-API-Result" then
            ngx.header[k] = v
        end
    end
    ngx.print(http_res.body)
    return ngx.exit(http_res.status)
end

ngx.log(ngx.ERR, "Auth API unhandled response: ", api_json)
return unlock_and_abort(500, nil, "Internal Server Error.\nUnhandled Auth State")
