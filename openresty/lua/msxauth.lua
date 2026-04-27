-- msxauth.lua

-- Modules
local authorization = require("authorization")
local s4u2api       = require("s4u2api")
local resty_sha256  = require("resty.sha256")
local resty_aes     = require("resty.aes")
local openssl_mac   = require("resty.openssl.mac")
local resty_string  = require("resty.string")
local resty_http    = require("resty.http")
local resty_openidc = require("resty.openidc")
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
local MAC_KEY = ngx.decode_base64("***")
local API_SECRET = "***"

-- Are we inside the corporate network or VPN?
local is_trustedNetwork = (ngx.var.is_trustedNetwork == "1")

-- Test users
local is_testIP = (ngx.var.is_testIP == "1")

-- Is the client talking to the AutoDiscover endpoint?
local is_AutoDiscoverXML = (ngx.var.is_AutoDiscover == "xml")
local is_AutoDiscoverJSON = (ngx.var.is_AutoDiscover == "json")
local modify_AutoDiscover = ((ngx.var.is_AutoDiscover or "") ~= "")

-- Is the client talking to the ActiveSync endpoint?
local is_ActiveSync = (ngx.var.is_ActiveSync == "1")

-- Is the client connection NTLM pinned? (already authorized on TCP level)
local is_pinned = ((ngx.var.ntlm_pinned or "") ~= "")

local AUTH_BEARER_MSX = 1
local AUTH_BEARER_APPLE = 2
local AUTH_NTLM = 4
local AUTH_BASIC = 8

local CHALLENGES = {
    bearer_msx = 'Bearer client_id="00000002-0000-0ff1-ce00-000000000000", trusted_issuers="00000001-0000-0000-c000-000000000000@a7c865db-16d5-4de3-8c05-b1e99d713376", token_types="app_asserted_user_v1 service_asserted_app_v1", authorization_uri="https://login.microsoftonline.com/common/oauth2/authorize"',
    bearer_apple = 'Bearer client_id="f8d98a96-0999-43f5-8af3-69971c7bb423", authorization_uri="https://login.uni-graz.at/common/v2.0/auth"',
    basic  = 'Basic realm="%s"',
    negotiate = 'Negotiate',
    ntlm = 'NTLM'
}

local function abort(status, auth, msg, failed)
    ngx.status = status
    if status == 401 then
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

        if auth then
            local auth_headers = {}
            if band(auth, AUTH_BEARER_MSX) ~= 0 then
                table.insert(auth_headers, CHALLENGES.bearer_msx)
            end
            if band(auth, AUTH_BEARER_APPLE) ~= 0 then
                table.insert(auth_headers, CHALLENGES.bearer_apple)
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
    end
    if msg then
        ngx.header.content_type = "text/plain"
        ngx.say(msg)
    end
    return ngx.exit(status)
end

-- User-Agent parsing
local ua = ngx.var.http_user_agent or ""
local ua_Skype = string_find(ua, "Skype for Business", 1, true)

--
if false then
    local req = {}
    req["host"] = ngx.var.host
    req["uri"] = ngx.var.uri
    req["headers"] = ngx.req.get_headers()
    req["time"] = ngx.req.start_time()
    req["method"] = ngx.req.get_method()
    req["get_args"] = ngx.req.get_uri_args()
    req["body"] = ngx.req.get_body_data()

    ngx.log(ngx.CRIT, cjson.encode(req));
end
--

if ua_Skype and is_trustedNetwork then
    return
end

-- TODO: Remove before prod
-- Autodiscover passthrough for uni network not in testips
if is_AutoDiscoverXML or is_AutoDiscoverJSON then
    if is_trustedNetwork and not is_testIP then
        return
    end
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
    if ngx.var.modify_AutoDiscover == "json" then
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

if (auth_method or "") == "" then
    return abort(401, bor(AUTH_NTLM, AUTH_BASIC), "Unauthorized: No credentials")
end

-- Basic Auth = Mail Password
local auth_flags = AUTH_BASIC

-- NTLM/Negotiate within trusted networks
if is_trustedNetwork then
    auth_flags = bor(auth_flags, AUTH_NTLM)
end

-- Bearer if client requests it
if auth_method == "bearer" then
    auth_flags = bor(auth_flags, AUTH_BEARER_MSX)
--    local ua_Apple = string_find(ua, "Mac OS X", 1, true) or (string_find(ua, "Mail", 1, true) == 1 and string_find(ua, "Darwin", 1, true))
--    if ua_Apple then
--        auth_flags = bor(auth_flags, AUTH_BEARER_APPLE)
--    else
--        auth_flags = bor(auth_flags, AUTH_BEARER_MSX)
--    end
end

if (auth_payload or "") == "" then
    return abort(401, auth_flags, "Unauthorized: empty auth payload")
end

-- Check if ip address is banned
local banned, retry_after = ratelimit.check(ngx.var.remote_addr)
if banned then
    local retry_str = tostring(math.ceil(retry_after))
    ngx.header["Retry-After"] = retry_str
    return abort(429, nil, "Too many failed attempts. Try again in " .. retry_str .. " seconds.")
end

--
-- Authorization: Bearer
--
if auth_method == "bearer" then
    -- Did Microsoft issue this token?
    local opts = {
        discovery = "https://sts.windows.net/a7c865db-16d5-4de3-8c05-b1e99d713376/.well-known/openid-configuration",
        token_signing_alg_values_expected = { "RS256" },
        accept_unsupported_alg = false,
        introspection_enable_negative_cache = true,
        cache_segment = "msxauth:msx"
    }
    local msx_res, msx_jwt_err = resty_openidc.bearer_jwt_verify(opts)

    -- Microsoft issued JWT is valid, passthrough to exchange.
    if msx_res and not msx_jwt_err then
        return
    end

    -- Did we issue this token?
    local opts = {
        discovery = "https://login.uni-graz.at/auth/realms/UniGraz/.well-known/openid-configuration",
        token_signing_alg_values_expected = { "RS256" },
        accept_unsupported_alg = false,
        introspection_enable_negative_cache = true,
        cache_segment = "msxauth:uni"
    }
    local res, jwt_err, access_token = resty_openidc.bearer_jwt_verify(opts)

    if jwt_err or not res then
        local err_str = ""
        if msx_jwt_err then
            err_str = err_str .. "\nMSX JWT Err: " .. msx_jwt_err
        end
        if jwt_err then
            err_str = err_str .. "\nLocal JWT Err: " .. jwt_err
        end

        if err_str ~= "" then
            return abort(401, auth_flags, "Unauthorized:" .. err_str, true)
        else
            return abort(401, auth_flags, "Unauthorized: Invalid JWT", true)
        end
    end

    local upn = res.krb5_principal
    if not upn then
        return abort(500, nil, "Internal Server Error.\nkrb5_principal not found in claims.")
    end

    s4u2api.impersonate(upn, access_token, "https_webmail.uni-graz.at")
    return
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
local function enc_and_cache_keys(is_trustedNetwork, username, password, is_ActiveSync, deviceId, deviceType)
    local mac, err = openssl_mac.new(MAC_KEY, "HMAC", nil, "sha256")
    if not mac then
        return nil, nil, err
    end

    mac:update(is_trustedNetwork and "T" or "t")
    mac:update(is_ActiveSync and "A" or "a")
    mac:update("\0")
    mac:update(username)
    mac:update("\0")
    mac:update(password)
    mac:update("\0")

    if is_ActiveSync then
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
    is_ActiveSync,
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

-- Cached: Decrypt json from cache and use it as api response
local encrypted_json = cache:get(cache_key)
if encrypted_json then
    api_json = aes_obj:decrypt(encrypted_json)

    if not api_json then
        ngx.log(ngx.ERR, "Failed to decrypt data. Key mismatch or corrupted cache.")
    else
        api_obj = cjson.decode(api_json)
        -- Cached result: don't insert into cache again
        cached = true
    end
end

-- Not cached: forward full request to Python fake/auth server
if not cached then
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local headers = ngx.req.get_headers()

    -- API Authorization
    headers["X-API-Secret"] = API_SECRET
    headers["X-Forwarded-For"] = ngx.var.remote_addr
    headers["X-Trusted-Network"] = is_trustedNetwork

    local httpc = resty_http.new()
    httpc:set_timeout(1000)

    -- Forward full/original request to Python Auth API
    http_res, err = httpc:request_uri("http://127.0.0.1:8000" .. ngx.var.uri, {
        method = ngx.req.get_method(),
        body = body,
        query = ngx.var.args,
        headers = headers
    })

    if not http_res then
        err = "Auth API error: " .. err
        ngx.log(ngx.ERR, err)
        return abort(500, nil, "Internal Server Error.\n" .. err)
    end

    local api_res = http_res.headers["X-API-Result"]
    if not api_res or api_res == "" then
        err = "Auth API error: Empty result"
        ngx.log(ngx.ERR, err)
        return abort(500, nil, "Internal Server Error.\n" .. err)
    end

    api_json = ngx.decode_base64(api_res)
    if not api_json then
        err = "Auth API error: Invalid result (base64 decode failure)"
        ngx.log(ngx.ERR, err)
        return abort(500, nil, "Internal Server Error.\n" .. err)
    end

    api_obj, err = cjson.decode(api_json)
    if err then
        err = "Auth API JSON error: " .. err
        ngx.log(ngx.ERR, err)
        return abort(500, nil, "Internal Server Error.\n" .. err)
    end

    if api_obj["error"] then
        err = "Auth API returned error: " .. api_obj["error"]
        ngx.log(ngx.ERR, err)
        return abort(500, nil, "Internal Server Error.\n" .. err)
    end
end

local impersonate = api_obj["impersonate"]
if impersonate then
    -- Cache impersonate result
    if not cached then
        local ttl = impersonate["exp"] - ngx.time()
        ttl = max(min(ttl, 3600), 0)
        local encrypted_json = aes_obj:encrypt(api_json)
        local ok, err = cache:set(cache_key, encrypted_json, ttl)
        if not ok then
            ngx.log(ngx.ERR, "Failed to store encrypted data in cache: ", err)
        end
    end

    s4u2api.impersonate(impersonate["upn"], impersonate["jwt"])
    return

elseif api_obj["abort"] then
    local abort_ = api_obj["abort"]
    -- Cache abort result
    if not cached then
        local ttl = abort_["exp"] - ngx.time()
        ttl = max(min(ttl, 3600), 0)
        local encrypted_json = aes_obj:encrypt(api_json)
        local ok, err = cache:set(cache_key, encrypted_json, ttl)
        if not ok then
            ngx.log(ngx.ERR, "Failed to store encrypted data in cache: ", err)
        end
    end

    return abort(abort_["code"], auth_flags, abort_["msg"], not cached)

elseif api_obj["return"] then
    -- Return response from Auth Proxy
    -- Use case: ActiveSync fake mail server for MFA device verification
    ngx.status = http_res.status
    for k, v in pairs(http_res.headers) do
        local lk = string_lower(k)
        if lk ~= "transfer-encoding" and lk ~= "connection" and k ~= "X-API-Result" then
            ngx.header[k] = v
        end
    end
    return ngx.print(http_res.body)
end

ngx.log(ngx.ERR, "Auth API unhandled response: ", api_json)
return abort(500, nil, "Internal Server Error.\nUnhandled Auth State")
