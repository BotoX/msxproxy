-- keycloak.lua
--
-- Direct Grant (ROPC) authentication against Keycloak with CrowdSec detection,
-- OIDC JWT verification (via lua-resty-openidc), and ACR policy enforcement.

local _M = {}

local resty_http    = require("resty.http")
local resty_openidc = require("resty.openidc")
local cjson         = require("cjson.safe")
local metrics       = require("metrics")

local ngx           = ngx
local tostring      = tostring
local type          = type
local string_find   = string.find
local string_lower  = string.lower
local string_sub    = string.sub

local function aud_matches(aud, expected)
    if type(aud) == "string" then
        return aud == expected
    elseif type(aud) == "table" then
        for i = 1, #aud do
            if aud[i] == expected then
                return true
            end
        end
    end
    return false
end

local function make_abort(code, msg, ttl)
    return {
        abort = {
            code = code,
            msg  = msg,
            exp  = ngx.time() + ttl,
        }
    }
end

-- Perform a Keycloak ROPC (password) grant, verify the returned access token,
-- and enforce the mail-password / deviceId ACR policy for untrusted networks.
--
-- cfg:
--   discovery     string       Keycloak .well-known/openid-configuration URL
--   audience      string       Expected JWT aud claim
--   client_id     string       Direct Grant OIDC client_id
--   client_secret string|nil   Optional OIDC client_secret
--   cache_segment string|nil   Shared-dict cache segment for resty.openidc
--   timeout       number|nil   HTTP timeout in ms (default 5000)
--
-- opts (optional):
--   activesync_enroll boolean     Allow deviceId ACR and return { enroll = ... } on unenrolled devices
--   device_id         string|nil  ActiveSync DeviceId query parameter
--   device_type       string|nil  ActiveSync DeviceType query parameter
--
-- Returns:
--   result table: { impersonate = { upn, jwt, aud, exp } }
--              or { enroll      = { subject, email, name, exp } }
--              or { abort       = { code, msg, exp } }
function _M.authenticate_basic(cfg, username, password, user_ip, is_trusted_network, opts)
    opts = opts or {}
    local activesync_enroll = (opts.activesync_enroll == true)

    local oidc_opts = {
        discovery = cfg.discovery,
        token_signing_alg_values_expected = { "RS256" },
        accept_unsupported_alg = false,
        cache_segment = cfg.cache_segment or "keycloak",
    }

    local discovery, disc_err = resty_openidc.get_discovery_doc(oidc_opts)
    if not discovery or disc_err or not discovery.token_endpoint then
        ngx.log(ngx.ERR, "Keycloak OIDC discovery failed: ", tostring(disc_err))
        return make_abort(500, "Authentication service temporarily unavailable", 15)
    end

    local form = {
        grant_type = "password",
        client_id  = cfg.client_id,
        username   = username,
        password   = password,
        scope      = activesync_enroll and "openid profile email" or "openid",
    }
    if cfg.client_secret and cfg.client_secret ~= "" then
        form.client_secret = cfg.client_secret
    end
    if activesync_enroll then
        if opts.device_id and opts.device_id ~= "" then
            form.DeviceId = opts.device_id
        end
        if opts.device_type and opts.device_type ~= "" then
            form.DeviceType = opts.device_type
        end
    end

    local httpc = resty_http.new()
    httpc:set_timeout(cfg.timeout or 5000)

    local res, req_err = httpc:request_uri(discovery.token_endpoint, {
        method  = "POST",
        body    = ngx.encode_args(form),
        headers = {
            ["Content-Type"]    = "application/x-www-form-urlencoded",
            ["X-Forwarded-For"] = user_ip,
        },
        ssl_verify = true,
    })

    if not res then
        ngx.log(ngx.ERR, "Keycloak connection failed for user '", username, "': ", tostring(req_err))
        return make_abort(500, "Authentication service temporarily unavailable", 15)
    end

    local raw_ct = res.headers and res.headers["Content-Type"] or ""
    if type(raw_ct) == "table" then
        raw_ct = raw_ct[1] or ""
    end
    local content_type = string_lower(raw_ct)
    local res_body = res.body or ""

    if res.status < 200 or res.status >= 300 then
        -- Check if CrowdSec served an HTML Ban page
        if string_find(content_type, "text/html", 1, true)
            and string_find(res_body, "<title>CrowdSec Ban</title>", 1, true)
        then
            ngx.log(ngx.WARN, "CrowdSec BAN triggered for client IP '", user_ip, "' (user '", username, "')")
            metrics.inc("msxproxy_crowdsec_blocks_total", { type = "ban" })
            return make_abort(403, "Authentication blocked by security policy (CrowdSec BAN)", 60)
        end

        local err_data = cjson.decode(res_body)
        local error_code, error_desc
        if type(err_data) == "table" then
            error_code = err_data.error or "unknown_error"
            error_desc = err_data.error_description or res_body
        else
            error_code = "raw_error"
            error_desc = string_sub(res_body, 1, 200)
        end

        -- OAuth 2.0 RFC 6749: Keycloak returns 400 with "invalid_grant" on wrong credentials
        if error_code == "invalid_grant" or res.status == 401 then
            ngx.log(ngx.INFO, "Keycloak invalid credentials for user '", username, "': ", error_code, " - ", error_desc)
            return make_abort(401, "Unauthorized: Incorrect username or password.", 60)
        elseif res.status == 400 then
            ngx.log(ngx.WARN, "Keycloak 400 for user '", username, "': ", error_code, " - ", error_desc)
            return make_abort(400, "Invalid authentication request: " .. tostring(error_desc), 15)
        elseif res.status == 403 then
            ngx.log(ngx.WARN, "Keycloak 403 for user '", username, "': ", error_code, " - ", error_desc)
            return make_abort(403, "User access is disabled in Keycloak", 60)
        else
            ngx.log(ngx.ERR, "Keycloak returned status ", res.status, " for user '", username, "': ", error_code, " - ", error_desc)
            return make_abort(500, "Provider error: " .. tostring(res.status), 15)
        end
    end

    -- Check if CrowdSec served an HTML CAPTCHA / Challenge page
    if string_find(content_type, "text/html", 1, true)
        and string_find(res_body, "<title>CrowdSec Captcha</title>", 1, true)
    then
        ngx.log(ngx.WARN, "CrowdSec CAPTCHA triggered for client IP '", user_ip, "' (user '", username, "')")
        metrics.inc("msxproxy_crowdsec_blocks_total", { type = "captcha" })
        return make_abort(403, "Authentication blocked by security policy (CrowdSec CAPTCHA)", 60)
    end

    local token_data = cjson.decode(res_body)
    if type(token_data) ~= "table" then
        ngx.log(ngx.ERR, "Keycloak returned non-JSON response (status ", res.status, "): ", string_sub(res_body, 1, 500))
        return make_abort(500, "Keycloak returned an invalid or empty response", 15)
    end

    local access_token = token_data.access_token
    if not access_token or access_token == "" then
        ngx.log(ngx.WARN, "Keycloak returned no access_token for user '", username, "'")
        return make_abort(401, "Unauthorized: Incorrect username or password.", 60)
    end

    -- Verify JWT signature, algorithm, exp/nbf via Keycloak JWKS
    local claims, verify_err = resty_openidc.jwt_verify(access_token, oidc_opts)
    if not claims or verify_err then
        ngx.log(ngx.WARN, "Keycloak token verification failed for '", username, "': ", tostring(verify_err))
        return make_abort(401, "Unauthorized: Incorrect username or password.", 60)
    end

    if discovery.issuer and claims.iss ~= discovery.issuer then
        ngx.log(ngx.WARN, "Keycloak token issuer mismatch for '", username, "': ", tostring(claims.iss))
        return make_abort(401, "Unauthorized: Incorrect username or password.", 60)
    end

    if cfg.audience and not aud_matches(claims.aud, cfg.audience) then
        ngx.log(ngx.WARN, "Keycloak token audience mismatch for '", username, "'")
        return make_abort(401, "Unauthorized: Incorrect username or password.", 60)
    end

    local upn = claims.krb5_principal
    if not upn or upn == "" then
        return make_abort(403, "missing attribute: krb5_principal", 15)
    end

    local acr = claims.acr or ""
    if is_trusted_network or acr == "mail-password" or (activesync_enroll and acr == "deviceId") then
        return {
            impersonate = {
                upn = upn,
                jwt = access_token,
                aud = claims.aud,
                exp = claims.exp,
            }
        }
    end

    if activesync_enroll then
        return {
            enroll = {
                subject = claims.preferred_username or username,
                email   = claims.email or "",
                name    = claims.name or claims.preferred_username or username,
                exp     = claims.exp,
            }
        }
    end

    return make_abort(403, "Insufficient authentication: use special mail password", 60)
end

return _M
