local is_pinned = ((ngx.var.ntlm_pinned_owa_upstream or "") ~= "")
local resty_openidc = require("resty.openidc")
local resty_jwt = require("resty.jwt")
local s4u2api = require("s4u2api")
local config = require("config")
local metrics = require("metrics")

local owa_cfg = config.oidc.owa
local issuer  = config.oidc.local_issuer:gsub("/+$", "")

local opts = {
    redirect_uri = owa_cfg.redirect_uri or "/owa/redirect_uri",
    logout_path = owa_cfg.logout_path or "/owa/logout",
    discovery = issuer .. "/.well-known/openid-configuration",
    client_id = owa_cfg.client_id,
    client_secret = owa_cfg.client_secret,
    scope = "openid ActiveDirectoryPrincipal",
    use_pkce = true,
    accept_unsupported_alg = false,
    introspection_enable_negative_cache = true,
    cache_segment = "webmail:owa",
    session_contents = {
        access_token = true
    }
}
local session_opts = {
    secret = owa_cfg.session_secret,
    -- With storage key hashed it is impossible to decrypt data on server side without having a cookie too
    hash_storage_key = true,
    cookie_http_only = true,
    cookie_secure = true,
    cookie_same_site = "Lax",
    remember = false,
    storage = "shm",
    prefix = "owa",
    zone = "sessions"
}
local res, err, _, session = resty_openidc.authenticate(opts, nil, nil, session_opts)

if err then
    metrics.inc("msxproxy_auth_total", { method = "owa", result = "500" })
    ngx.status = 500
    ngx.header.content_type = 'text/plain'
    ngx.say(err)
    return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
end

local jwt_obj = resty_jwt:load_jwt(res.access_token)
local claims = jwt_obj.payload
local upn = claims.krb5_principal

if not upn then
    metrics.inc("msxproxy_auth_total", { method = "owa", result = "500" })
    ngx.status = 500
    ngx.header.content_type = 'text/plain'
    ngx.say("Internal Server Error.\nkrb5_principal not found in claims.")
    return ngx.exit(500)
end

if is_pinned then
    metrics.inc("msxproxy_auth_total", { method = "owa", result = "pinned" })
    ngx.req.set_header("Authorization", "")
else
    s4u2api.impersonate(upn, res.access_token)
    metrics.inc("msxproxy_auth_total", { method = "owa", result = "ok" })
end
