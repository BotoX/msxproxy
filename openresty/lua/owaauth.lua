local is_pinned = ((ngx.var.ntlm_pinned_owa_upstream or "") ~= "")
local resty_openidc = require("resty.openidc")
local resty_jwt = require("resty.jwt")
local s4u2api = require("s4u2api")
local opts = {
    redirect_uri = "/owa/redirect_uri",
    logout_path = "/owa/logout",
    discovery = "https://login.uni-graz.at/auth/realms/UniGraz/.well-known/openid-configuration",
    client_id = "https_webmail.uni-graz.at",
    client_secret = "***",
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
    secret = "***",
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
    ngx.status = 500
    ngx.header.content_type = 'text/plain'
    ngx.say(err)
    return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
end

local jwt_obj = resty_jwt:load_jwt(res.access_token)
local claims = jwt_obj.payload
local upn = claims.krb5_principal

if not upn then
    ngx.status = 500
    ngx.header.content_type = 'text/plain'
    ngx.say("Internal Server Error.\nkrb5_principal not found in claims.")
    return ngx.exit(500)
end

if is_pinned then
    ngx.req.set_header("Authorization", "")
else
    s4u2api.impersonate(upn, res.access_token)
end
