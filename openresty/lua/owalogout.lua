-- owalogout.lua
--
-- Rewrites Exchange OWA's server-supplied CloseWindowOnLogout flag from true to
-- false in OwaUserConfiguration JSON responses so that clicking "Sign out" /
-- "Abmelden" (in any UI language) navigates to /owa/logoff.owa (or
-- /owa/<mailbox>/logoff.owa for explicit logon) instead of displaying a static
-- "Please close all browser windows" modal dialog.
--
-- Paired with the OpenResty location redirecting ^/(owa|ecp)/(.*/)?logoff\.owa$
-- to /owa/logout, this completes full OIDC + pinned-upstream logout cleanly.

local string_find  = string.find
local string_gsub  = string.gsub
local string_lower = string.lower
local string_match = string.match
local string_sub   = string.sub

local M = {}

local TARGET_ACTION = "getowauserconfiguration"

-- Exchange emits compact JSON ("CloseWindowOnLogout":true, = 27 bytes).
-- A 64-byte streaming tail window guarantees matches spanning arbitrary chunk
-- boundaries (including optional JSON whitespace around ':') are caught with
-- O(1) memory overhead.
local STREAM_OVERLAP = 64
local REWRITE_PATTERN = '("CloseWindowOnLogout"%s*:%s*)true([,%s%}])'
local REWRITE_REPLACEMENT = '%1false%2'

local function value_matches_action(val)
    if type(val) == "string" then
        return string_lower(val) == TARGET_ACTION
    end
    if type(val) == "table" then
        for i = 1, #val do
            if type(val[i]) == "string" and string_lower(val[i]) == TARGET_ACTION then
                return true
            end
        end
    end
    return false
end

local function has_target_action(tbl, keys)
    if type(tbl) ~= "table" then
        return false
    end
    for k, v in pairs(tbl) do
        if type(k) == "string" then
            local kl = string_lower(k)
            for i = 1, #keys do
                if kl == keys[i] and value_matches_action(v) then
                    return true
                end
            end
        end
    end
    return false
end

local function get_header_value(headers, lower_name, title_name)
    if type(headers) ~= "table" then
        return nil
    end
    local val = headers[lower_name]
    if val == nil and title_name then
        val = headers[title_name]
    end
    if type(val) == "table" then
        val = val[1]
    end
    if type(val) == "string" then
        return val
    end
    return nil
end

local function match_owa_endpoint(uri_lower, filename_pattern)
    return string_match(uri_lower, "^/owa/" .. filename_pattern .. "$") ~= nil
        or string_match(uri_lower, "^/owa/[^/]+/" .. filename_pattern .. "$") ~= nil
end

-- Determine whether the current OWA request returns OwaUserConfiguration JSON
-- (which carries ApplicationSettings.CloseWindowOnLogout).
function M.should_rewrite_request(uri, uri_args, req_headers)
    if type(uri) ~= "string" or uri == "" then
        return false
    end
    local uri_lower = string_lower(uri)

    -- Primary OWA bootstrap payload (standard and explicit-logon mailbox paths)
    if match_owa_endpoint(uri_lower, "sessiondata%.ashx") then
        return true
    end

    -- Fallback / popout OwaUserConfiguration endpoint
    if match_owa_endpoint(uri_lower, "service%.svc") then
        if has_target_action(uri_args, { "action" }) then
            return true
        end
        if has_target_action(req_headers, { "action", "x-owa-actionname" }) then
            return true
        end
    end

    return false
end

-- Called during access_by_lua after OWA authentication succeeds.
-- Flags eligible requests and strips Accept-Encoding upstream so Exchange
-- returns uncompressed JSON that body_filter can rewrite safely.
function M.prepare_request()
    local ngx = _G.ngx
    local uri = ngx.var and ngx.var.uri
    if type(uri) ~= "string" or uri == "" then
        return false
    end

    local uri_lower = string_lower(uri)
    local is_sessiondata = match_owa_endpoint(uri_lower, "sessiondata%.ashx")
    local is_service = (not is_sessiondata) and match_owa_endpoint(uri_lower, "service%.svc")

    if not is_sessiondata and not is_service then
        return false
    end

    local rewrite = is_sessiondata
    if is_service then
        local uri_args = ngx.req and ngx.req.get_uri_args and ngx.req.get_uri_args() or nil
        local req_headers = ngx.req and ngx.req.get_headers and ngx.req.get_headers() or nil
        rewrite = M.should_rewrite_request(uri, uri_args, req_headers)
    end

    if not rewrite then
        return false
    end

    if ngx.ctx then
        ngx.ctx.owa_rewrite_logout = true
    end
    if ngx.req and ngx.req.clear_header then
        ngx.req.clear_header("Accept-Encoding")
    end
    return true
end

-- Called during header_filter_by_lua.
-- Verifies the response is uncompressed JSON/JS 200 OK and clears Content-Length
-- because changing true -> false adds 1 byte per match.
function M.header_filter()
    local ngx = _G.ngx
    local ctx = ngx.ctx
    if not ctx or not ctx.owa_rewrite_logout then
        return
    end

    if ngx.status ~= 200 then
        ctx.owa_rewrite_logout = false
        return
    end

    local enc = get_header_value(ngx.header, "content-encoding", "Content-Encoding")
    if enc and enc ~= "" and string_lower(enc) ~= "identity" then
        ctx.owa_rewrite_logout = false
        return
    end

    local ct = get_header_value(ngx.header, "content-type", "Content-Type")
    if ct then
        local ct_lower = string_lower(ct)
        if not string_find(ct_lower, "json", 1, true) and not string_find(ct_lower, "javascript", 1, true) then
            ctx.owa_rewrite_logout = false
            return
        end
    end

    ngx.header.content_length = nil
    ngx.header.etag = nil
end

-- Called during body_filter_by_lua.
-- Streams chunks with a small tail overlap so matches spanning chunk boundaries
-- are always rewritten without buffering the entire response in memory.
function M.body_filter()
    local ngx = _G.ngx
    local ctx = ngx.ctx
    if not ctx or not ctx.owa_rewrite_logout then
        return
    end

    local chunk = ngx.arg[1]
    local eof = ngx.arg[2]

    local data = (ctx.owa_logout_tail or "") .. (chunk or "")

    if eof then
        ctx.owa_logout_tail = nil
        if data ~= "" then
            ngx.arg[1] = (string_gsub(data, REWRITE_PATTERN, REWRITE_REPLACEMENT))
        else
            ngx.arg[1] = ""
        end
        ngx.arg[2] = true
        return
    end

    if data == "" then
        ngx.arg[1] = nil
        return
    end

    data = (string_gsub(data, REWRITE_PATTERN, REWRITE_REPLACEMENT))

    if #data <= STREAM_OVERLAP then
        ctx.owa_logout_tail = data
        ngx.arg[1] = nil
    else
        local cut = #data - STREAM_OVERLAP
        ngx.arg[1] = string_sub(data, 1, cut)
        ctx.owa_logout_tail = string_sub(data, cut + 1)
    end
end

return M
