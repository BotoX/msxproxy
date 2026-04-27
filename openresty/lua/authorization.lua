local _M = {}

local ngx          = ngx
local ngx_decode64 = ngx.decode_base64
local string_lower = string.lower
local string_find  = string.find
local string_sub   = string.sub

--- Parse Authorization header and return method, payload.
-- @return method (lowercase string or nil), payload (string or nil).
function _M.split_header(auth)
    if not auth or auth == "" then
        return nil, nil
    end

    local space_pos = string_find(auth, " ", 1, true)
    if space_pos and #auth > space_pos then
        return string_lower(string.sub(auth, 1, space_pos - 1)), string.sub(auth, space_pos + 1)
    elseif space_pos then
        return string_lower(string.sub(auth, 1, space_pos - 1)), nil
    end

    return string_lower(auth), nil
end

--- Parse Basic Authorization payload and return username, password, and error.
-- @return username (string or nil), password (string or nil), err (string or nil)
function _M.basic(payload)
    if not payload or payload == "" then
        return nil, nil, "empty Basic auth payload"
    end

    -- Decode base64(user:pass)
    local decoded = ngx_decode64(payload)
    if not decoded then
        return nil, nil, "invalid base64 in Basic auth"
    end

    -- Split "user:pass" (user can contain ':', so split on the *first* colon)
    local colon_pos = string_find(decoded, ":", 1, true)  -- plain find
    if not colon_pos then
        -- No colon → invalid Basic auth payload
        return nil, nil, "malformed Basic credentials (no colon)"
    end

    local username = string_sub(decoded, 1, colon_pos - 1)
    local password = string_sub(decoded, colon_pos + 1)

    return username, password, nil
end

return _M
