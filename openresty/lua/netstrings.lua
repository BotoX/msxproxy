local _M = {}

local function read_netstring(sock)
    -- sock:receiveuntil creates an iterator that reads up to the given delimiter
    local reader, err = sock:receiveuntil(":")
    if not reader then
        return nil, err
    end

    local len_str, err = reader()
    if not len_str then
        -- Clean EOF (e.g., err == "closed") if it happens at the start
        return nil, err
    end

    local len = tonumber(len_str)
    if not len then
        return nil, "Missing or corrupt netstring header"
    end

    if len > 65535 then
        return nil, "Length exceeds limit"
    end

    -- Read the data chunk + 1 byte for the trailing comma
    local data, err = sock:receive(len + 1)
    if not data then
        return nil, "Truncated netstring"
    end

    if data:sub(-1) ~= "," then
        return nil, "Missing delimiter at end of netstring"
    end

    -- Return the string without the trailing comma
    return data:sub(1, -2)
end
_M.read = read_netstring


function _M.read_dict(sock)
    local obj = {}

    while true do
        local key, err = read_netstring(sock)
        if key == "" then
            break
        end
        if not key then
            if err == "closed" then
                break -- Clean end of stream
            end
            return nil, err
        end

        local value_raw, err = read_netstring(sock)
        if not value_raw then
            return nil, err or "Missing value"
        end

        local value
        if value_raw == "" then
            -- In OpenResty, to preserve a null key in a table, we use ngx.null.
            -- Standard Lua 'nil' would completely erase the key from the table.
            value = ngx.null
        else
            local tag = value_raw:sub(1, 1)
            local content = value_raw:sub(2)

            if tag == "t" then
                value = true
            elseif tag == "f" then
                value = false
            elseif tag == "b" or tag == "s" then
                -- Lua strings are 8-bit clean (binary safe), so bytes and strings are the same.
                value = content
            elseif tag == "i" then
                value = tonumber(content)
            else
                return nil, "Invalid type " .. tostring(tag) .. " for " .. tostring(key)
            end
        end

        obj[key] = value
    end

    return obj
end


function _M.write_dict(sock, obj)
    local payload = {}

    for k, v in pairs(obj) do
        -- Encode key
        local k_str = tostring(k)
        table.insert(payload, tostring(#k_str) .. ":" .. k_str .. ",")

        -- Encode tagged value
        if v == nil or v == ngx.null then
            table.insert(payload, "0:,")
        elseif type(v) == "boolean" then
            if v then
                table.insert(payload, "1:t,")
            else
                table.insert(payload, "1:f,")
            end
        elseif type(v) == "number" then
            local v_str = tostring(v)
            table.insert(payload, tostring(1 + #v_str) .. ":i" .. v_str .. ",")
        elseif type(v) == "string" then
            -- Note: We map all Lua strings to 's'.
            table.insert(payload, tostring(1 + #v) .. ":s" .. v .. ",")
        else
            return nil, "Cannot serialize " .. tostring(k) .. " of type " .. type(v)
        end
    end

    -- EOF
    table.insert(payload, "0:,")

    local bytes, err = sock:send(payload)
    if not bytes then
        return nil, err
    end

    return true
end

return _M
