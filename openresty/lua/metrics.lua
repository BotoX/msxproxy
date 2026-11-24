-- metrics.lua
--
-- Lightweight, zero-dependency Prometheus metrics backed by ngx.shared.metrics.
-- Safe no-op if `lua_shared_dict metrics` is not configured.

local _M = {}

local ngx           = ngx
local pairs         = pairs
local ipairs        = ipairs
local tostring      = tostring
local table_insert  = table.insert
local table_concat  = table.concat
local table_sort    = table.sort
local string_format = string.format

local STORE = ngx.shared and ngx.shared.metrics or nil

local HELP = {
    msxproxy_auth_total             = { type = "counter", help = "Total authentication requests handled by OpenResty." },
    msxproxy_auth_cache_total       = { type = "counter", help = "Encrypted Basic auth cache lookups." },
    msxproxy_ratelimit_bans_total   = { type = "counter", help = "Total IP bans triggered by the OpenResty rate limiter." },
    msxproxy_crowdsec_blocks_total  = { type = "counter", help = "Total CrowdSec ban/CAPTCHA responses received from Keycloak." },
    msxproxy_s4u2api_requests_total = { type = "counter", help = "Total Kerberos impersonation requests sent to s4u2api." },
}

local function format_labels(labels)
    if not labels then
        return ""
    end
    local keys = {}
    for k in pairs(labels) do
        table_insert(keys, k)
    end
    if #keys == 0 then
        return ""
    end
    table_sort(keys)
    local parts = {}
    for _, k in ipairs(keys) do
        local v = tostring(labels[k]):gsub('\\', '\\\\'):gsub('"', '\\"'):gsub('\n', '\\n')
        table_insert(parts, string_format('%s="%s"', k, v))
    end
    return "{" .. table_concat(parts, ",") .. "}"
end

function _M.inc(metric, labels, delta)
    if not STORE then
        return
    end
    local key = metric .. format_labels(labels)
    STORE:incr(key, delta or 1, 0)
end

-- Render all stored counters in Prometheus text exposition format (0.0.4).
function _M.render()
    if not STORE then
        return "# lua_shared_dict metrics is not configured\n"
    end

    local keys = STORE:get_keys(0)
    table_sort(keys)

    local grouped = {}
    local metric_names = {}
    local seen = {}

    for _, key in ipairs(keys) do
        local val = STORE:get(key)
        if val ~= nil then
            local name = key:match("^([^{]+)") or key
            if not seen[name] then
                seen[name] = true
                table_insert(metric_names, name)
                grouped[name] = {}
            end
            table_insert(grouped[name], string_format("%s %s", key, tostring(val)))
        end
    end

    table_sort(metric_names)

    local out = {}
    for _, name in ipairs(metric_names) do
        local meta = HELP[name]
        if meta then
            table_insert(out, string_format("# HELP %s %s", name, meta.help))
            table_insert(out, string_format("# TYPE %s %s", name, meta.type))
        end
        for _, line in ipairs(grouped[name]) do
            table_insert(out, line)
        end
    end

    return table_concat(out, "\n") .. "\n"
end

return _M
