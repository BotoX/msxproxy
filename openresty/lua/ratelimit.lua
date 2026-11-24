-- ratelimit.lua
--
-- Per-IP authentication failure tracker with incremental ban times.
-- Mirrors fail2ban settings:
--   bantime             = 1m
--   findtime            = 12h
--   maxretry            = 15
--   bantime.increment   = true
--   bantime.multipliers = 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
--   bantime.maxtime     = 15m
--
-- Storage layout — two lock-free keys per IP in ngx.shared.auth_failures:
--
--   "f:" .. ip
--     value   uint32   failures in the current FINDTIME window.
--                      Incremented atomically via STORE:incr(key, 1, 0, FINDTIME)
--                      so concurrent Nginx workers cannot race or drop counts.
--                      Deleted on ban transition and on successful login.
--
--   "b:" .. ip
--     value   uint32   total lifetime ban count (drives multiplier; persists
--                      for FINDTIME seconds after the last ban).
--     flags   uint32   banned_until — unix timestamp when the current ban
--                      expires; 0 means not currently banned.
--                      uint32 is safe until 2106 (max ~4.3 billion seconds).
--
--   ttl                Always FINDTIME (12h). Since FINDTIME > MAX_BANTIME,
--                      the ban record always outlives any active ban. After
--                      12h of inactivity the keys expire and the IP starts
--                      fresh.

local _M = {}

local ngx = ngx
local min = math.min

-- ── Configuration ────────────────────────────────────────────────────────────

local BASE_BANTIME = 60                              -- seconds (1 minute)
local FINDTIME     = 12 * 3600                       -- seconds (12 hours)
local MAXRETRY     = 15
local MAX_BANTIME  = 15 * 60                         -- seconds (15 minutes)
local MULTIPLIERS  = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15}

local STORE = ngx.shared.auth_failures

-- ── Internal helpers ─────────────────────────────────────────────────────────

-- Returns the ban duration in seconds for the Nth ban (0-indexed).
local function ban_duration(bans)
    local idx = min(bans + 1, #MULTIPLIERS)
    return min(BASE_BANTIME * MULTIPLIERS[idx], MAX_BANTIME)
end

-- ── Public API ───────────────────────────────────────────────────────────────

-- Check whether the IP is currently serving a ban.
-- Call at the very start of every authenticated request.
--
-- Returns:
--   is_banned   bool
--   retry_after number|nil   seconds remaining on the active ban
function _M.check(ip)
    local bans, banned_until = STORE:get("b:" .. ip)
    if not bans or not banned_until then
        return false, nil
    end

    local now = ngx.time()
    if banned_until > now then
        return true, banned_until - now
    end

    return false, nil
end

-- Record a failed authentication attempt.
-- Call from abort() when status == 401.
--
-- Returns:
--   is_now_banned  bool
--   ban_seconds    number|nil   duration of the new ban, if one was triggered
function _M.on_failure(ip)
    local now = ngx.time()
    local ban_key  = "b:" .. ip
    local fail_key = "f:" .. ip

    local bans, banned_until = STORE:get(ban_key)

    -- Guard: should not be called while banned, but handle it safely.
    if bans and banned_until and banned_until > now then
        return true, banned_until - now
    end

    local fails, err = STORE:incr(fail_key, 1, 0, FINDTIME)
    if not fails then
        ngx.log(ngx.ERR, "[ratelimit] incr failed for ", ip, ": ", err)
        return false, nil
    end

    if fails >= MAXRETRY then
        -- Only the single worker that hits fails == MAXRETRY performs the ban
        -- transition so a concurrent burst cannot double-increment `bans`.
        if fails == MAXRETRY then
            STORE:delete(fail_key)
            local prev_bans = bans or 0
            local duration  = ban_duration(prev_bans)
            local new_bans  = prev_bans + 1
            banned_until    = now + duration

            ngx.log(ngx.ALERT,
                "[ratelimit] banned ", ip,
                " for ", duration, "s",
                " (ban #", new_bans, ")"
            )

            STORE:set(ban_key, new_bans, FINDTIME, banned_until)
            return true, duration
        end

        return true, ban_duration(bans or 0)
    end

    return false, nil
end

-- Record a successful authentication.
-- Resets the failure counter atomically while preserving the ban count
-- (and any active ban) in "b:" .. ip.
function _M.on_success(ip)
    STORE:delete("f:" .. ip)
end

return _M
