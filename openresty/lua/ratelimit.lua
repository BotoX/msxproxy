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
-- Storage layout — two integers per IP:
--
--   ngx.shared.auth_failures:set(ip, value, ttl, flags)
--
--   value   uint32   (bans << 16) | fails
--                     bans  — high 16 bits: total lifetime ban count (drives
--                             multiplier; persists until key expires)
--                     fails — low  16 bits: failures in the current window
--                             (reset to 0 after each ban and on success)
--
--   flags   uint32   banned_until — unix timestamp when the current ban
--                    expires; 0 means not currently banned.
--                    uint32 is safe until 2106 (max ~4.3 billion seconds).
--
--   ttl              Always FINDTIME (12h).  Since FINDTIME > MAX_BANTIME,
--                    the key always outlives any active ban.  After 12h of
--                    complete inactivity the key expires and the IP starts
--                    fresh.  Consecutive failures reset the TTL on each write,
--                    so a persistent attacker keeps their ban count alive.
--
-- Note: findtime is approximated as "FINDTIME seconds from the last ban or
-- from key creation", not a true sliding window.  This is a common trade-off
-- when avoiding per-failure timestamps.  It is slightly more conservative
-- (failures expire a little later than in a true sliding window), which is
-- acceptable for a security tool.

local _M = {}

local ngx    = ngx
local bit    = require("bit")
local lshift = bit.lshift
local rshift = bit.rshift
local band   = bit.band
local bor    = bit.bor
local min    = math.min
local ceil   = math.ceil

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

-- Unpack value + flags into (fails, bans, banned_until).
local function unpack_state(value, flags)
    return band(value, 0xFFFF),  -- fails
           rshift(value, 16),    -- bans
           flags or 0            -- banned_until
end

-- Pack (fails, bans) into value and (banned_until) into flags.
local function pack_state(fails, bans, banned_until)
    return bor(lshift(bans, 16), fails),  -- value
           banned_until                   -- flags
end

-- ── Public API ───────────────────────────────────────────────────────────────

-- Check whether the IP is currently serving a ban.
-- Call at the very start of every authenticated request.
--
-- Returns:
--   is_banned   bool
--   retry_after number|nil   seconds remaining on the active ban
function _M.check(ip)
    local value, flags = STORE:get(ip)
    if not value then
        return false, nil
    end

    local _, _, banned_until = unpack_state(value, flags)
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
    local now   = ngx.time()
    local value, flags = STORE:get(ip)

    local fails, bans, banned_until
    if not value then
        fails, bans, banned_until = 0, 0, 0
    else
        fails, bans, banned_until = unpack_state(value, flags)
    end

    -- Guard: should not be called while banned, but handle it safely.
    if banned_until > now then
        return true, banned_until - now
    end

    fails = fails + 1

    if fails >= MAXRETRY then
        local duration = ban_duration(bans)
        bans           = bans + 1
        banned_until   = now + duration
        fails          = 0

        ngx.log(ngx.ALERT,
            "[ratelimit] banned ", ip,
            " for ", duration, "s",
            " (ban #", bans, ")"
        )

        local v, f = pack_state(fails, bans, banned_until)
        STORE:set(ip, v, FINDTIME, f)
        return true, duration
    end

    local v, f = pack_state(fails, bans, 0)
    STORE:set(ip, v, FINDTIME, f)
    return false, nil
end

-- Record a successful authentication.
-- Resets the failure counter but preserves the ban count so the next ban
-- still uses the correct incremented multiplier.
-- Call just before every successful proxy pass.
function _M.on_success(ip)
    local value, flags = STORE:get(ip)
    if not value then return end

    local _, bans, banned_until = unpack_state(value, flags)

    -- Do not touch an active ban.
    if banned_until > ngx.time() then return end

    -- Zero out fails (low 16 bits), preserve bans (high 16 bits).
    STORE:set(ip, lshift(bans, 16), FINDTIME, 0)
end

return _M
