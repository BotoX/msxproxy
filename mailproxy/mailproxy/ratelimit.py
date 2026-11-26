"""
Multi-worker per-IP authentication rate limiter backed by anonymous shared memory.

Mirrors OpenResty's `ratelimit.lua`
  - base_bantime  (default 60s / 1m)
  - findtime      (default 43200s / 12h)
  - maxretry      (default 15)
  - max_bantime   (default 900s / 15m)
  - linear multipliers: 1..15

Storage layout:
  Fixed-size 8-way set-associative hash table in anonymous shared memory
  (`multiprocessing.RawArray('B', ...)`) synchronized with a `multiprocessing.Lock`.
  Default size: 16,384 sets x 8 ways = 131,072 slots x 44 bytes = ~5.5 MiB.

  - Shared seamlessly across forked worker processes (`--workers > 1`) and all
    four listeners (IMAP 143/993, SMTP 587/465).
  - Strictly O(1) per lookup/update (at most 8 contiguous slots) and fixed-memory
    (evicts expired entries first, then soonest-to-expire unbanned entries).
  - Keyed with a per-instance random BLAKE2b salt to prevent hash-flooding DoS.
"""
from __future__ import annotations

import hashlib
import ipaddress
import logging
import multiprocessing
import secrets
import struct
import time
from typing import Callable

from . import config
from .metrics import metrics

logger = logging.getLogger(__name__)

# Slot binary layout (44 bytes):
#   state        uint8   (0 = empty, 1 = occupied)
#   ip_key       16s     (IPv4 mapped as ::ffff:a.b.c.d, IPv6 as 16 raw bytes)
#   pad          3 bytes
#   fails        uint32  (failures in current findtime window)
#   bans         uint32  (lifetime ban count within findtime window)
#   banned_until uint64  (unix timestamp when current ban expires; 0 = not banned)
#   expires_at   uint64  (unix timestamp when slot expires)
_SLOT_STRUCT = struct.Struct("<B16s3xIIQQ")
_SLOT_SIZE = _SLOT_STRUCT.size  # 44 bytes

_MULTIPLIERS = (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15)

DEFAULT_NUM_SETS = 16384  # power of 2
DEFAULT_WAYS = 8          # 16384 * 8 = 131,072 slots (~5.5 MiB)

_IPV4_MAPPED_PREFIX = b"\x00" * 10 + b"\xff\xff"


def _ip_to_key(ip: str) -> bytes:
    """Normalize an IPv4 or IPv6 address string to a 16-byte canonical key."""
    try:
        addr = ipaddress.ip_address(ip)
        if isinstance(addr, ipaddress.IPv4Address):
            return _IPV4_MAPPED_PREFIX + addr.packed
        return addr.packed
    except ValueError:
        return hashlib.blake2b(ip.encode("utf-8", errors="replace"), digest_size=16).digest()


def _is_ignored(ip: str) -> bool:
    """Return True if ip falls within any CIDR in config.RATELIMIT_IGNORE_NETWORKS."""
    nets = config.RATELIMIT_IGNORE_NETWORKS
    if not nets:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for net in nets:
        if addr.version == net.version and addr in net:
            return True
    return False


def _ban_duration(bans: int, base_bantime: int, max_bantime: int) -> int:
    """Compute incremental ban duration for the Nth ban (0-indexed)."""
    idx = min(bans, len(_MULTIPLIERS) - 1)
    return min(base_bantime * _MULTIPLIERS[idx], max_bantime)


class SharedRateLimiter:
    """Fixed-size shared-memory per-IP rate limiter safe across forked workers."""

    def __init__(
        self,
        num_sets: int = DEFAULT_NUM_SETS,
        ways: int = DEFAULT_WAYS,
        time_fn: Callable[[], float] = time.time,
    ) -> None:
        if num_sets <= 0 or (num_sets & (num_sets - 1)) != 0:
            raise ValueError("num_sets must be a positive power of 2")
        if ways <= 0:
            raise ValueError("ways must be positive")

        self._num_sets = num_sets
        self._set_mask = num_sets - 1
        self._ways = ways
        self._set_stride = ways * _SLOT_SIZE
        self._total_bytes = num_sets * self._set_stride
        self._time = time_fn
        self._salt = secrets.token_bytes(16)

        self._raw = multiprocessing.RawArray("B", self._total_bytes)
        self._buf = memoryview(self._raw).cast("B")
        self._lock = multiprocessing.Lock()

    @property
    def capacity(self) -> int:
        return self._num_sets * self._ways

    @property
    def memory_bytes(self) -> int:
        return self._total_bytes

    def _set_offset(self, ip_key: bytes) -> int:
        digest = hashlib.blake2b(ip_key, key=self._salt, digest_size=8).digest()
        set_idx = int.from_bytes(digest, "little") & self._set_mask
        return set_idx * self._set_stride

    def reset(self) -> None:
        """Clear all tracked failures and bans."""
        with self._lock:
            self._buf[:] = bytes(self._total_bytes)

    def check(self, ip: str) -> tuple[bool, int]:
        """
        Check whether `ip` is currently banned.

        Returns `(is_banned, retry_after_seconds)`.
        """
        if not config.RATELIMIT_ENABLED or not ip or _is_ignored(ip):
            return False, 0

        ip_key = _ip_to_key(ip)
        base = self._set_offset(ip_key)
        now = int(self._time())

        with self._lock:
            for w in range(self._ways):
                off = base + w * _SLOT_SIZE
                state, slot_ip, _fails, _bans, banned_until, expires_at = _SLOT_STRUCT.unpack_from(
                    self._buf, off
                )
                if state == 1 and slot_ip == ip_key:
                    if expires_at <= now:
                        self._buf[off] = 0
                        return False, 0
                    if banned_until > now:
                        return True, int(banned_until - now)
                    return False, 0

        return False, 0

    def on_failure(self, ip: str) -> tuple[bool, int]:
        """
        Record a failed authentication attempt for `ip`.

        Returns `(is_banned, ban_seconds)` when the IP is banned (newly or already).
        """
        if not config.RATELIMIT_ENABLED or not ip or _is_ignored(ip):
            return False, 0

        findtime = max(1, int(config.RATELIMIT_FINDTIME))
        maxretry = max(1, int(config.RATELIMIT_MAXRETRY))
        base_bantime = max(1, int(config.RATELIMIT_BASE_BANTIME))
        max_bantime = max(base_bantime, int(config.RATELIMIT_MAX_BANTIME))

        ip_key = _ip_to_key(ip)
        base = self._set_offset(ip_key)
        now = int(self._time())

        newly_banned = False
        ban_seconds = 0
        ban_count = 0

        with self._lock:
            match_off: int | None = None
            match_active = False
            match_fails = 0
            match_bans = 0
            match_banned_until = 0

            free_off: int | None = None
            evict_unbanned_off: int | None = None
            evict_unbanned_exp = 0
            evict_any_off: int | None = None
            evict_any_exp = 0

            for w in range(self._ways):
                off = base + w * _SLOT_SIZE
                state, slot_ip, fails, bans, banned_until, expires_at = _SLOT_STRUCT.unpack_from(
                    self._buf, off
                )
                if state == 0:
                    if free_off is None:
                        free_off = off
                    continue

                if expires_at <= now:
                    # Lazily reclaim expired slot
                    self._buf[off] = 0
                    if slot_ip == ip_key:
                        match_off = off
                        match_active = False
                    elif free_off is None:
                        free_off = off
                    continue

                if slot_ip == ip_key:
                    match_off = off
                    match_active = True
                    match_fails = fails
                    match_bans = bans
                    match_banned_until = banned_until
                    break

                if banned_until <= now:
                    if evict_unbanned_off is None or expires_at < evict_unbanned_exp:
                        evict_unbanned_off = off
                        evict_unbanned_exp = expires_at
                if evict_any_off is None or expires_at < evict_any_exp:
                    evict_any_off = off
                    evict_any_exp = expires_at

            if match_active:
                if match_banned_until > now:
                    return True, int(match_banned_until - now)
                target_off = match_off
                new_fails = match_fails + 1
                new_bans = match_bans
            else:
                target_off = (
                    match_off
                    if match_off is not None
                    else (
                        free_off
                        if free_off is not None
                        else (
                            evict_unbanned_off
                            if evict_unbanned_off is not None
                            else evict_any_off
                        )
                    )
                )
                new_fails = 1
                new_bans = 0

            expires_at = now + findtime
            if new_fails >= maxretry:
                ban_seconds = _ban_duration(new_bans, base_bantime, max_bantime)
                ban_count = new_bans + 1
                _SLOT_STRUCT.pack_into(
                    self._buf,
                    target_off,
                    1,
                    ip_key,
                    0,
                    ban_count,
                    now + ban_seconds,
                    expires_at,
                )
                newly_banned = True
            else:
                _SLOT_STRUCT.pack_into(
                    self._buf,
                    target_off,
                    1,
                    ip_key,
                    new_fails,
                    new_bans,
                    0,
                    expires_at,
                )

        if newly_banned:
            metrics.inc("all", "ratelimit_bans")
            logger.warning(
                "Rate-limit ban #%d triggered for IP '%s' (%ds after %d failures)",
                ban_count,
                ip,
                ban_seconds,
                maxretry,
            )
            return True, ban_seconds

        return False, 0

    def on_success(self, ip: str) -> None:
        """
        Clear the failure counter for `ip` on successful authentication.

        Preserves lifetime `bans` history (if > 0) for the remainder of `findtime`,
        matching OpenResty's `ratelimit.lua`.
        """
        if not config.RATELIMIT_ENABLED or not ip:
            return

        ip_key = _ip_to_key(ip)
        base = self._set_offset(ip_key)
        now = int(self._time())

        with self._lock:
            for w in range(self._ways):
                off = base + w * _SLOT_SIZE
                state, slot_ip, _fails, bans, banned_until, expires_at = _SLOT_STRUCT.unpack_from(
                    self._buf, off
                )
                if state == 1 and slot_ip == ip_key:
                    if expires_at <= now or bans == 0:
                        self._buf[off] = 0
                    else:
                        _SLOT_STRUCT.pack_into(
                            self._buf,
                            off,
                            1,
                            ip_key,
                            0,
                            bans,
                            banned_until,
                            expires_at,
                        )
                    return


ratelimit = SharedRateLimiter()
