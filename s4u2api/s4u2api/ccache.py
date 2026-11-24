"""
Pure-Python MIT Kerberos FILE: credential cache (ccache v3/v4) reader.

Parses big-endian ccache files (versions 0x0503 and 0x0504) to inspect cached
service ticket expiration times without requiring the `krb5` C extension.
"""
from collections.abc import Iterator
from pathlib import Path
import struct

CCACHE_V3 = 0x0503
CCACHE_V4 = 0x0504


class _Cursor:
    __slots__ = ("data", "pos", "end")

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0
        self.end = len(data)

    def eof(self) -> bool:
        return self.pos >= self.end

    def _advance(self, n: int) -> int:
        if n < 0 or self.pos + n > self.end:
            raise ValueError("Truncated or corrupt Kerberos ccache")
        start = self.pos
        self.pos += n
        return start

    def u8(self) -> int:
        i = self._advance(1)
        return self.data[i]

    def u16(self) -> int:
        i = self._advance(2)
        return struct.unpack_from(">H", self.data, i)[0]

    def u32(self) -> int:
        i = self._advance(4)
        return struct.unpack_from(">I", self.data, i)[0]

    def skip(self, n: int) -> None:
        self._advance(n)

    def counted_bytes(self) -> bytes:
        length = self.u32()
        i = self._advance(length)
        return self.data[i : i + length]

    def read_principal(self) -> str:
        _name_type = self.u32()
        num_components = self.u32()
        realm = self.counted_bytes().decode("utf-8", errors="replace")
        components = [
            self.counted_bytes().decode("utf-8", errors="replace")
            for _ in range(num_components)
        ]
        return f"{'/'.join(components)}@{realm}"


def iter_ccache_tickets(data: bytes) -> Iterator[tuple[str, str, int]]:
    """
    Yield `(client_principal, server_principal, endtime)` for each credential
    record in a MIT Kerberos FILE: ccache (version 3 or 4).
    """
    cur = _Cursor(data)
    version = cur.u16()
    if version not in (CCACHE_V3, CCACHE_V4):
        raise ValueError(f"Unsupported ccache version: 0x{version:04x}")

    if version == CCACHE_V4:
        header_len = cur.u16()
        cur.skip(header_len)

    # Default principal
    cur.read_principal()

    while not cur.eof():
        client = cur.read_principal()
        server = cur.read_principal()

        # Keyblock: uint16 keytype, [uint16 etype in v3], counted_octet_string (uint32 len) keyvalue
        _keytype = cur.u16()
        if version == CCACHE_V3:
            _etype = cur.u16()
        cur.counted_bytes()

        # Times: authtime, starttime, endtime, renew_till (4 x uint32)
        _authtime = cur.u32()
        _starttime = cur.u32()
        endtime = cur.u32()
        _renew_till = cur.u32()

        # is_skey (uint8) + ticket_flags (uint32)
        cur.u8()
        cur.u32()

        # Addresses
        num_addr = cur.u32()
        for _ in range(num_addr):
            cur.u16()
            cur.counted_bytes()

        # Authdata
        num_ad = cur.u32()
        for _ in range(num_ad):
            cur.u16()
            cur.counted_bytes()

        # ticket + second_ticket
        cur.counted_bytes()
        cur.counted_bytes()

        yield client, server, endtime


def get_ticket_endtime(ccache_path: str | Path, spn: str) -> int | None:
    """
    Return the latest `endtime` (Unix timestamp) for a cached ticket matching
    `spn` in `ccache_path`, or None if the file/ticket does not exist.
    """
    try:
        data = Path(ccache_path).read_bytes()
    except FileNotFoundError:
        return None

    best_endtime: int | None = None
    for _client, server, endtime in iter_ccache_tickets(data):
        if server == spn and (best_endtime is None or endtime > best_endtime):
            best_endtime = endtime
    return best_endtime
