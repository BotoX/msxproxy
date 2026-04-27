import asyncio
from dataclasses import dataclass

@dataclass
class ImapCommand:
    tag: str
    command: str
    args: list[bytes]

class ImapParser:
    """
    Streaming IMAP command parser for client -> proxy side, that:
      - Reads atoms, quoted strings, literals {N}\r\n<bytes>.
      - Properly handles synchronous literals by sending '+ ' continuation.
      - Supports RFC 7888 non-synchronous literals ({N}+\r\n).
    """

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter | None = None
    ):
        self.reader = reader
        self.writer = writer

    async def read_command(self) -> ImapCommand | None:
        tag, command, args = await self._read_tag_command_and_args()
        if tag is None:
            return None

        return ImapCommand(tag=tag, command=command, args=args)

    async def _read_tag_command_and_args(self) -> tuple[str | None, str, list[bytes]]:
        reader = self.reader

        try:
            # 1. Read TAG
            tag_bytes = bytearray()
            while True:
                if len(tag_bytes) >= 32:
                    raise RuntimeError("* BAD Command Error: tag too long")
                ch = await reader.readexactly(1)
                if ch == b" ":
                    break
                if ch == b"\r":
                    tag = tag_bytes.decode().upper() or "*"
                    lf = await reader.readexactly(1)
                    if lf != b"\n":
                        raise RuntimeError(f"{tag} BAD Command Error: expected LF after CR")
                    raise ValueError(f"{tag} BAD Command Error: unexpected newline in tag")
                if ch == b"\n":
                    tag = tag_bytes.decode().upper() or "*"
                    raise RuntimeError(f"{tag} BAD Command Error: bare LF in command")
                tag_bytes.extend(ch)

            tag = tag_bytes.decode()

            # 2. Read COMMAND
            cmd_bytes = bytearray()
            while True:
                if len(cmd_bytes) >= 32:
                    raise RuntimeError(f"{tag} BAD Command Error: command too long")
                ch = await reader.readexactly(1)
                if ch == b" ":
                    break
                if ch == b"\r":
                    lf = await reader.readexactly(1)
                    if lf != b"\n":
                        raise RuntimeError(f"{tag} BAD Command Error: expected LF after CR")
                    command = cmd_bytes.decode().upper()
                    return tag, command, []
                if ch == b"\n":
                    raise RuntimeError(f"{tag} BAD Command Error: bare LF in command")
                cmd_bytes.extend(ch)

            command = cmd_bytes.decode().upper()

            # 3. Read ARGS
            args: list[bytes] = []
            while True:
                if len(args) >= 8:
                    raise RuntimeError(f"{tag} BAD Command Error: too many arguments")
                ch = await reader.readexactly(1)
                if ch == b" ":
                    continue
                if ch == b"\r":
                    lf = await reader.readexactly(1)
                    if lf != b"\n":
                        raise RuntimeError(f"{tag} BAD Command Error: expected LF after CR")
                    break
                if ch == b"\n":
                    raise RuntimeError(f"{tag} BAD Command Error: bare LF in command")

                # Quoted String
                if ch == b'"':
                    buf = bytearray()
                    escaped = False
                    while True:
                        if len(buf) >= 4096:
                            raise RuntimeError(f"{tag} BAD Command Error: quoted string too long")
                        b = await reader.readexactly(1)
                        if escaped:
                            buf.extend(b)
                            escaped = False
                        else:
                            if b == b"\\":
                                escaped = True
                            elif b == b'"':
                                break
                            else:
                                buf.extend(b)
                    args.append(bytes(buf))

                # Literal String {N} or {N}+
                elif ch == b"{":
                    num_buf = bytearray()
                    is_non_sync = False

                    while True:
                        if len(num_buf) >= 8:
                            raise RuntimeError(f"{tag} BAD Command Error: literal length too long")
                        b = await reader.readexactly(1)
                        if b == b"}":
                            break
                        if b == b"+":
                            is_non_sync = True
                            b = await reader.readexactly(1)
                            if b != b"}":
                                raise RuntimeError(f"{tag} BAD Command Error: expected }} after + in literal length")
                            break
                        if not b.isdigit():
                            raise RuntimeError(f"{tag} BAD Command Error: non-digit in literal length")
                        num_buf.extend(b)

                    cr = await reader.readexactly(1)
                    lf = await reader.readexactly(1)
                    if cr != b"\r" or lf != b"\n":
                        raise RuntimeError(f"{tag} BAD Command Error: expected CRLF after literal length")

                    if not num_buf:
                        raise RuntimeError(f"{tag} BAD Command Error: empty literal length")
                    length = int(num_buf.decode())
                    if length > 4096:
                        raise RuntimeError(f"{tag} BAD Command Error: literal length too large")

                    # Send the continuation request for standard (synchronous) literals
                    if not is_non_sync and self.writer:
                        self.writer.write(b"+ \r\n")
                        await self.writer.drain()

                    data = await reader.readexactly(length)
                    args.append(data)

                # Atom
                else:
                    buf = bytearray()
                    buf.extend(ch)
                    while True:
                        if len(buf) >= 4096:
                            raise RuntimeError(f"{tag} BAD Command Error: atom too long")
                        b = await reader.readexactly(1)
                        if b == b" ":
                            break
                        if b == b"\r":
                            lf = await reader.readexactly(1)
                            if lf != b"\n":
                                raise RuntimeError(f"{tag} BAD Command Error: expected LF after CR")
                            args.append(bytes(buf))
                            return tag, command, args
                        if b == b"\n":
                            raise RuntimeError(f"{tag} BAD Command Error: bare LF in atom")
                        buf.extend(b)
                    args.append(bytes(buf))
        except UnicodeDecodeError:
            raise RuntimeError(f"* BAD Unicode decode error")

        return tag, command, args
