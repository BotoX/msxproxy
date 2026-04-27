# tests/test_imap_parser.py
import asyncio

import pytest

from mailproxy.imap_parser import ImapParser, ImapCommand


class DummyWriter:
    def __init__(self):
        self.written = []

    def write(self, data: bytes):
        self.written.append(data)

    async def drain(self):
        pass


@pytest.mark.asyncio
async def test_imap_parser_simple_auth_inline_base64():
    # A1 AUTHENTICATE XOAUTH2 ZHVtbXk=\r\n  ("dummy")
    raw = b"A1 AUTHENTICATE XOAUTH2 ZHVtbXk=\r\n"

    reader = asyncio.StreamReader()
    reader.feed_data(raw)
    reader.feed_eof()

    dummy_writer = DummyWriter()
    parser = ImapParser(reader, dummy_writer)

    cmd = await parser.read_command()
    assert isinstance(cmd, ImapCommand)
    assert cmd.tag == "A1"
    assert cmd.command == "AUTHENTICATE"
    assert cmd.args == [b"XOAUTH2", b"ZHVtbXk="]
    assert dummy_writer.written == []  # no "+ " sent


@pytest.mark.asyncio
async def test_imap_parser_auth_needs_continuation():
    # Client sends command with no initial response, then a base64 line.
    raw = b"A1 AUTHENTICATE XOAUTH2\r\nZHVtbXk=\r\n"

    reader = asyncio.StreamReader()
    reader.feed_data(raw)
    reader.feed_eof()

    dummy_writer = DummyWriter()
    parser = ImapParser(reader, dummy_writer)

    cmd = await parser.read_command()
    assert cmd.tag == "A1"
    assert cmd.command == "AUTHENTICATE"
    assert cmd.args == [b"XOAUTH2"]
    assert await reader.readline() == b"ZHVtbXk=\r\n"
    assert dummy_writer.written == []


@pytest.mark.asyncio
async def test_imap_parser_auth_oauthbearer_continuation():
    raw = b"A2 AUTHENTICATE OAUTHBEARER\r\nZHVtbXk=\r\n"

    reader = asyncio.StreamReader()
    reader.feed_data(raw)
    reader.feed_eof()

    dummy_writer = DummyWriter()
    parser = ImapParser(reader, dummy_writer)

    cmd = await parser.read_command()
    assert cmd.tag == "A2"
    assert cmd.command == "AUTHENTICATE"
    assert cmd.args == [b"OAUTHBEARER"]
    assert await reader.readline() == b"ZHVtbXk=\r\n"
    assert dummy_writer.written == []


@pytest.mark.asyncio
async def test_imap_parser_literal_argument():
    # A3 AUTHENTICATE XOAUTH2 {5}\r\nabcde\r\n
    raw = b"A3 AUTHENTICATE XOAUTH2 {5}\r\nabcde\r\n"

    reader = asyncio.StreamReader()
    reader.feed_data(raw)
    reader.feed_eof()

    dummy_writer = DummyWriter()
    parser = ImapParser(reader, dummy_writer)

    cmd = await parser.read_command()
    assert cmd.tag == "A3"
    assert cmd.command == "AUTHENTICATE"
    assert cmd.args == [b"XOAUTH2", b"abcde"]
    assert dummy_writer.written == [b"+ \r\n"]


@pytest.mark.asyncio
async def test_imap_parser_literal_argument2():
    # A3 AUTHENTICATE XOAUTH2 {5}\r\nabcde\r\n
    raw = b"A3 AUTHENTICATE XOAUTH2 {5+}\r\nabcde\r\n"

    reader = asyncio.StreamReader()
    reader.feed_data(raw)
    reader.feed_eof()

    dummy_writer = DummyWriter()
    parser = ImapParser(reader, dummy_writer)

    cmd = await parser.read_command()
    assert cmd.tag == "A3"
    assert cmd.command == "AUTHENTICATE"
    assert cmd.args == [b"XOAUTH2", b"abcde"]
    assert dummy_writer.written == []


@pytest.mark.asyncio
async def test_imap_parser_multiple_literals_and_quoted():
    # A4 APPEND "INBOX" {5}\r\nhello {7}\r\nworld! \r\n
    raw = b'A4 APPEND "INBOX" {5}\r\nhello {7}\r\nworld! \r\n'

    reader = asyncio.StreamReader()
    reader.feed_data(raw)
    reader.feed_eof()

    dummy_writer = DummyWriter()
    parser = ImapParser(reader, dummy_writer)

    cmd = await parser.read_command()
    assert cmd.tag == "A4"
    assert cmd.command == "APPEND"
    # args: ["INBOX", b"hello", b"world! "]
    assert cmd.args[0] == b"INBOX"
    assert cmd.args[1] == b"hello"
    assert cmd.args[2] == b"world! "


@pytest.mark.asyncio
async def test_imap_parser_quoted_string_with_escape():
    # A5 LOGIN "user\"name" "pass\\word"\r\n
    raw = b'A5 LOGIN "user\\\"name" "pass\\\\word"\r\n'

    reader = asyncio.StreamReader()
    reader.feed_data(raw)
    reader.feed_eof()

    dummy_writer = DummyWriter()
    parser = ImapParser(reader, dummy_writer)

    cmd = await parser.read_command()
    assert cmd.tag == "A5"
    assert cmd.command == "LOGIN"
    assert cmd.args[0] == b'user"name'
    assert cmd.args[1] == b"pass\\word"


# ---------- Malformed inputs ----------


@pytest.mark.asyncio
async def test_imap_parser_literal_non_digit_length():
    # A6 APPEND INBOX {1x}\r\n
    raw = b"A6 APPEND INBOX {1x}\r\n"

    reader = asyncio.StreamReader()
    reader.feed_data(raw)
    reader.feed_eof()

    dummy_writer = DummyWriter()
    parser = ImapParser(reader, dummy_writer)

    with pytest.raises(RuntimeError, match="non-digit in literal length"):
        await parser.read_command()


@pytest.mark.asyncio
async def test_imap_parser_literal_missing_crlf():
    # A7 APPEND INBOX {5}x\r\n
    # Length header not properly terminated by CRLF
    raw = b"A7 APPEND INBOX {5}x\r\n"

    reader = asyncio.StreamReader()
    reader.feed_data(raw)
    reader.feed_eof()

    dummy_writer = DummyWriter()
    parser = ImapParser(reader, dummy_writer)

    with pytest.raises(RuntimeError, match="expected CRLF after literal length"):
        await parser.read_command()


@pytest.mark.asyncio
async def test_imap_parser_bare_lf_in_command():
    # A8 CAPABILITY\n   (bare LF, not CRLF)
    raw = b"A8 CAPABILITY\n"

    reader = asyncio.StreamReader()
    reader.feed_data(raw)
    reader.feed_eof()

    dummy_writer = DummyWriter()
    parser = ImapParser(reader, dummy_writer)

    with pytest.raises(RuntimeError, match="bare LF in command|newline in tag"):
        await parser.read_command()


@pytest.mark.asyncio
async def test_imap_parser_bare_lf_in_atom():
    # A9 FOO ba\nr\r\n
    raw = b"A9 FOO ba\nr\r\n"

    reader = asyncio.StreamReader()
    reader.feed_data(raw)
    reader.feed_eof()

    dummy_writer = DummyWriter()
    parser = ImapParser(reader, dummy_writer)

    with pytest.raises(RuntimeError, match="bare LF in atom"):
        await parser.read_command()
