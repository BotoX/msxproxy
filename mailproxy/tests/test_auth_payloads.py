# tests/test_auth_payloads.py
import pytest

from mailproxy.utils import (
    parse_xoauth2_payload,
    parse_oauthbearer_payload,
)


def test_parse_xoauth2_payload_basic():
    raw = b"user=test@example.com\x01auth=Bearer abc123\x01\x01"
    user, token = parse_xoauth2_payload(raw)
    assert user == "test@example.com"
    assert token == "abc123"


def test_parse_oauthbearer_payload_basic():
    raw = b"n,a=test@example.com,\x01auth=Bearer abc123\x01\x01"
    user, token = parse_oauthbearer_payload(raw)
    assert user == "test@example.com"
    assert token == "abc123"


def test_parse_xoauth2_payload_missing_user():
    raw = b"auth=Bearer abc123\x01\x01"
    with pytest.raises(ValueError, match="invalid XOAUTH2 payload"):
        parse_xoauth2_payload(raw)


def test_parse_xoauth2_payload_missing_token():
    raw = b"user=test@example.com\x01foo=bar\x01\x01"
    with pytest.raises(ValueError, match="invalid XOAUTH2 payload"):
        parse_xoauth2_payload(raw)


def test_parse_oauthbearer_payload_missing_user():
    raw = b"n,\x01auth=Bearer abc123\x01\x01"  # no a=<user>
    with pytest.raises(ValueError, match="invalid OAUTHBEARER payload"):
        parse_oauthbearer_payload(raw)


def test_parse_oauthbearer_payload_missing_token():
    raw = b"n,a=test@example.com,\x01foo=bar\x01\x01"
    with pytest.raises(ValueError, match="invalid OAUTHBEARER payload"):
        parse_oauthbearer_payload(raw)


def test_parse_oauthbearer_payload_with_extra_fields():
    # Allow extra fields but still extract user and token
    raw = (
        b"n,a=test@example.com,\x01"
        b"host=mail.example.com\x01"
        b"port=993\x01"
        b"auth=Bearer abc123\x01\x01"
    )
    user, token = parse_oauthbearer_payload(raw)
    assert user == "test@example.com"
    assert token == "abc123"
