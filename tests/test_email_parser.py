import pytest

from app.modules.email_parser import parse_email


@pytest.fixture
def sample_email():
    return (
        b"From: sender@example.com\r\n"
        b"To: receiver@example.com\r\n"
        b"Subject: Test Email\r\n"
        b"Date: Tue, 18 Nov 2026 10:00:00 +0000\r\n"
        b"Return-Path: <sender@example.com>\r\n"
        b"Reply-To: support@example.com\r\n"
        b"Sender: sender@example.com\r\n"
        b"Message-ID: <12345@example.com>\r\n"
        b"Received: from mail.example.com\r\n"
        b"Authentication-Results: mx.example.com; spf=pass\r\n"
        b"DKIM-Signature: v=1; d=example.com; s=google\r\n"
        b"\r\n"
        b"This is a test email body."
    )


def test_parse_email_success(sample_email):
    result = parse_email(sample_email)

    assert result["from"] == "sender@example.com"
    assert result["to"] == "receiver@example.com"
    assert result["subject"] == "Test Email"


def test_extract_date(sample_email):
    result = parse_email(sample_email)
    assert "2026" in result["date"]


def test_extract_return_path(sample_email):
    result = parse_email(sample_email)
    assert result["return_path"] == "<sender@example.com>"


def test_extract_reply_to(sample_email):
    result = parse_email(sample_email)
    assert result["reply_to"] == "support@example.com"


def test_extract_sender(sample_email):
    result = parse_email(sample_email)
    assert result["sender"] == "sender@example.com"


def test_extract_message_id(sample_email):
    result = parse_email(sample_email)
    assert result["message_id"] == "<12345@example.com>"


def test_extract_received_headers(sample_email):
    result = parse_email(sample_email)

    assert len(result["received"]) == 1
    assert "mail.example.com" in result["received"][0]


def test_extract_authentication_results(sample_email):
    result = parse_email(sample_email)

    assert len(result["authentication_results"]) == 1
    assert "spf=pass" in result["authentication_results"][0]


def test_extract_dkim_signature(sample_email):
    result = parse_email(sample_email)

    assert len(result["dkim_signature"]) == 1
    assert "d=example.com" in result["dkim_signature"][0]


def test_empty_email():
    with pytest.raises(ValueError):
        parse_email(b"")


def test_missing_headers():
    raw_email = (
        b"From: sender@example.com\r\n"
        b"\r\n"
        b"Test body"
    )

    result = parse_email(raw_email)

    assert result["from"] == "sender@example.com"
    assert result["subject"] == "Not available"
    assert result["message_id"] == "Not available"
    assert result["received"] == []
    assert result["authentication_results"] == []