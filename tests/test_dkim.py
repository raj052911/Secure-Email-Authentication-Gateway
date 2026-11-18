import pytest

from app.modules.dkim_verifier import (
    extract_dkim_information,
    verify_dkim_signature
)


def test_extract_dkim_information():
    raw_email = (
        b"From: sender@example.com\r\n"
        b"To: receiver@example.com\r\n"
        b"Subject: Test Email\r\n"
        b"DKIM-Signature: v=1; a=rsa-sha256; "
        b"d=example.com; s=google;\r\n"
        b" bh=abc123; b=signature123\r\n"
        b"\r\n"
        b"Test email body"
    )

    result = extract_dkim_information(raw_email)

    assert result["domain"] == "example.com"
    assert result["selector"] == "google"
    assert result["algorithm"] == "rsa-sha256"
    assert result["dns_name"] == "google._domainkey.example.com"


def test_missing_dkim_signature():
    raw_email = (
        b"From: sender@example.com\r\n"
        b"To: receiver@example.com\r\n"
        b"Subject: Test Email\r\n"
        b"\r\n"
        b"Test email body"
    )

    with pytest.raises(ValueError):
        extract_dkim_information(raw_email)


def test_missing_dkim_domain():
    raw_email = (
        b"From: sender@example.com\r\n"
        b"DKIM-Signature: v=1; a=rsa-sha256; s=google; b=test\r\n"
        b"\r\n"
        b"Test body"
    )

    with pytest.raises(ValueError):
        extract_dkim_information(raw_email)


def test_missing_dkim_selector():
    raw_email = (
        b"From: sender@example.com\r\n"
        b"DKIM-Signature: v=1; a=rsa-sha256; d=example.com; b=test\r\n"
        b"\r\n"
        b"Test body"
    )

    with pytest.raises(ValueError):
        extract_dkim_information(raw_email)


def test_invalid_dkim_domain():
    raw_email = (
        b"From: sender@example.com\r\n"
        b"DKIM-Signature: v=1; d=invalid_domain; s=google; b=test\r\n"
        b"\r\n"
        b"Test body"
    )

    with pytest.raises(ValueError):
        extract_dkim_information(raw_email)


def test_invalid_dkim_domain_with_hyphen():
    raw_email = (
        b"From: sender@example.com\r\n"
        b"DKIM-Signature: v=1; d=-example.com; s=google; b=test\r\n"
        b"\r\n"
        b"Test body"
    )

    with pytest.raises(ValueError):
        extract_dkim_information(raw_email)


def test_invalid_dkim_domain_without_tld():
    raw_email = (
        b"From: sender@example.com\r\n"
        b"DKIM-Signature: v=1; d=example; s=google; b=test\r\n"
        b"\r\n"
        b"Test body"
    )

    with pytest.raises(ValueError):
        extract_dkim_information(raw_email)


def test_invalid_dkim_selector():
    raw_email = (
        b"From: sender@example.com\r\n"
        b"DKIM-Signature: v=1; d=example.com; s=invalid@selector; b=test\r\n"
        b"\r\n"
        b"Test body"
    )

    with pytest.raises(ValueError):
        extract_dkim_information(raw_email)


def test_empty_email():
    with pytest.raises(ValueError):
        verify_dkim_signature(b"")


def test_valid_dkim_domain_with_subdomain():
    raw_email = (
        b"From: sender@mail.example.com\r\n"
        b"DKIM-Signature: v=1; d=mail.example.com; s=google; b=test\r\n"
        b"\r\n"
        b"Test body"
    )

    result = extract_dkim_information(raw_email)

    assert result["domain"] == "mail.example.com"


def test_dkim_domain_is_normalized():
    raw_email = (
        b"From: sender@example.com\r\n"
        b"DKIM-Signature: v=1; d=EXAMPLE.COM; s=google; b=test\r\n"
        b"\r\n"
        b"Test body"
    )

    result = extract_dkim_information(raw_email)

    assert result["domain"] == "example.com"