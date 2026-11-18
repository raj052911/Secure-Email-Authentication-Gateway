import pytest

from app.modules.dmarc_checker import (
    validate_domain,
    parse_dmarc_record,
    domains_aligned,
    evaluate_dmarc
)


def test_validate_domain():
    assert validate_domain("GOOGLE.COM") == "google.com"


def test_invalid_domain():
    with pytest.raises(ValueError):
        validate_domain("invalid_domain")


def test_parse_valid_dmarc_record():
    record = "v=DMARC1; p=reject; rua=mailto:reports@example.com"

    result = parse_dmarc_record(record)

    assert result["version"] == "DMARC1"
    assert result["policy"] == "reject"
    assert result["spf_alignment"] == "r"
    assert result["dkim_alignment"] == "r"


def test_dmarc_quarantine_policy():
    record = "v=DMARC1; p=quarantine"

    result = parse_dmarc_record(record)

    assert result["policy"] == "quarantine"


def test_invalid_dmarc_policy():
    record = "v=DMARC1; p=invalid"

    with pytest.raises(ValueError):
        parse_dmarc_record(record)


def test_empty_dmarc_record():
    with pytest.raises(ValueError):
        parse_dmarc_record("")


def test_strict_domain_alignment():
    result = domains_aligned(
        "example.com",
        "example.com",
        "s"
    )

    assert result is True


def test_strict_domain_alignment_failure():
    result = domains_aligned(
        "mail.example.com",
        "example.com",
        "s"
    )

    assert result is False


def test_relaxed_domain_alignment():
    result = domains_aligned(
        "mail.example.com",
        "example.com",
        "r"
    )

    assert result is True


def test_dmarc_pass_with_aligned_spf():
    policy = {
        "spf_alignment": "r",
        "dkim_alignment": "r"
    }

    result = evaluate_dmarc(
        "example.com",
        "PASS",
        "mail.example.com",
        "FAIL",
        "",
        policy
    )

    assert result["status"] == "PASS"
    assert result["spf_aligned"] is True


def test_dmarc_fail_without_alignment():
    policy = {
        "spf_alignment": "r",
        "dkim_alignment": "r"
    }

    result = evaluate_dmarc(
        "example.com",
        "FAIL",
        "other.com",
        "FAIL",
        "different.com",
        policy
    )

    assert result["status"] == "FAIL"
    assert result["spf_aligned"] is False
    assert result["dkim_aligned"] is False