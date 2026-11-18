import pytest

from app.modules.spf_checker import (
    validate_domain,
    extract_spf_mechanisms,
    get_spf_report_data
)


def test_validate_valid_domain():
    result = validate_domain("google.com")
    assert result == "google.com"


def test_validate_domain_uppercase():
    result = validate_domain("GOOGLE.COM")
    assert result == "google.com"


def test_validate_invalid_domain():
    with pytest.raises(ValueError):
        validate_domain("invalid_domain")


def test_validate_empty_domain():
    with pytest.raises(ValueError):
        validate_domain("")


def test_extract_spf_mechanisms():
    record = "v=spf1 include:_spf.google.com ~all"

    result = extract_spf_mechanisms(record)

    assert "include:_spf.google.com" in result
    assert "~all" in result


def test_extract_empty_spf_record():
    result = extract_spf_mechanisms(None)

    assert result == []


def test_spf_report_data():
    result = get_spf_report_data("google.com")

    assert "spf_status" in result
    assert "spf_record" in result
    assert "findings" in result
    assert "recommendations" in result

    assert isinstance(result["findings"], list)
    assert isinstance(result["recommendations"], list)