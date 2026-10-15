"""Unit tests for Finding model and Severity enum."""

import json

import pytest
from pydantic import ValidationError

from app.scanner.models import Finding, Severity


def test_finding_valid_creation():
    """Verify that a finding can be created with valid parameters."""
    finding = Finding(
        check_id="test_check",
        title="Sample Finding",
        severity=Severity.HIGH,
        url="https://example.com/test",
        evidence="Found header: X-Debug: true",
        recommendation="Disable debug headers in production.",
    )

    assert finding.check_id == "test_check"
    assert finding.title == "Sample Finding"
    assert finding.severity == Severity.HIGH
    assert finding.url == "https://example.com/test"
    assert finding.evidence == "Found header: X-Debug: true"
    assert finding.recommendation == "Disable debug headers in production."
    assert finding.timestamp is not None
    assert finding.extra_data == {}


def test_severity_case_insensitivity():
    """Verify Severity enum accepts case-insensitive string values."""
    f_low = Finding(
        check_id="c1",
        title="Low issue",
        severity="low",  # type: ignore
        url="https://example.com",
        evidence="info",
        recommendation="fix",
    )
    assert f_low.severity == Severity.LOW

    f_crit = Finding(
        check_id="c2",
        title="Critical issue",
        severity="CRITICAL",  # type: ignore
        url="https://example.com",
        evidence="info",
        recommendation="fix",
    )
    assert f_crit.severity == Severity.CRITICAL


def test_finding_empty_fields_rejected():
    """Verify that whitespace or empty strings are rejected for critical fields."""
    with pytest.raises(ValidationError):
        Finding(
            check_id="   ",
            title="Title",
            severity=Severity.MEDIUM,
            url="https://example.com",
            evidence="evidence",
            recommendation="fix",
        )

    with pytest.raises(ValidationError):
        Finding(
            check_id="valid_id",
            title="",
            severity=Severity.MEDIUM,
            url="https://example.com",
            evidence="evidence",
            recommendation="fix",
        )


def test_finding_json_serialization():
    """Verify that Finding serializes to JSON cleanly."""
    finding = Finding(
        check_id="check_tls",
        title="Insecure Cipher",
        severity=Severity.MEDIUM,
        url="https://example.com",
        evidence="3DES supported",
        recommendation="Disable legacy ciphers.",
        extra_data={"ciphers": ["3DES", "RC4"]},
    )

    json_str = finding.model_dump_json()
    assert "Insecure Cipher" in json_str
    assert "medium" in json_str

    parsed = json.loads(json_str)
    assert parsed["check_id"] == "check_tls"
    assert parsed["extra_data"]["ciphers"] == ["3DES", "RC4"]

    # Reconstruct from dict
    restored = Finding.model_validate(parsed)
    assert restored.check_id == finding.check_id
    assert restored.severity == finding.severity
