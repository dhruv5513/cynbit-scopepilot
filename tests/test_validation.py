
import pytest

from src.validation import validate_and_normalize


def create_valid_record():
    return {
        "ip_address": "192.0.2.10",
        "port": 443,
        "status": "online",
        "hostname": None,
        "as_number": 64500,
        "as_name": "TEST-AS",
        "country": "US",
        "first_seen": "2026-01-01 10:00:00",
        "last_online": "2026-01-02",
        "malware": "TestMalware"
    }


def test_valid_record_passes_validation():
    df = validate_and_normalize([create_valid_record()])

    assert df.loc[0, "is_valid_record"] is True or bool(
        df.loc[0, "is_valid_record"]
    )
    assert df.loc[0, "ip_version"] == 4
    assert df.loc[0, "validation_issues"] == []


def test_invalid_ip_is_detected():
    record = create_valid_record()
    record["ip_address"] = "999.999.999.999"

    df = validate_and_normalize([record])

    assert not df.loc[0, "is_valid_ip"]
    assert "Invalid IP address" in df.loc[0, "validation_issues"]


def test_invalid_port_is_detected():
    record = create_valid_record()
    record["port"] = 70000

    df = validate_and_normalize([record])

    assert not df.loc[0, "is_valid_port"]
    assert "Invalid port" in df.loc[0, "validation_issues"]


def test_invalid_status_is_detected():
    record = create_valid_record()
    record["status"] = "unknown"

    df = validate_and_normalize([record])

    assert not df.loc[0, "is_valid_status"]
    assert "Invalid status" in df.loc[0, "validation_issues"]


def test_invalid_date_is_detected():
    record = create_valid_record()
    record["first_seen"] = "not-a-date"

    df = validate_and_normalize([record])

    assert "Invalid first_seen date" in df.loc[
        0, "validation_issues"
    ]


def test_missing_hostname_is_allowed():
    record = create_valid_record()
    record["hostname"] = None

    df = validate_and_normalize([record])

    assert bool(df.loc[0, "is_valid_record"])


def test_original_source_columns_are_preserved():
    record = create_valid_record()

    df = validate_and_normalize([record])

    assert df.loc[0, "ip_address"] == "192.0.2.10"
    assert df.loc[0, "first_seen"] == "2026-01-01 10:00:00"


def test_empty_records_raise_error():
    with pytest.raises(ValueError, match="No threat intelligence"):
        validate_and_normalize([])
