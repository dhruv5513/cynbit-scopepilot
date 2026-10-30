
import pytest

from src.validation import validate_and_normalize
from src.analysis import detect_duplicates, analyze_feed_quality


def create_record(ip_address):
    return {
        "ip_address": ip_address,
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


def create_validated_dataframe(records):
    return validate_and_normalize(records)


def test_duplicate_ip_is_detected():
    records = [
        create_record("192.0.2.10"),
        create_record("192.0.2.10"),
        create_record("192.0.2.20")
    ]

    df = create_validated_dataframe(records)
    result = detect_duplicates(df)

    assert result["is_duplicate"].tolist() == [
        False, True, False
    ]


def test_duplicate_count_is_calculated():
    records = [
        create_record("192.0.2.10"),
        create_record("192.0.2.10"),
        create_record("192.0.2.10")
    ]

    df = create_validated_dataframe(records)
    result = detect_duplicates(df)

    assert result["duplicate_count"].tolist() == [3, 3, 3]


def test_original_records_are_preserved():
    records = [
        create_record("192.0.2.10"),
        create_record("192.0.2.10")
    ]

    df = create_validated_dataframe(records)
    result = detect_duplicates(df)

    assert len(result) == 2


def test_quality_summary_counts_records():
    records = [
        create_record("192.0.2.10"),
        create_record("192.0.2.20")
    ]

    df = create_validated_dataframe(records)
    summary = analyze_feed_quality(df)

    assert summary["total_records"] == 2
    assert summary["unique_indicators"] == 2
    assert summary["valid_records"] == 2
    assert summary["invalid_records"] == 0


def test_quality_summary_counts_missing_hostnames():
    records = [
        create_record("192.0.2.10"),
        create_record("192.0.2.20")
    ]

    df = create_validated_dataframe(records)
    summary = analyze_feed_quality(df)

    assert summary["missing_hostnames"] == 2


def test_quality_summary_counts_status():
    first = create_record("192.0.2.10")
    second = create_record("192.0.2.20")
    second["status"] = "offline"

    df = create_validated_dataframe([first, second])
    summary = analyze_feed_quality(df)

    assert summary["online_records"] == 1
    assert summary["offline_records"] == 1


def test_empty_dataframe_raises_error():
    df = create_validated_dataframe([create_record("192.0.2.10")])
    empty_df = df.iloc[0:0]

    with pytest.raises(ValueError, match="empty dataset"):
        analyze_feed_quality(empty_df)


def test_duplicate_detection_requires_normalized_ip():
    import pandas as pd

    df = pd.DataFrame({"ip_address": ["192.0.2.10"]})

    with pytest.raises(ValueError, match="Normalized IP address"):
        detect_duplicates(df)
