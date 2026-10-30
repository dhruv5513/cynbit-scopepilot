
import pytest

from src.validation import validate_and_normalize
from src.risk_assessment import assess_indicator_risk


def create_record(ip_address, status, last_online):
    return {
        "ip_address": ip_address,
        "port": 443,
        "status": status,
        "hostname": None,
        "as_number": 64500,
        "as_name": "TEST-AS",
        "country": "US",
        "first_seen": "2026-01-01 10:00:00",
        "last_online": last_online,
        "malware": "TestMalware"
    }


def test_online_indicator_gets_30_points():
    record = create_record(
        "192.0.2.10", "online", "2026-01-01"
    )

    df = validate_and_normalize([record])
    result = assess_indicator_risk(df, as_of="2026-02-05")

    assert result.loc[0, "priority_score"] == 30
    assert result.loc[0, "priority_level"] == "Medium"


def test_recent_online_indicator_gets_50_points():
    record = create_record(
        "192.0.2.10", "online", "2026-01-01"
    )

    df = validate_and_normalize([record])
    result = assess_indicator_risk(df, as_of="2026-01-05")

    assert result.loc[0, "priority_score"] == 50
    assert result.loc[0, "priority_level"] == "High"


def test_recent_offline_indicator_gets_20_points():
    record = create_record(
        "192.0.2.10", "offline", "2026-01-01"
    )

    df = validate_and_normalize([record])
    result = assess_indicator_risk(df, as_of="2026-01-05")

    assert result.loc[0, "priority_score"] == 20
    assert result.loc[0, "priority_level"] == "Medium"


def test_old_offline_indicator_gets_zero_points():
    record = create_record(
        "192.0.2.10", "offline", "2025-10-01"
    )

    df = validate_and_normalize([record])
    result = assess_indicator_risk(df, as_of="2026-01-05")

    assert result.loc[0, "priority_score"] == 0
    assert result.loc[0, "priority_level"] == "Low"


def test_explanation_is_generated():
    record = create_record(
        "192.0.2.10", "online", "2026-01-01"
    )

    df = validate_and_normalize([record])
    result = assess_indicator_risk(df, as_of="2026-01-05")

    explanation = result.loc[0, "risk_explanation"]

    assert "Source reports indicator as online" in explanation
    assert "Last online within the last 7 days" in explanation


def test_invalid_date_is_explained():
    record = create_record(
        "192.0.2.10", "online", "invalid-date"
    )

    df = validate_and_normalize([record])
    result = assess_indicator_risk(df, as_of="2026-01-05")

    assert result.loc[0, "priority_score"] == 30
    assert "Last online date is unavailable" in (
        result.loc[0, "risk_explanation"]
    )


def test_empty_dataframe_raises_error():
    record = create_record(
        "192.0.2.10", "online", "2026-01-01"
    )

    df = validate_and_normalize([record])

    with pytest.raises(ValueError, match="empty dataset"):
        assess_indicator_risk(df.iloc[0:0])


def test_missing_required_column_raises_error():
    import pandas as pd

    df = pd.DataFrame({
        "ip_address": ["192.0.2.10"]
    })

    with pytest.raises(ValueError, match="Missing required risk"):
        assess_indicator_risk(df)


def test_assessment_note_clarifies_score_limitation():
    record = create_record(
        "192.0.2.10", "online", "2026-01-01"
    )

    df = validate_and_normalize([record])
    result = assess_indicator_risk(df, as_of="2026-01-05")

    assert "not a confirmed maliciousness verdict" in (
        result.loc[0, "assessment_note"]
    )
