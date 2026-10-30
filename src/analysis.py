
import pandas as pd


def detect_duplicates(df):
    """
    Identify duplicate threat indicators using normalized IP addresses.

    Original records are preserved. Duplicate records are flagged,
    not deleted.
    """

    if "ip_address_normalized" not in df.columns:
        raise ValueError(
            "Normalized IP address column is missing. "
            "Run validation before duplicate detection."
        )

    result = df.copy()

    result["is_duplicate"] = result.duplicated(
        subset=["ip_address_normalized"],
        keep="first"
    )

    result["duplicate_count"] = (
        result.groupby("ip_address_normalized")[
            "ip_address_normalized"
        ].transform("size")
    )

    return result


def analyze_feed_quality(df):
    """
    Generate a feed-quality summary from validated threat records.
    """

    required_columns = [
        "ip_address_normalized",
        "is_valid_ip",
        "is_valid_port",
        "is_valid_status",
        "is_valid_record",
        "hostname",
        "first_seen_parsed",
        "last_online_parsed",
        "status_normalized",
    ]

    missing_columns = [
        column for column in required_columns
        if column not in df.columns
    ]

    if missing_columns:
        raise ValueError(
            f"Missing required analysis columns: {missing_columns}"
        )

    total_records = len(df)

    if total_records == 0:
        raise ValueError("Cannot analyze an empty dataset.")

    duplicate_count = int(
        df["ip_address_normalized"].duplicated().sum()
    )

    invalid_ip_count = int((~df["is_valid_ip"]).sum())
    invalid_port_count = int((~df["is_valid_port"]).sum())
    invalid_status_count = int((~df["is_valid_status"]).sum())
    invalid_record_count = int((~df["is_valid_record"]).sum())

    missing_hostname_count = int(df["hostname"].isna().sum())

    invalid_first_seen_count = int(
        df["first_seen_parsed"].isna().sum()
    )

    invalid_last_online_count = int(
        df["last_online_parsed"].isna().sum()
    )

    valid_record_count = total_records - invalid_record_count

    summary = {
        "total_records": total_records,
        "unique_indicators": int(
            df["ip_address_normalized"].nunique()
        ),
        "duplicate_records": duplicate_count,
        "valid_records": valid_record_count,
        "invalid_records": invalid_record_count,
        "invalid_ip_addresses": invalid_ip_count,
        "invalid_ports": invalid_port_count,
        "invalid_statuses": invalid_status_count,
        "missing_hostnames": missing_hostname_count,
        "invalid_first_seen_dates": invalid_first_seen_count,
        "invalid_last_online_dates": invalid_last_online_count,
        "online_records": int(
            (df["status_normalized"] == "online").sum()
        ),
        "offline_records": int(
            (df["status_normalized"] == "offline").sum()
        ),
    }

    return summary
