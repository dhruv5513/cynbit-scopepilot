
import ipaddress

import pandas as pd


REQUIRED_COLUMNS = [
    "ip_address",
    "port",
    "status",
    "hostname",
    "as_number",
    "as_name",
    "country",
    "first_seen",
    "last_online",
    "malware",
]


def validate_ip(value):
    """Check whether an IP address is valid."""
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except (ValueError, TypeError):
        return False


def get_ip_version(value):
    """Return IP version 4 or 6 for a valid IP address."""
    try:
        return ipaddress.ip_address(str(value).strip()).version
    except (ValueError, TypeError):
        return None


def validate_and_normalize(records):
    """
    Validate threat intelligence records and add normalized fields.

    Original source columns are preserved.
    Invalid records are flagged, not silently removed.
    """

    if not isinstance(records, list):
        raise ValueError("Expected a list of threat intelligence records.")

    if not records:
        raise ValueError("No threat intelligence records were provided.")

    df = pd.DataFrame(records)

    missing_columns = [
        column for column in REQUIRED_COLUMNS
        if column not in df.columns
    ]

    if missing_columns:
        raise ValueError(
            f"Missing required columns: {missing_columns}"
        )

    # Normalize IP address text without changing the original value.
    df["ip_address_normalized"] = (
        df["ip_address"].astype("string").str.strip()
    )

    # Validate IP addresses and identify their versions.
    df["is_valid_ip"] = df["ip_address_normalized"].apply(validate_ip)
    df["ip_version"] = df["ip_address_normalized"].apply(get_ip_version)

    # Validate port values.
    numeric_ports = pd.to_numeric(df["port"], errors="coerce")
    df["is_valid_port"] = (
        numeric_ports.notna()
        & numeric_ports.between(1, 65535)
        & (numeric_ports % 1 == 0)
    )

    # Normalize status for consistent analysis.
    df["status_normalized"] = (
        df["status"].astype("string").str.strip().str.lower()
    )

    df["is_valid_status"] = df["status_normalized"].isin(
        ["online", "offline"]
    )

    # Parse dates into separate datetime columns.
    # Original date strings remain unchanged.
    df["first_seen_parsed"] = pd.to_datetime(
        df["first_seen"],
        errors="coerce",
        utc=True
    )

    df["last_online_parsed"] = pd.to_datetime(
        df["last_online"],
        errors="coerce",
        utc=True
    )

    # Collect validation issues for each record.
    def get_validation_issues(row):
        issues = []

        if not row["is_valid_ip"]:
            issues.append("Invalid IP address")

        if not row["is_valid_port"]:
            issues.append("Invalid port")

        if not row["is_valid_status"]:
            issues.append("Invalid status")

        if pd.isna(row["first_seen_parsed"]):
            issues.append("Invalid first_seen date")

        if pd.isna(row["last_online_parsed"]):
            issues.append("Invalid last_online date")

        return issues

    df["validation_issues"] = df.apply(
        get_validation_issues,
        axis=1
    )

    df["is_valid_record"] = df["validation_issues"].apply(
        lambda issues: len(issues) == 0
    )

    return df
