
import pandas as pd


def assess_indicator_risk(df, as_of=None):
    """
    Calculate an explainable prioritization score for threat indicators.

    This score helps analysts prioritize investigation.
    It does NOT confirm that an indicator is malicious.
    
    Scoring:
    - Online source status: +30 points
    - Last online within 7 days: +20 points
    - Last online within 30 days: +10 points
    - Older observations: +0 points

    Invalid records are flagged separately as data-quality concerns.
    """

    required_columns = [
        "ip_address",
        "status_normalized",
        "last_online_parsed",
        "is_valid_record",
    ]

    missing_columns = [
        column for column in required_columns
        if column not in df.columns
    ]

    if missing_columns:
        raise ValueError(
            f"Missing required risk assessment columns: {missing_columns}"
        )

    if df.empty:
        raise ValueError("Cannot assess an empty dataset.")

    result = df.copy()

    # Use a fixed reference date during testing when provided.
    reference_date = (
        pd.Timestamp.now(tz="UTC")
        if as_of is None
        else pd.Timestamp(as_of)
    )

    if reference_date.tzinfo is None:
        reference_date = reference_date.tz_localize("UTC")
    else:
        reference_date = reference_date.tz_convert("UTC")

    scores = []
    explanations = []

    for _, row in result.iterrows():
        score = 0
        reasons = []

        # Source status contributes to investigation priority.
        if row["status_normalized"] == "online":
            score += 30
            reasons.append("Source reports indicator as online")
        elif row["status_normalized"] == "offline":
            reasons.append("Source reports indicator as offline")
        else:
            reasons.append("Source status is unknown or invalid")

        # Recency is based on the source's last_online field.
        last_online = row["last_online_parsed"]

        if pd.isna(last_online):
            reasons.append("Last online date is unavailable")
        else:
            age_days = (
                reference_date - last_online
            ).total_seconds() / 86400

            if age_days < 0:
                reasons.append("Last online date is in the future")
            elif age_days <= 7:
                score += 20
                reasons.append("Last online within the last 7 days")
            elif age_days <= 30:
                score += 10
                reasons.append("Last online within the last 30 days")
            else:
                reasons.append("Last online more than 30 days ago")

        # Data validity is reported separately from threat priority.
        if not bool(row["is_valid_record"]):
            reasons.append("Record has data validation issues")

        scores.append(score)
        explanations.append(reasons)

    result["priority_score"] = scores
    result["risk_explanation"] = explanations

    def assign_priority(score):
        if score >= 40:
            return "High"
        elif score >= 20:
            return "Medium"
        return "Low"

    result["priority_level"] = result["priority_score"].apply(
        assign_priority
    )

    result["assessment_note"] = (
        "Investigation priority only; not a confirmed maliciousness verdict"
    )

    return result
