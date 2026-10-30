
import json
import tempfile
from pathlib import Path

import pandas as pd
import streamlit as st

from src.ingestion import load_threat_data
from src.validation import validate_and_normalize
from src.analysis import detect_duplicates, analyze_feed_quality
from src.risk_assessment import assess_indicator_risk


# --------------------------------------------------
# Page configuration
# --------------------------------------------------

st.set_page_config(
    page_title="ThreatLens AI",
    page_icon="🛡️",
    layout="wide"
)


# --------------------------------------------------
# Custom styling
# --------------------------------------------------

st.markdown(
    """
    <style>
    .main {
        background-color: #0e1117;
    }

    .block-container {
        padding-top: 2rem;
    }

    .stMetric {
        background-color: #1c2333;
        padding: 15px;
        border-radius: 10px;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# --------------------------------------------------
# Application header
# --------------------------------------------------

st.title("🛡️ ThreatLens AI")

st.subheader("Explainable Threat Intelligence Analysis")

st.markdown(
    """
    Analyze threat intelligence feeds through data validation,
    duplicate detection, feed-quality assessment and
    explainable investigation prioritization.
    """
)

st.divider()


# --------------------------------------------------
# Sidebar: Dataset upload
# --------------------------------------------------

st.sidebar.title("Dataset Manager")

uploaded_file = st.sidebar.file_uploader(
    "Upload Threat Intelligence JSON",
    type=["json"],
    help="Upload a JSON file containing a list of threat records."
)

st.sidebar.info(
    "Expected source format: Feodo Tracker JSON records."
)


# --------------------------------------------------
# Load uploaded dataset
# --------------------------------------------------

def process_uploaded_file(uploaded_file):
    """Load an uploaded JSON file using the ingestion module."""

    temporary_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            suffix=".json",
            delete=False
        ) as temporary_file:

            temporary_file.write(uploaded_file.getvalue())
            temporary_path = Path(temporary_file.name)

        records = load_threat_data(temporary_path)

        return records

    finally:
        if temporary_path and temporary_path.exists():
            temporary_path.unlink()


# --------------------------------------------------
# Main analysis pipeline
# --------------------------------------------------

if uploaded_file is None:

    st.info(
        "Upload a threat intelligence JSON file from the sidebar "
        "to begin analysis."
    )

    st.markdown("### Analysis capabilities")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown(
            """
            **1. Data validation**
            - IP address validation
            - Port and status checks
            - Date parsing
            - Validation issue reporting

            **2. Duplicate detection**
            - Repeated IP identification
            - Duplicate record counts
            - Original record preservation
            """
        )

    with col2:
        st.markdown(
            """
            **3. Feed-quality analysis**
            - Missing metadata
            - Valid and invalid records
            - Online and offline distribution

            **4. Risk prioritization**
            - Rule-based priority scores
            - High, medium and low categories
            - Explainable findings
            """
        )

    st.stop()


# --------------------------------------------------
# Process dataset
# --------------------------------------------------

try:

    with st.spinner("Analyzing threat intelligence data..."):

        records = process_uploaded_file(uploaded_file)

        validated_df = validate_and_normalize(records)

        analyzed_df = detect_duplicates(validated_df)

        risk_df = assess_indicator_risk(analyzed_df)

        quality_summary = analyze_feed_quality(analyzed_df)

except (ValueError, FileNotFoundError, json.JSONDecodeError) as error:

    st.error(f"Unable to process the uploaded dataset: {error}")
    st.stop()

except Exception as error:

    st.error(f"An unexpected error occurred: {error}")
    st.stop()


# --------------------------------------------------
# Dataset overview
# --------------------------------------------------

st.success("Dataset processed successfully!")

st.header("📊 Dataset Overview")

col1, col2, col3, col4 = st.columns(4)

col1.metric(
    "Total Records",
    quality_summary["total_records"]
)

col2.metric(
    "Unique Indicators",
    quality_summary["unique_indicators"]
)

col3.metric(
    "Duplicate Records",
    quality_summary["duplicate_records"]
)

col4.metric(
    "Valid Records",
    quality_summary["valid_records"]
)


# --------------------------------------------------
# Feed quality metrics
# --------------------------------------------------

st.divider()

st.header("🔍 Feed Quality Analysis")

col1, col2, col3, col4 = st.columns(4)

col1.metric(
    "Invalid Records",
    quality_summary["invalid_records"]
)

col2.metric(
    "Missing Hostnames",
    quality_summary["missing_hostnames"]
)

col3.metric(
    "Online Records",
    quality_summary["online_records"]
)

col4.metric(
    "Offline Records",
    quality_summary["offline_records"]
)


with st.expander("View detailed validation statistics"):

    col1, col2, col3 = st.columns(3)

    col1.write(
        "Invalid IP addresses: "
        f"**{quality_summary['invalid_ip_addresses']}**"
    )

    col2.write(
        "Invalid ports: "
        f"**{quality_summary['invalid_ports']}**"
    )

    col3.write(
        "Invalid statuses: "
        f"**{quality_summary['invalid_statuses']}**"
    )

    col1.write(
        "Invalid first-seen dates: "
        f"**{quality_summary['invalid_first_seen_dates']}**"
    )

    col2.write(
        "Invalid last-online dates: "
        f"**{quality_summary['invalid_last_online_dates']}**"
    )


# --------------------------------------------------
# Risk distribution
# --------------------------------------------------

st.divider()

st.header("⚠️ Investigation Priority Distribution")

priority_counts = (
    risk_df["priority_level"]
    .value_counts()
    .reindex(["High", "Medium", "Low"], fill_value=0)
)

chart_col, details_col = st.columns([2, 1])

with chart_col:

    st.bar_chart(priority_counts)

with details_col:

    st.metric("High Priority", int(priority_counts["High"]))

    st.metric("Medium Priority", int(priority_counts["Medium"]))

    st.metric("Low Priority", int(priority_counts["Low"]))


st.caption(
    "Priority scores are experimental investigation-prioritization "
    "heuristics, not probabilities or confirmed maliciousness verdicts."
)


# --------------------------------------------------
# Indicator explorer
# --------------------------------------------------

st.divider()

st.header("🔎 Indicator Explorer")

filter_col1, filter_col2, filter_col3 = st.columns(3)

with filter_col1:

    selected_priority = st.selectbox(
        "Filter by priority",
        ["All", "High", "Medium", "Low"]
    )

with filter_col2:

    selected_status = st.selectbox(
        "Filter by source status",
        ["All", "online", "offline"]
    )

with filter_col3:

    search_ip = st.text_input(
        "Search IP address",
        placeholder="Enter an IP address"
    )


filtered_df = risk_df.copy()

if selected_priority != "All":

    filtered_df = filtered_df[
        filtered_df["priority_level"] == selected_priority
    ]

if selected_status != "All":

    filtered_df = filtered_df[
        filtered_df["status_normalized"] == selected_status
    ]

if search_ip.strip():

    filtered_df = filtered_df[
        filtered_df["ip_address_normalized"].str.contains(
            search_ip.strip(),
            case=False,
            na=False
        )
    ]


display_columns = [
    "ip_address",
    "status_normalized",
    "is_valid_record",
    "is_duplicate",
    "priority_score",
    "priority_level",
]

st.write(f"Showing {len(filtered_df)} matching records.")

st.dataframe(
    filtered_df[display_columns],
    use_container_width=True,
    hide_index=True
)


# --------------------------------------------------
# Explainable findings
# --------------------------------------------------

st.divider()

st.header("🧠 Explainable Risk Findings")

if filtered_df.empty:

    st.info("No indicators match the selected filters.")

else:

    for _, row in filtered_df.iterrows():

        with st.expander(
            f"{row['ip_address']} — {row['priority_level']} Priority"
        ):

            st.write(
                f"**Investigation Priority Score:** "
                f"{row['priority_score']}/50"
            )

            st.write("**Reasons:**")

            for reason in row["risk_explanation"]:
                st.write(f"- {reason}")

            st.caption(row["assessment_note"])


# --------------------------------------------------
# CSV export
# --------------------------------------------------

st.divider()

st.header("📥 Export Analysis")

export_df = risk_df.copy()

export_df["risk_explanation"] = export_df[
    "risk_explanation"
].apply(lambda reasons: "; ".join(reasons))

export_df["validation_issues"] = export_df[
    "validation_issues"
].apply(lambda issues: "; ".join(issues))

csv_data = export_df.to_csv(index=False).encode("utf-8")

st.download_button(
    label="Download Complete Analysis as CSV",
    data=csv_data,
    file_name="threatlens_analysis.csv",
    mime="text/csv"
)


# --------------------------------------------------
# Footer
# --------------------------------------------------

st.divider()

st.caption(
    "ThreatLens AI | Explainable Threat Intelligence Analysis | "
    "Analyst review is required before making security decisions."
)
