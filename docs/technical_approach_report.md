# ThreatLens AI – Technical Approach Report

## 1. Introduction

ThreatLens AI is a prototype threat intelligence analysis system developed as part of the Cynbit Technologies assessment.

The purpose of the project is to demonstrate how threat intelligence data can be ingested, validated, analyzed, and prioritized through an explainable analytical workflow.

The prototype is designed as a complementary analytical layer to Feeder. It demonstrates data-quality analysis and investigation prioritization without claiming direct integration with the Feeder product.

## 2. Project Objectives

The main objectives are:

- Ingest threat intelligence records from JSON files.
- Validate indicator data and identify incorrect or incomplete records.
- Detect duplicate indicators.
- Analyze feed quality through measurable statistics.
- Assign investigation priority using transparent, rule-based scoring.
- Display results through an interactive dashboard.
- Provide downloadable analysis results in CSV format.
- Maintain code reliability through automated testing.

## 3. Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core application development |
| Pandas | Data processing and analysis |
| NumPy | Numerical operations |
| Streamlit | Interactive dashboard |
| Pytest | Automated testing |
| JSON | Input threat intelligence data |
| CSV | Exporting analysis results |
| Git and GitHub | Version control and source-code management |

## 4. System Architecture

The prototype follows a modular architecture. Each module performs a separate responsibility, making the system easier to maintain and test.

### Architecture workflow

1. **Data Input:** The user uploads a JSON threat intelligence dataset.
2. **Data Ingestion:** The ingestion module reads the JSON file and checks its basic structure.
3. **Data Validation:** The validation module checks IP addresses, ports, statuses, and date fields.
4. **Duplicate Detection:** The analysis module identifies repeated indicators.
5. **Feed Quality Analysis:** The system calculates data-quality statistics.
6. **Risk Assessment:** A rule-based scoring mechanism assigns investigation priority.
7. **Dashboard:** Streamlit displays metrics, charts, indicator details, and explanations.
8. **Export:** Users can download the analyzed records as a CSV file.

### Module structure

| File | Responsibility |
|---|---|
| `src/ingestion.py` | Loads and checks JSON input |
| `src/validation.py` | Validates and normalizes threat records |
| `src/analysis.py` | Detects duplicates and calculates feed-quality statistics |
| `src/risk_assessment.py` | Calculates explainable investigation-priority scores |
| `app.py` | Provides the Streamlit dashboard |

## 5. Data Ingestion

The ingestion module uses Python's JSON and pathlib libraries to load threat intelligence records.

The module performs the following checks:

- Confirms that the input file exists.
- Reads the file using UTF-8 encoding.
- Handles invalid JSON.
- Confirms that the dataset contains a list of records.
- Checks that individual records are dictionaries.

Invalid input is handled through clear error messages rather than allowing the application to fail unexpectedly.

## 6. Data Validation and Normalization

The validation module uses Pandas and Python's `ipaddress` library.

The system checks:

- IP address validity.
- IP version.
- Port range and integer format.
- Supported status values such as online and offline.
- First-seen and last-online date fields.
- Missing or incomplete information.

The system creates additional validation columns while preserving the original source fields.

Missing hostnames are recorded as data-quality observations rather than automatically making a record invalid.

Each record receives a validation result and, where applicable, a list of validation issues.

## 7. Duplicate Detection and Feed Quality Analysis

The analysis module identifies duplicate indicators using normalized IP addresses.

It adds duplicate flags and duplicate counts without removing the original records.

The feed-quality analysis calculates:

- Total records.
- Unique indicators.
- Duplicate records.
- Valid and invalid records.
- Invalid IP addresses.
- Invalid ports.
- Invalid statuses.
- Missing hostnames.
- Invalid date values.
- Online and offline record counts.

These metrics help users understand the quality and completeness of the input dataset.

## 8. Explainable Risk Assessment

The prototype uses a transparent, rule-based scoring mechanism to assign investigation priority.

The scoring logic considers:

| Condition | Score |
|---|---:|
| Source reports indicator as online | +30 |
| Last online within 7 days | +20 |
| Last online within 30 days | +10 |
| Last online more than 30 days ago | +0 |

The recency conditions are mutually exclusive. The score is calculated by combining the applicable status and recency points.

### Priority classification

| Score | Priority |
|---|---|
| 40 or above | High |
| 20–39 | Medium |
| Below 20 | Low |

The system also generates explanations describing why a particular score was assigned.

**Important:** This score represents investigation priority, not a confirmed maliciousness verdict. An online status or recent observation alone does not prove that an indicator is malicious.

The current implementation is rule-based. It does not use a trained machine-learning model.

## 9. Dashboard and User Interface

The Streamlit dashboard provides an interactive interface for analyzing threat intelligence records.

Its main features include:

- JSON dataset upload.
- Dataset overview metrics.
- Feed-quality statistics.
- Validation statistics.
- Risk-priority distribution chart.
- Indicator explorer.
- Filters for priority, status, and IP address.
- Expandable risk explanations.
- CSV download of analyzed results.

The dashboard is designed to make the analysis understandable without requiring users to inspect the Python source code.

## 10. Testing and Validation

Pytest is used to verify the functionality of the application's modules.

The test suite covers:

- JSON ingestion and input errors.
- IP address validation.
- Port and status validation.
- Date validation.
- Missing hostname handling.
- Duplicate detection.
- Feed-quality calculations.
- Risk scoring and priority classification.
- Invalid and empty input handling.

The current implementation has **30 passing automated tests**.

The dashboard was also manually tested using the Feodo Tracker JSON dataset. The uploaded dataset contained five records, all of which passed the implemented record-validation checks.

The dashboard displayed five total records, five unique indicators, zero duplicates, and two records with missing hostnames.

These results demonstrate the prototype's workflow on the sample dataset; they do not establish production-scale performance or detection accuracy.

## 11. Limitations

The current prototype has the following limitations:

- JSON is the supported input format.
- The implementation uses a small Feodo Tracker sample dataset.
- No direct Feeder integration has been implemented.
- Risk prioritization is based on predefined rules rather than a trained ML model.
- The scoring mechanism is not a confirmed threat-detection system.
- The prototype has not undergone production-scale performance or security testing.
- Additional representative datasets are needed for broader evaluation.

## 12. Future Technical Enhancements

Possible future improvements include:

1. Support for additional threat intelligence formats and feeds.
2. Historical indicator tracking and trend analysis.
3. Allowlist support to reduce unnecessary investigation.
4. Integration with Feeder interfaces, subject to available APIs and compatibility.
5. Analyst feedback to improve prioritization.
6. Evaluation of anomaly-detection methods such as Isolation Forest using suitable historical data.
7. Larger-scale testing and performance evaluation.
8. More comprehensive security and deployment testing.

Any future machine-learning implementation should be evaluated using representative data and appropriate metrics before being used operationally.

## 13. Conclusion

ThreatLens AI demonstrates a modular approach to threat intelligence ingestion, validation, duplicate detection, feed-quality analysis, and explainable investigation prioritization.

The prototype combines Python-based processing with an interactive Streamlit dashboard and automated tests.

It provides a technical foundation for exploring how analytical capabilities could complement a threat intelligence collection and delivery platform such as Feeder.

The current implementation is a proof of concept and should be evaluated further with larger datasets, operational feedback, and integration testing before production use.