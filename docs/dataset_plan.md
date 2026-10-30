# ThreatLens AI – Dataset Plan

## 1. Dataset Strategy

The project will follow a hybrid dataset approach combining publicly available cybersecurity threat intelligence data with controlled synthetic records.

The purpose is to evaluate the system using realistic indicators while also testing edge cases that may not be sufficiently represented in public feeds.

## 2. Public Dataset Source

### Feodo Tracker – abuse.ch

Source:
https://feodotracker.abuse.ch/blocklist/

Purpose:
- Analyse real-world botnet command-and-control IP indicators.
- Test IP address validation.
- Identify duplicate records.
- Examine available indicator metadata.
- Evaluate feed quality.

The original source data will be preserved separately from processed data.

## 3. Synthetic Dataset

Additional synthetic records will be created for testing:

- Domain indicators.
- URL indicators.
- File hashes.
- Invalid indicator formats.
- Duplicate observations.
- Missing values.
- Old observations.
- Conflicting metadata.

All synthetic records will be explicitly labelled as synthetic.

They will not be presented as real threat intelligence.

## 4. Observed Public Dataset Schema

The initial Feodo Tracker JSON sample contains the following fields:

- ip_address
- port
- status
- hostname
- as_number
- as_name
- country
- first_seen
- last_online
- malware

These fields will be mapped into the project's internal data structure.

### Proposed Field Mapping

| Original Field | Internal Field |
|---|---|
| ip_address | indicator_value |
| port | port |
| status | source_status |
| hostname | hostname |
| as_number | as_number |
| as_name | as_name |
| country | country |
| first_seen | first_seen |
| last_online | last_online |
| malware | malware_family |

### Data Handling Notes

- Original field names and values will be preserved in raw data.
- Missing values will remain null.
- Date fields will be parsed using their actual formats.
- Source status will not be treated as a definitive maliciousness label.
- Malware family information will only be used where supplied by the source.
- Dataset collection date will be recorded separately.

## 5. Initial Dataset Inspection

The downloaded Feodo Tracker full blocklist contains 5 records.

Initial observations:

- Unique IP addresses: 5
- Online records: 1
- Offline records: 4
- Missing hostnames: 2
- Observed malware families: Emotet and QakBot
- Observed countries: US, GB, and JP
- Observed ports: 443 and 8080

### Data Limitations

The downloaded dataset is too small for reliable machine learning
training or performance evaluation.

It will be used as a small real-world reference sample.
Additional clearly labelled synthetic records will be created
for testing validation, duplicate detection, missing values,
and anomaly analysis.

No model accuracy claims will be made using this small sample.

## 5. Data Processing Strategy

The processing pipeline will include:

1. Data ingestion.
2. Field mapping.
3. Indicator validation.
4. Duplicate identification.
5. Missing-value analysis.
6. Timestamp normalization.
7. Data quality reporting.

## 6. Machine Learning Strategy

The project will initially use rule-based validation and statistical analysis.

Isolation Forest may be evaluated experimentally for anomaly detection after suitable features are prepared.

Anomaly scores will not be treated as proof that an indicator is malicious.

## 7. Evaluation Strategy

The system will be evaluated using:

- Valid and invalid indicator samples.
- Duplicate records.
- Missing metadata.
- Stale observations.
- Synthetic edge cases.
- Detection consistency.
- False-positive analysis.

Evaluation metrics will be selected according to the availability of reliable ground-truth labels.

## 8. Data Integrity and Limitations

- Original public data will be retained separately.
- Synthetic data will be clearly identified.
- Dataset source and collection date will be recorded.
- No fabricated threat labels or confidence scores will be introduced.
- Public threat intelligence may be incomplete or outdated.