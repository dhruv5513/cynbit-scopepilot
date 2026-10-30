# AI Opportunity Report
## ThreatLens AI – Explainable Threat Intelligence Analysis

**Prepared for:** Cynbit Technologies  
**Project:** ThreatLens AI  
**Category:** AI/ML Proof of Concept

---

## 1. Executive Summary

ThreatLens AI is a proposed AI-assisted threat intelligence analysis system designed to improve the quality assessment, analysis and prioritization of threat intelligence indicators.

The solution is designed as a complementary analytical layer to Cynbit's Feeder product.

Feeder focuses on collecting, normalizing, deduplicating, storing and distributing threat intelligence data. ThreatLens AI extends this workflow by introducing additional analytical capabilities that help analysts evaluate incoming intelligence records and prioritize them for investigation.

The prototype currently includes data ingestion, indicator validation, duplicate detection, feed-quality analysis and explainable investigation prioritization.

## 2. Understanding the Existing Product

Cynbit's Feeder is a threat intelligence collection and delivery appliance designed to operate within a customer's own network.

Its documented capabilities include:

- Collecting threat intelligence through HTTP, S3, SMB and manual uploads.
- Parsing different feed formats using configurable parser definitions.
- Normalizing indicators into consistent records.
- Deduplicating indicators across different sources.
- Preserving observation history, including source information and observation timestamps.
- Delivering intelligence through formats and integrations such as EDL, TAXII, CSV, SFTP and webhooks.
- Supporting offline and air-gapped deployment scenarios.

These capabilities establish a foundation for managing threat intelligence feeds.

## 3. Identified Opportunity

Although collecting and normalizing threat intelligence is important, analysts also need to evaluate the quality and relevance of the collected information.

Potential analytical challenges include:

- Invalid or incomplete indicators.
- Repeated indicators across incoming records.
- Missing metadata.
- Outdated observations.
- Difficulty prioritizing indicators for investigation.
- Limited visibility into why a particular indicator requires attention.

These challenges create an opportunity for an additional analytical layer that provides explainable findings without replacing the existing collection and delivery workflow.

## 4. Proposed AI Solution: ThreatLens AI

ThreatLens AI is proposed as an explainable threat intelligence analysis system.

Its primary objective is to help analysts understand the quality and investigation priority of threat intelligence records.

### Core capabilities

**4.1 Data Ingestion**

- Import threat intelligence records from JSON files.
- Preserve original source information.
- Handle missing files and malformed JSON.

**4.2 Indicator Validation**

- Validate IPv4 and IPv6 addresses.
- Validate port numbers.
- Check source status values.
- Parse observation dates.
- Identify invalid records and explain validation issues.

**4.3 Duplicate Detection**

- Identify repeated IP indicators.
- Calculate duplicate counts.
- Preserve original records for traceability.

**4.4 Feed Quality Analysis**

- Calculate total and unique indicator counts.
- Identify incomplete metadata.
- Report invalid records.
- Analyze online and offline status distribution.
- Generate feed-quality summaries.

**4.5 Explainable Investigation Prioritization**

- Calculate rule-based priority scores.
- Consider source status and observation recency.
- Assign High, Medium and Low priority levels.
- Display explanations for each assessment.

The current scoring approach is an experimental heuristic and does not represent a probability of maliciousness.

## 5. Role of AI and Machine Learning

The current prototype establishes a rule-based analytical foundation.

A future enhancement could introduce anomaly detection using an unsupervised machine learning algorithm such as Isolation Forest.

Potential applications include:

- Identifying unusual indicator patterns.
- Detecting unusual feed activity.
- Highlighting records that differ from normal data distributions.
- Supporting analyst investigation through anomaly explanations.

Such a model would require suitable historical data, meaningful feature engineering and evaluation before being used in operational workflows.

An anomaly score must not be treated as proof that an indicator is malicious.

## 6. Expected Business Value

ThreatLens AI could provide the following benefits:

**Improved Data Quality**

Identifies invalid records and missing metadata before analysts rely on the information.

**Better Investigation Prioritization**

Helps analysts focus on indicators that deserve closer examination.

**Greater Transparency**

Provides understandable reasons behind validation results and prioritization scores.

**Reduced Manual Effort**

Automates repetitive checks and generates structured analytical summaries.

**Complementary Product Value**

Provides an additional analytical capability alongside Feeder's existing threat intelligence collection and delivery workflow.

These are proposed benefits that require validation through practical user testing.

## 7. Proposed Technical Architecture

The prototype uses the following technology stack:

| Component | Technology |
|---|---|
| Programming language | Python |
| Data processing | Pandas, NumPy |
| Validation | Python IP address utilities |
| Machine learning extension | Scikit-learn |
| Dashboard | Streamlit |
| Automated testing | Pytest |
| Data input | JSON |
| Report export | CSV |

The architecture is modular:

1. Data ingestion loads threat intelligence records.
2. Validation checks and normalizes the records.
3. Analysis identifies duplicates and calculates feed-quality metrics.
4. Risk assessment generates explainable investigation priorities.
5. Streamlit presents the results through an interactive dashboard.

## 8. Current Proof of Concept

The current implementation demonstrates:

- JSON-based threat intelligence ingestion.
- IP address, port, status and date validation.
- Duplicate indicator detection.
- Feed-quality reporting.
- Explainable rule-based prioritization.
- Interactive Streamlit dashboard.
- Indicator filtering and search.
- CSV export.

The implementation has been tested using a small Feodo Tracker dataset containing five records.

The automated test suite currently contains 30 passing tests.

The dataset is useful for demonstrating the workflow, but its size is insufficient for making broad claims about production performance or machine learning accuracy.

## 9. Limitations and Considerations

- The current prototype processes JSON input rather than integrating directly with Feeder.
- The demonstration dataset is small.
- Risk prioritization uses experimental rules rather than a trained predictive model.
- Source status and observation recency do not independently establish maliciousness.
- Missing metadata should not automatically make an indicator invalid.
- Operational deployment would require additional security, scalability and integration testing.
- Any future machine learning model would require representative historical data and proper evaluation.

## 10. Future Scope

Potential future improvements include:

1. Historical observation analysis.
2. Allowlist integration.
3. Advanced anomaly detection using Isolation Forest.
4. Additional threat intelligence feed formats.
5. Integration with Feeder through supported interfaces.
6. Analyst feedback and investigation workflows.
7. More comprehensive evaluation using larger datasets.

These are proposed enhancements and are not claims about currently implemented capabilities.

## 11. Conclusion

ThreatLens AI demonstrates how an additional analytical layer can complement a threat intelligence collection and delivery platform.

By combining structured data validation, duplicate detection, feed-quality analysis and explainable prioritization, the prototype provides a foundation for helping analysts understand and investigate threat intelligence records.

The proposed solution focuses on transparency, modularity and practical usefulness while preserving the distinction between analytical prioritization and confirmed threat attribution.

Its future development could strengthen the analytical workflow around Cynbit's Feeder product.