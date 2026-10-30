# ThreatLens AI – Explainable Threat Intelligence Analysis

**Developed for:** Cynbit Technologies Assessment  
**Project Type:** AI/ML Proof of Concept  
**Status:** Working Prototype

## 1. Project Overview

ThreatLens AI is a prototype threat intelligence analysis system designed to ingest, validate, analyze, and prioritize threat intelligence indicators.

It focuses on improving feed quality, identifying duplicate indicators, and providing explainable investigation priorities through a rule-based scoring mechanism.

The project is designed as a complementary analytical layer to Cynbit Technologies' Feeder product. It does not currently have direct integration with Feeder.

## 2. Key Features

- **JSON Data Ingestion:** Upload and process threat intelligence records.
- **Data Validation:** Validate IP addresses, ports, statuses, and date fields.
- **Duplicate Detection:** Identify repeated IP indicators.
- **Feed Quality Analysis:** Calculate data-quality metrics and identify missing information.
- **Explainable Risk Assessment:** Assign investigation priorities using transparent scoring rules.
- **Interactive Dashboard:** Explore indicators, filter results, and view risk explanations.
- **CSV Export:** Download analyzed threat intelligence records.
- **Automated Testing:** Validate core modules using Pytest.

## 3. Technology Stack

- Python
- Pandas
- NumPy
- Streamlit
- Pytest
- JSON and CSV
- Git and GitHub

## 4. Project Structure

```text
ThreatLens-AI/
│
├── src/
│   ├── __init__.py
│   ├── ingestion.py
│   ├── validation.py
│   ├── analysis.py
│   └── risk_assessment.py
│
├── data/
│   └── (local JSON datasets)
│
├── docs/
│   ├── company_research.md
│   ├── feeder_product_analysis.md
│   ├── dataset_plan.md
│   ├── ai_opportunity_report.md
│   └── technical_approach_report.md
│
├── screenshots/
├── tests/
│   ├── test_ingestion.py
│   ├── test_validation.py
│   ├── test_analysis.py
│   └── test_risk_assessment.py
│
├── app.py
├── requirements.txt
├── README.md
└── .gitignore
```

## 5. Installation and Setup

### Prerequisites

- Python 3.10 or later
- Git

### Clone the repository

```bash
git clone https://github.com/dhruv5513/cynbit-scopepilot.git
cd cynbit-scopepilot
```

### Create a virtual environment

**Windows PowerShell:**

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### Install dependencies

```powershell
python -m pip install -r requirements.txt
```

## 6. Run the Application

Start the Streamlit dashboard:

```powershell
streamlit run app.py
```

Open the local URL displayed in the terminal, usually:

```text
http://localhost:8501
```

Upload a compatible threat intelligence JSON file through the dashboard to begin analysis.

## 7. Dataset

The prototype was tested using the Feodo Tracker IP blocklist dataset from abuse.ch.

Dataset source:

https://feodotracker.abuse.ch/

The sample JSON files are excluded from Git tracking. Download a compatible JSON dataset and upload it through the dashboard.

## 8. Risk Assessment Methodology

The current prototype uses a rule-based investigation-priority score.

| Condition | Score |
|---|---:|
| Source reports indicator as online | +30 |
| Last online within 7 days | +20 |
| Last online within 30 days | +10 |
| Last online more than 30 days ago | +0 |

Priority classification:

- High: Score of 40 or above
- Medium: Score between 20 and 39
- Low: Score below 20

The score represents investigation priority, not a confirmed maliciousness verdict. The current implementation does not use a trained machine-learning model.

## 9. Run Automated Tests

Execute the test suite:

```powershell
python -m pytest -v
```

The current project test suite contains 30 passing automated tests covering ingestion, validation, duplicate detection, feed-quality analysis, and risk assessment.

## 10. Project Documentation

The following reports are included in the `docs/` directory:

1. **AI Opportunity Report:** Identifies potential AI opportunities and explains how analytical capabilities could complement Feeder.
2. **Technical Approach Report:** Describes the architecture, implementation, technology stack, testing, limitations, and future enhancements.
3. **Feeder Product Analysis:** Documents the product research and analysis.
4. **Dataset Plan:** Describes the dataset selection and planned data-processing approach.
5. **Company Research:** Summarizes the company research conducted for the assessment.

## 11. Current Limitations

- JSON is the currently supported input format.
- The prototype has been tested with a small sample dataset.
- Risk prioritization uses predefined rules rather than a trained ML model.
- Direct Feeder integration has not been implemented.
- Production-scale performance and security testing remain future work.

## 12. Future Enhancements

- Support for additional threat intelligence formats.
- Historical indicator tracking.
- Allowlist support.
- Integration with Feeder interfaces, subject to API availability and compatibility.
- Analyst feedback for improving prioritization.
- Evaluation of anomaly-detection techniques using representative historical data.
- Larger-scale performance and security testing.

## 13. Disclaimer

ThreatLens AI is an assessment proof of concept. Its investigation-priority scores are intended to support analysis and do not independently establish whether an indicator is malicious.

---

**Repository:** https://github.com/dhruv5513/cynbit-scopepilot